
import json

import networkx as nx

from helpers import make_graph, resource
from iacgraph.graph import build_infrastructure_graph
from iacgraph.network import INTERNET, make_rule
from iacgraph.paths import build_attack_graph, find_attack_paths
from iacgraph.plan import get_references, get_resources, load_plan
from iacgraph.rules import check_cfg_01, check_cfg_02, check_net_01, check_net_02, check_path_01, run_rules


def add_edge(graph, source, target, protocol, from_port, to_port, cause):
    rule = make_rule(cause, "group", "ingress", protocol, from_port, to_port, ["0.0.0.0/0"], [])
    graph.add_edge(source, target, source=source, target=target, kind="network", label=f"{protocol}/{from_port}", cause=cause, rule=rule)


def attack_graph_with_entry(target_kind, protocol, from_port, to_port):
    graph = nx.MultiDiGraph()
    graph.add_node(INTERNET, kind="internet")
    graph.add_node("target", kind=target_kind)
    add_edge(graph, INTERNET, "target", protocol, from_port, to_port, "the_rule")
    return graph


def keys(findings):
    return [(finding["rule"], finding["resource"], finding["severity"]) for finding in findings]


def test_net_01_finds_ssh_and_rdp():
    assert keys(check_net_01(attack_graph_with_entry("compute", "tcp", 22, 22), set())) == [("NET-01", "the_rule", "high")]
    assert keys(check_net_01(attack_graph_with_entry("compute", "tcp", 3389, 3389), set())) == [("NET-01", "the_rule", "high")]
    assert keys(check_net_01(attack_graph_with_entry("compute", "tcp", 0, 65535), set())) != []  # all ports include 22
    assert keys(check_net_01(attack_graph_with_entry("compute", "-1", None, None), set())) != []  # "-1" = all traffic
    assert keys(check_net_01(attack_graph_with_entry("compute", "tcp", 443, 443), set())) == []


def test_net_01_ignores_an_accepted_service():
    graph = attack_graph_with_entry("compute", "tcp", 22, 22)
    assert check_net_01(graph, {("target", 22)}) == []


def test_net_02_finds_a_database_open_to_the_internet():
    assert keys(check_net_02(attack_graph_with_entry("database", "tcp", 5432, 5432), set())) == [("NET-02", "target", "critical")]


def test_path_01_needs_at_least_two_steps():
    one_step = [[(INTERNET, "db", 0)]]
    two_steps = [[(INTERNET, "web", 0), ("web", "db", 0)]]
    assert check_path_01(one_step) == []
    assert keys(check_path_01(two_steps)) == [("PATH-01", "db", "high")]


def test_cfg_01_finds_an_unencrypted_database():
    graph = make_graph(resource("aws_db_instance.a", {"storage_encrypted": False}), resource("aws_db_instance.b", {"storage_encrypted": True}))
    assert keys(check_cfg_01(graph, [])) == [("CFG-01", "aws_db_instance.a", "medium")]


def test_cfg_02_finds_service_wildcards_only():
    def policy(action):
        return json.dumps({"Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]})

    graph = make_graph(
        resource("aws_iam_role_policy.all", {"policy": policy("*")}),
        resource("aws_iam_role_policy.s3_all", {"policy": policy("s3:*")}),
        resource("aws_iam_role_policy.s3_read", {"policy": policy(["s3:GetObject", "s3:List*"])}),
    )
    assert [finding["resource"] for finding in check_cfg_02(graph, [])] == ["aws_iam_role_policy.all", "aws_iam_role_policy.s3_all"]


def test_a_weakness_on_an_attack_path_is_raised_to_high():
    graph = make_graph(resource("aws_db_instance.db", {"storage_encrypted": False}))
    attack_graph = nx.MultiDiGraph()
    attack_graph.add_node(INTERNET, kind="internet")
    attack_graph.add_node("aws_instance.web", kind="compute")
    attack_graph.add_node("aws_db_instance.db", kind="database")
    add_edge(attack_graph, INTERNET, "aws_instance.web", "tcp", 22, 22, "ssh_rule")
    add_edge(attack_graph, "aws_instance.web", "aws_db_instance.db", "tcp", 3306, 3306, "mysql_rule")
    _, paths = find_attack_paths(attack_graph, set())
    findings = run_rules(graph, attack_graph, paths, set(), [])
    cfg = [finding for finding in findings if finding["rule"] == "CFG-01"][0]
    assert cfg["severity"] == "high" and cfg["raised"]


def test_the_insecure_demo_has_five_findings_and_the_secure_demo_none():
    accepted = {("aws_instance.web", 443)}  # HTTPS of the web server is public on purpose
    found = {}
    for name in ("demo-insecure", "demo-secure"):
        plan = load_plan(f"tests/fixtures/{name}.plan.json")
        resources = get_resources(plan, [])
        graph = build_infrastructure_graph(resources, get_references(plan, resources, []))
        attack_graph = build_attack_graph(graph, [])
        _, paths = find_attack_paths(attack_graph, accepted)
        found[name] = keys(run_rules(graph, attack_graph, paths, accepted, []))
    assert found["demo-insecure"] == [
        ("CFG-01", "aws_db_instance.main", "high"),
        ("CFG-02", "aws_iam_role_policy.app_s3", "high"),
        ("NET-01", "aws_vpc_security_group_ingress_rule.web_ssh_world", "high"),
        ("PATH-01", "aws_db_instance.main", "high"),
        ("PATH-01", "aws_s3_bucket.data", "high"),
    ]
    assert found["demo-secure"] == []