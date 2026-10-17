
import networkx as nx

from iacgraph.graph import build_infrastructure_graph
from iacgraph.network import INTERNET, make_rule
from iacgraph.paths import build_attack_graph, describe_path, find_attack_paths, is_accepted
from iacgraph.plan import get_references, get_resources, load_plan

HTTPS_ACCEPTED = {("web", 443)}


def add_network_edge(graph, source, target, port):
    rule = make_rule(f"rule_{source}_{target}_{port}", "group", "ingress", "tcp", port, port, ["0.0.0.0/0"], [])
    graph.add_edge(source, target, source=source, target=target, kind="network", label=f"tcp/{port}", cause=rule["resource"], rule=rule)


def add_iam_edge(graph, source, target):
    graph.add_edge(source, target, source=source, target=target, kind="iam", label="s3:*", cause="policy")


def demo_shape():
    """The shape of the insecure demo: SSH and HTTPS into web; web -> db and web -> bucket."""
    graph = nx.MultiDiGraph()
    graph.add_node(INTERNET, kind="internet")
    graph.add_node("web", kind="compute")
    graph.add_node("db", kind="database")
    graph.add_node("bucket", kind="bucket")
    add_network_edge(graph, INTERNET, "web", 22)
    add_network_edge(graph, INTERNET, "web", 443)
    add_network_edge(graph, "web", "db", 3306)
    add_iam_edge(graph, "web", "bucket")
    return graph


def descriptions(graph, paths):
    return [describe_path(graph, path) for path in paths]


def test_bfs_gives_the_number_of_steps():
    hops, _ = find_attack_paths(demo_shape(), HTTPS_ACCEPTED)
    assert hops == {"web": 1, "db": 2, "bucket": 2}


def test_the_demo_shape_has_two_attack_paths_through_ssh():
    graph = demo_shape()
    _, paths = find_attack_paths(graph, HTTPS_ACCEPTED)
    assert descriptions(graph, paths) == [
        "internet -[tcp/22]-> web -[s3:*]-> bucket",
        "internet -[tcp/22]-> web -[tcp/3306]-> db",
    ]


def test_without_accepting_https_there_are_four_paths():
    """Two entry edges (22 and 443) x two data stores: each edge is a separate path."""
    _, paths = find_attack_paths(demo_shape(), set())
    assert len(paths) == 4


def entry_edge(from_port, to_port):
    """An edge from the Internet to "web" that opens tcp/from_port-to_port."""
    rule = make_rule("rule", "group", "ingress", "tcp", from_port, to_port, ["0.0.0.0/0"], [])
    return {"source": INTERNET, "target": "web", "rule": rule}


def test_is_accepted_needs_exactly_the_accepted_port():
    assert is_accepted(entry_edge(443, 443), HTTPS_ACCEPTED)
    assert not is_accepted(entry_edge(22, 22), HTTPS_ACCEPTED)
    assert not is_accepted(entry_edge(0, 65535), HTTPS_ACCEPTED)  # includes 443, but is not "the HTTPS service"


def test_if_only_https_is_open_nothing_is_reachable():
    graph = demo_shape()
    graph.remove_edge(INTERNET, "web", key=0)  # remove SSH
    hops, paths = find_attack_paths(graph, HTTPS_ACCEPTED)
    assert hops == {} and paths == []


def test_a_cycle_does_not_repeat_a_node():
    graph = demo_shape()
    graph.add_node("app", kind="compute")
    add_network_edge(graph, "web", "app", 8080)
    add_network_edge(graph, "app", "web", 8080)
    add_network_edge(graph, "app", "db", 3306)
    _, paths = find_attack_paths(graph, HTTPS_ACCEPTED)
    assert "internet -[tcp/22]-> web -[tcp/8080]-> app -[tcp/3306]-> db" in descriptions(graph, paths)
    for path in paths:
        nodes = [path[0][0]] + [target for _, target, _ in path]
        assert len(nodes) == len(set(nodes))


def test_a_data_store_beyond_the_depth_limit_keeps_its_shortest_path():
    graph = nx.MultiDiGraph()
    graph.add_node(INTERNET, kind="internet")
    chain = [INTERNET, "w1", "w2", "w3", "db"]
    for name in chain[1:-1]:
        graph.add_node(name, kind="compute")
    graph.add_node("db", kind="database")
    for source, target in zip(chain, chain[1:]):
        add_network_edge(graph, source, target, 22)
    hops, paths = find_attack_paths(graph, set(), max_depth=2)
    assert hops["db"] == 4
    assert len(paths) == 1 and len(paths[0]) == 4


def test_the_attack_graph_of_the_demo():
    plan = load_plan("tests/fixtures/demo-insecure.plan.json")
    warnings = []
    resources = get_resources(plan, warnings)
    graph = build_infrastructure_graph(resources, get_references(plan, resources, warnings))
    attack_graph = build_attack_graph(graph, warnings)
    found = sorted((source, target, edge["label"]) for source, target, edge in attack_graph.edges(data=True))
    assert found == [
        ("aws_instance.web", "aws_db_instance.main", "tcp/3306"),
        ("aws_instance.web", "aws_s3_bucket.data", "s3:*"),
        (INTERNET, "aws_instance.web", "tcp/22"),
        (INTERNET, "aws_instance.web", "tcp/443"),
    ]