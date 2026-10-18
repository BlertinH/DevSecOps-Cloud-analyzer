import json

import pytest

from iacgraph.graph import build_infrastructure_graph
from iacgraph.paths import build_attack_graph, find_attack_paths
from iacgraph.plan import get_references, get_resources, load_plan
from iacgraph.policy import decide, load_policy
from iacgraph.rules import run_rules


def write_policy(tmp_path, data):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    return path


def test_the_default_policy_blocks_high_and_accepts_nothing():
    assert load_policy() == {"fail_on": "high", "accepted": set()}


def test_a_policy_file_is_read(tmp_path):
    path = write_policy(tmp_path, {"fail_on": "medium", "accepted_public_services": [{"resource": "aws_instance.web", "port": 443}]})
    assert load_policy(path) == {"fail_on": "medium", "accepted": {("aws_instance.web", 443)}}


def test_a_typo_in_a_key_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        load_policy(write_policy(tmp_path, {"fail-on": "high"}))


def test_an_unknown_severity_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        load_policy(write_policy(tmp_path, {"fail_on": "urgent"}))


def test_the_gate_blocks_at_or_above_fail_on():
    findings = [{"severity": "medium"}, {"severity": "high"}]
    assert decide(findings, {"fail_on": "high", "accepted": set()}) == (False, [{"severity": "high"}])
    assert decide(findings, {"fail_on": "critical", "accepted": set()}) == (True, [])
    assert decide([], {"fail_on": "low", "accepted": set()}) == (True, [])


def test_the_insecure_demo_is_blocked_and_the_secure_demo_passes():
    decisions = {}
    for name in ("demo-insecure", "demo-secure"):
        policy = load_policy(f"terraform/{name}/policy.json")
        plan = load_plan(f"tests/fixtures/{name}.plan.json")
        resources = get_resources(plan, [])
        graph = build_infrastructure_graph(resources, get_references(plan, resources, []))
        attack_graph = build_attack_graph(graph, [])
        _, paths = find_attack_paths(attack_graph, policy["accepted"])
        findings = run_rules(graph, attack_graph, paths, policy["accepted"], [])
        passed, blocking = decide(findings, policy)
        decisions[name] = ("PASS" if passed else "BLOCK", len(blocking))
    assert decisions == {"demo-insecure": ("BLOCK", 5), "demo-secure": ("PASS", 0)}