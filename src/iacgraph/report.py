import json

from . import __version__
from .paths import describe_path, is_accepted
from .rules import RULES


def text_report(result):
    attack_graph = result["attack_graph"]
    accepted = result["policy"]["accepted"]
    graph = result["graph"]
    lines = [f"iacgraph {__version__}"]
    lines.append(f"Infrastructure graph: {graph.number_of_nodes()} resources, {graph.number_of_edges()} references")

    lines.append("")
    lines.append(f"Attack graph edges: {attack_graph.number_of_edges()}")
    for source, target, edge in attack_graph.edges(data=True):
        note = ""
        if is_accepted(edge, accepted):
            note = "  [accepted public service]"
        lines.append(f"  {source} -> {target}  {edge['label']}  via {edge['cause']}{note}")

    lines.append("")
    lines.append(f"Reachable by an attacker from the Internet (BFS): {len(result['hops'])}")
    for node, steps in result["hops"].items():  # BFS order: nearest first
        lines.append(f"  {steps} step(s)  {node}")

    lines.append("")
    lines.append(f"Attack paths: {len(result['paths'])}")
    for number, path in enumerate(result["paths"], start=1):
        lines.append(f"  AP-{number}  {describe_path(attack_graph, path)}")

    lines.append("")
    lines.append(f"Findings: {len(result['findings'])}")
    for finding in result["findings"]:
        raised = ""
        if finding["raised"]:
            raised = "  (raised: on an attack path)"
        lines.append(f"  [{finding['severity'].upper()}] {finding['rule']}  {finding['resource']}{raised}")
        lines.append(f"      {finding['message']}")
        lines.append(f"      fix: {RULES[finding['rule']]['fix']}")

    if result["warnings"]:
        lines.append("")
        lines.append("Warnings (parts of the plan that are not fully analysed):")
        for warning in sorted(set(result["warnings"])):
            lines.append(f"  - {warning}")

    lines.append("")
    fail_on = result["policy"]["fail_on"]
    if result["passed"]:
        lines.append(f"Gate: PASS (no finding at or above {fail_on})")
    else:
        lines.append(f"Gate: BLOCK ({len(result['blocking'])} finding(s) at or above {fail_on})")
    return "\n".join(lines) + "\n"


def json_report(result):
    attack_graph = result["attack_graph"]
    report = {
        "tool": "iacgraph",
        "version": __version__,
        "edges": [
            {"source": source, "target": target, "kind": edge["kind"], "label": edge["label"], "cause": edge["cause"]}
            for source, target, edge in attack_graph.edges(data=True)
        ],
        "reachable": result["hops"],
        "attack_paths": [
            {"id": f"AP-{number}", "target": path[-1][1], "path": describe_path(attack_graph, path)}
            for number, path in enumerate(result["paths"], start=1)
        ],
        "findings": result["findings"],
        "warnings": sorted(set(result["warnings"])),
        "gate": {
            "decision": "PASS" if result["passed"] else "BLOCK",
            "fail_on": result["policy"]["fail_on"],
            "blocking": len(result["blocking"]),
        },
    }
    return json.dumps(report, indent=2) + "\n"