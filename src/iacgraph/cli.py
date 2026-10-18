"""The command line, and the analysis pipeline from plan to gate decision.

Usage:
    iacgraph plan.json --policy policy.json [--format text|json] [--output FILE]

Exit codes (the CI pipeline uses them):
    0  PASS   no finding at or above fail_on
    1  BLOCK  at least one finding at or above fail_on
    2  ERROR  the analysis could not run; the gate "fails closed" and blocks
"""

import argparse
import sys

from .graph import build_infrastructure_graph
from .paths import build_attack_graph, find_attack_paths
from .plan import get_references, get_resources, load_plan
from .policy import decide, load_policy
from .report import json_report, sarif_report, text_report
from .rules import run_rules


def analyze(plan, policy):
    """Run every step of the analysis and collect the results in one dictionary."""
    warnings = []
    resources = get_resources(plan, warnings)
    references = get_references(plan, resources, warnings)
    graph = build_infrastructure_graph(resources, references)
    attack_graph = build_attack_graph(graph, warnings)
    hops, paths = find_attack_paths(attack_graph, policy["accepted"])
    findings = run_rules(graph, attack_graph, paths, policy["accepted"], warnings)
    passed, blocking = decide(findings, policy)
    return {
        "graph": graph,
        "attack_graph": attack_graph,
        "hops": hops,
        "paths": paths,
        "findings": findings,
        "warnings": warnings,
        "policy": policy,
        "passed": passed,
        "blocking": blocking,
    }


def main(arguments=None):
    parser = argparse.ArgumentParser(
        prog="iacgraph",
        description="Find insecure configurations and attack paths in a Terraform plan for AWS.",
    )
    parser.add_argument("plan", help="output of: terraform show -json tfplan")
    parser.add_argument("--policy", help="policy.json (default: fail_on high, no accepted services)")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--output", help="write the report to this file instead of the screen")
    parser.add_argument("--source-dir", default=".", help="folder with the .tf files (for SARIF line numbers)")
    args = parser.parse_args(arguments)

    try:
        plan = load_plan(args.plan)
        policy = load_policy(args.policy)
        result = analyze(plan, policy)
        if args.format == "json":
            report = json_report(result)
        elif args.format == "sarif":
            report = sarif_report(result, args.source_dir)
        else:
            report = text_report(result)
    except Exception as error:  # fail closed: any error stops the pipeline
        print(f"iacgraph: error: {error}", file=sys.stderr)
        return 2

    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(report)
    else:
        print(report, end="")

    if result["passed"]:
        return 0  # PASS
    return 1  # BLOCK