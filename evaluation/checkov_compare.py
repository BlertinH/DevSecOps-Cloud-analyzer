import json
import os
import subprocess

from iacgraph.cli import analyze
from iacgraph.plan import load_plan
from iacgraph.policy import load_policy

CHECKOV = os.environ.get("CHECKOV", "checkov")

SAME_RULE = {
    "CKV_AWS_24": "NET-01",
    "CKV_AWS_25": "NET-01",
    "CKV_AWS_277": "NET-01",
    "CKV_AWS_17": "NET-02",
    "CKV_AWS_16": "CFG-01",
    "CKV_AWS_62": "CFG-02",
    "CKV_AWS_63": "CFG-02",
}

RULE_IDS = ["NET-01", "NET-02", "PATH-01", "CFG-01", "CFG-02"]


def checkov_failed_checks(plan):
    command = [CHECKOV, "-f", plan, "--framework", "terraform_plan", "-o", "json", "--compact", "--quiet"]
    output = subprocess.run(command, capture_output=True, text=True).stdout
    report = json.loads(output) if output.strip() else {}
    if isinstance(report, list):
        report = report[0] if report else {}
    return report.get("results", {}).get("failed_checks", [])


def count(counts, tool, expected, found):
    for rule, _ in expected & found:
        counts[tool][rule]["TP"] += 1
    for rule, _ in found - expected:
        counts[tool][rule]["FP"] += 1
    for rule, _ in expected - found:
        counts[tool][rule]["FN"] += 1


def ratio(part, whole):
    return f"{part / whole:.2f}" if whole else "-"


def main():
    with open("evaluation/expected.json", encoding="utf-8") as file:
        scenarios = json.load(file)["scenarios"]

    counts = {tool: {rule: {"TP": 0, "FP": 0, "FN": 0} for rule in RULE_IDS} for tool in ("iacgraph", "checkov")}
    extra = []
    missed = []
    print("| Scenario | Checkov: all failed checks | Expected problems | iacgraph found | Checkov found (same rules) |")
    print("|---|---|---|---|---|")
    for scenario in scenarios:
        expected = {(f["rule"], f["resource"]) for f in scenario["findings"]}
        result = analyze(load_plan(scenario["plan"]), load_policy(scenario["policy"]))
        iacgraph = {(f["rule"], f["resource"]) for f in result["findings"]}
        failed = checkov_failed_checks(scenario["plan"])
        checkov = {(SAME_RULE[c["check_id"]], c["resource"]) for c in failed if c["check_id"] in SAME_RULE}
        count(counts, "iacgraph", expected, iacgraph)
        count(counts, "checkov", expected, checkov)
        extra += [(scenario["name"], rule, resource) for rule, resource in sorted(checkov - expected)]
        missed += [(scenario["name"], rule, resource) for rule, resource in sorted(expected - checkov)]
        print(f"| {scenario['name']} | {len(failed)} | {len(expected)} | {len(iacgraph)} | {len(checkov)} |")

    print()
    print("| Rule | iacgraph precision | iacgraph recall | Checkov TP | Checkov FP | Checkov FN | Checkov precision | Checkov recall |")
    print("|---|---|---|---|---|---|---|---|")
    for rule in RULE_IDS:
        i = counts["iacgraph"][rule]
        c = counts["checkov"][rule]
        print(
            f"| {rule} | {ratio(i['TP'], i['TP'] + i['FP'])} | {ratio(i['TP'], i['TP'] + i['FN'])} "
            f"| {c['TP']} | {c['FP']} | {c['FN']} "
            f"| {ratio(c['TP'], c['TP'] + c['FP'])} | {ratio(c['TP'], c['TP'] + c['FN'])} |"
        )

    print()
    print("Checkov alarms that are not in expected.json:")
    for name, rule, resource in extra:
        print(f"- {name}: {rule} {resource}")
    if not extra:
        print("- none")

    print()
    print("Expected problems that Checkov did not find:")
    for name, rule, resource in missed:
        print(f"- {name}: {rule} {resource}")
    if not missed:
        print("- none")


if __name__ == "__main__":
    main()
