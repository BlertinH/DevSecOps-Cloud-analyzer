import json

from iacgraph.cli import analyze
from iacgraph.plan import load_plan
from iacgraph.policy import load_policy

RULE_IDS = ["NET-01", "NET-02", "PATH-01", "CFG-01", "CFG-02"]


def finding_key(finding):
    return (finding["rule"], finding["resource"], finding["target"], finding["severity"])


def ratio(part, whole):
    return f"{part / whole:.2f}" if whole else "-"


def main():
    with open("evaluation/expected.json", encoding="utf-8") as file:
        scenarios = json.load(file)["scenarios"]

    counts = {rule: {"TP": 0, "FP": 0, "FN": 0} for rule in RULE_IDS}
    print("| Scenario | Expected | Found | Gate (expected) | Gate (found) |")
    print("|---|---|---|---|---|")
    for scenario in scenarios:
        result = analyze(load_plan(scenario["plan"]), load_policy(scenario["policy"]))
        expected = {finding_key(f) for f in scenario["findings"]}
        found = {finding_key(f) for f in result["findings"]}
        for key in expected & found:
            counts[key[0]]["TP"] += 1
        for key in found - expected:
            counts[key[0]]["FP"] += 1
        for key in expected - found:
            counts[key[0]]["FN"] += 1
        gate = "PASS" if result["passed"] else "BLOCK"
        print(f"| {scenario['name']} | {len(expected)} | {len(found)} | {scenario['gate']} | {gate} |")

    print()
    print("| Rule | TP | FP | FN | Precision | Recall |")
    print("|---|---|---|---|---|---|")
    for rule, c in counts.items():
        precision = ratio(c["TP"], c["TP"] + c["FP"])
        recall = ratio(c["TP"], c["TP"] + c["FN"])
        print(f"| {rule} | {c['TP']} | {c['FP']} | {c['FN']} | {precision} | {recall} |")


if __name__ == "__main__":
    main()
