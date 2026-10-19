import json
import re
import statistics
import time

from iacgraph.cli import analyze
from iacgraph.plan import load_plan
from iacgraph.policy import load_policy

RUNS = 3
COPIES = [1, 10, 50, 100, 200, 500]
BASE_PLAN = "tests/fixtures/demo-insecure.plan.json"
BASE_POLICY = "terraform/demo-insecure/policy.json"


def measure(plan, policy):
    times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        result = analyze(plan, policy)
        times.append(time.perf_counter() - start)
    return statistics.median(times), result


def bigger_plan(base, copies):
    addresses = [change["address"] for change in base["resource_changes"]]
    buckets = [c["change"]["after"]["bucket"] for c in base["resource_changes"] if c["type"] == "aws_s3_bucket"]
    pattern = re.compile(r"\b(" + "|".join(re.escape(address) for address in addresses) + r")\b")
    original = json.dumps({"changes": base["resource_changes"], "blocks": base["configuration"]["root_module"]["resources"]})
    plan = {"resource_changes": [], "configuration": {"root_module": {"resources": []}}}
    for number in range(copies):
        text = pattern.sub(lambda match: f"{match.group(1)}_{number}", original)
        for bucket in buckets:
            text = text.replace(bucket, f"{bucket}-{number}")
        copy = json.loads(text)
        plan["resource_changes"] += copy["changes"]
        plan["configuration"]["root_module"]["resources"] += copy["blocks"]
    return plan


def bigger_policy(base, copies):
    accepted = {(f"{resource}_{number}", port) for resource, port in base["accepted"] for number in range(copies)}
    return {"fail_on": base["fail_on"], "accepted": accepted}


def main():
    with open("evaluation/expected.json", encoding="utf-8") as file:
        scenarios = json.load(file)["scenarios"]

    print("| Scenario | Resources | Time (ms) |")
    print("|---|---|---|")
    for scenario in scenarios:
        seconds, result = measure(load_plan(scenario["plan"]), load_policy(scenario["policy"]))
        print(f"| {scenario['name']} | {result['graph'].number_of_nodes()} | {seconds * 1000:.1f} |")

    print()
    print("| Copies of demo-insecure | Resources | Attack graph nodes | Attack graph edges | Attack paths | Findings | Time (s) |")
    print("|---|---|---|---|---|---|---|")
    base = load_plan(BASE_PLAN)
    policy = load_policy(BASE_POLICY)
    for copies in COPIES:
        seconds, result = measure(bigger_plan(base, copies), bigger_policy(policy, copies))
        attack_graph = result["attack_graph"]
        print(
            f"| {copies} | {result['graph'].number_of_nodes()} | {attack_graph.number_of_nodes()} "
            f"| {attack_graph.number_of_edges()} | {len(result['paths'])} | {len(result['findings'])} | {seconds:.2f} |"
        )


if __name__ == "__main__":
    main()
