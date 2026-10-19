import json

import pytest

from iacgraph.cli import analyze
from iacgraph.plan import load_plan
from iacgraph.policy import load_policy

with open("evaluation/expected.json", encoding="utf-8") as file:
    SCENARIOS = json.load(file)["scenarios"]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_scenario(scenario):
    result = analyze(load_plan(scenario["plan"]), load_policy(scenario["policy"]))
    found = sorted((f["rule"], f["resource"], f["target"], f["severity"]) for f in result["findings"])
    expected = sorted((f["rule"], f["resource"], f["target"], f["severity"]) for f in scenario["findings"])
    assert found == expected
    assert ("PASS" if result["passed"] else "BLOCK") == scenario["gate"]
