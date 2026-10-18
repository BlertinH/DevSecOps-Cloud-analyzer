import json

from .rules import SEVERITIES

ALLOWED_KEYS = {"fail_on", "accepted_public_services"}


def load_policy(path=None):
    data = {}
    if path is not None:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)

    unknown_keys = set(data) - ALLOWED_KEYS
    if unknown_keys:
        raise ValueError(f"{path}: unknown key(s): {', '.join(sorted(unknown_keys))}")

    fail_on = data.get("fail_on", "high")
    if fail_on not in SEVERITIES:
        raise ValueError(f"{path}: fail_on must be one of {SEVERITIES}, not '{fail_on}'")

    accepted = set()
    for service in data.get("accepted_public_services", []):
        accepted.add((service["resource"], int(service["port"])))
    return {"fail_on": fail_on, "accepted": accepted}


def decide(findings, policy):
    threshold = SEVERITIES.index(policy["fail_on"])
    blocking = [finding for finding in findings if SEVERITIES.index(finding["severity"]) >= threshold]
    return len(blocking) == 0, blocking