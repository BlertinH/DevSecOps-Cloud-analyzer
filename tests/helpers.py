from iacgraph.graph import build_infrastructure_graph
from iacgraph.plan import get_references, get_resources


def resource(address, values=None, refs=None, unknown=()):
    """One resource for make_plan.

    address: "aws_instance.web"
    values:  known settings, e.g. {"associate_public_ip_address": True}
    refs:    references, e.g. {"subnet_id": ["aws_subnet.public"]}
    unknown: names of settings only known after apply, e.g. ["id"]
    """
    return {"address": address, "values": values or {}, "refs": refs or {}, "unknown": list(unknown)}


def make_plan(*resources):
    changes = []
    blocks = []
    for item in resources:
        resource_type, name = item["address"].split(".")
        changes.append(
            {
                "address": item["address"],
                "mode": "managed",
                "type": resource_type,
                "name": name,
                "change": {
                    "actions": ["create"],
                    "after": item["values"],
                    "after_unknown": {setting: True for setting in item["unknown"]},
                },
            }
        )
        expressions = {}
        for attribute, targets in item["refs"].items():
            references = []
            for target in targets:
                references += [f"{target}.id", target]
            expressions[attribute] = {"references": references}
        blocks.append({"address": item["address"], "expressions": expressions})
    return {"resource_changes": changes, "configuration": {"root_module": {"resources": blocks}}}


def make_graph(*resources):
    """The infrastructure graph of a tiny plan."""
    plan = make_plan(*resources)
    warnings = []
    found = get_resources(plan, warnings)
    return build_infrastructure_graph(found, get_references(plan, found, warnings))