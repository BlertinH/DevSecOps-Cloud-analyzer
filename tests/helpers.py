"""Small helpers that build tiny Terraform plans for tests.

A real plan has hundreds of lines. For a unit test we only need a few
resources, so make_plan builds the two parts of a plan that iacgraph reads:
"resource_changes" (the settings) and "configuration" (the references).
"""


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
