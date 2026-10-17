import json

NOT_A_RESOURCE = ("var", "local", "data", "module", "each", "count", "path", "self", "terraform")


def load_plan(path):
    """Read a plan file and return it as a dictionary."""
    with open(path, encoding="utf-8") as file:
        plan = json.load(file)
    if "resource_changes" not in plan or "configuration" not in plan:
        raise ValueError(f"{path} is not a Terraform plan (create it with: terraform show -json tfplan)")
    return plan


def get_resources(plan, warnings):
    """Every resource that will exist after `terraform apply`.

    Returns a dictionary, for example:
    {"aws_instance.web": {"type": "aws_instance",
                          "values": {"associate_public_ip_address": True, ...},
                          "unknown": {"id", "public_ip", ...}}}

    "values" are the settings Terraform already knows.
    "unknown" are the names of settings Terraform only knows after apply.
    """
    resources = {}
    in_modules = 0
    for change in plan["resource_changes"]:
        if change.get("mode") != "managed":
            continue  # a data source is only read, never created
        if change.get("module_address"):
            in_modules += 1
            continue  # only the root module is analysed
        if change.get("deposed"):
            continue  # an old copy that Terraform is replacing
        if change["change"]["actions"] == ["delete"]:
            continue  # will not exist after apply

        after_unknown = change["change"].get("after_unknown") or {}
        resources[change["address"]] = {
            "type": change["type"],
            "values": change["change"].get("after") or {},
            "unknown": {name for name, unknown in after_unknown.items() if unknown is True},
        }

    if in_modules:
        warnings.append(f"{in_modules} resource(s) inside modules are not analysed")
    return resources


def find_reference_strings(expression):
    """All strings in the "references" lists inside one expression.

    A simple expression looks like this:
        {"references": ["aws_subnet.public_a.id", "aws_subnet.public_a"]}
    Expressions of nested blocks contain lists and dictionaries, so the
    function calls itself for everything inside (recursion).
    """
    found = []
    if isinstance(expression, dict):
        found.extend(expression.get("references", []))
        for key, inner in expression.items():
            if key not in ("references", "constant_value"):
                found.extend(find_reference_strings(inner))
    elif isinstance(expression, list):
        for item in expression:
            found.extend(find_reference_strings(item))
    return found


def without_index(address):
    """'aws_subnet.public[0]' -> 'aws_subnet.public' (count and for_each add an index)."""
    return address.split("[")[0]


def get_references(plan, resources, warnings):
    """Which resource refers to which, through which setting.

    Returns a sorted list of (source, attribute, target) tuples, for example
    ("aws_instance.web", "subnet_id", "aws_subnet.public_a").
    """
    # With count or for_each, one resource block creates several resources:
    # "aws_subnet.public" -> ["aws_subnet.public[0]", "aws_subnet.public[1]"]
    instances = {}
    for address in resources:
        instances.setdefault(without_index(address), []).append(address)

    # The "configuration" part of the plan shows each resource block once,
    # with the expressions written in the .tf files.
    root_module = plan["configuration"].get("root_module", {})
    blocks = {block["address"]: block for block in root_module.get("resources", [])}

    references = set()
    for source in resources:
        block = blocks.get(without_index(source), {})
        for attribute, expression in block.get("expressions", {}).items():
            for text in find_reference_strings(expression):
                parts = text.split(".")
                if parts[0] == "local":
                    warnings.append(f"{source}: {attribute} uses {text}; references through locals are not followed")
                if parts[0] in NOT_A_RESOURCE or len(parts) < 2:
                    continue
                target_block = parts[0] + "." + without_index(parts[1])
                for target in instances.get(target_block, []):
                    if target != source:
                        references.add((source, attribute, target))
    return sorted(references)
