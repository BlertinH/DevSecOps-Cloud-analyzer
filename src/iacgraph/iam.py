
import fnmatch
import json

from .graph import is_unknown, referenced, referenced_by, resources_of_type, value


def as_list(item):
    if isinstance(item, str):
        return [item]
    return list(item or [])


def matches(text, pattern):
    return fnmatch.fnmatchcase(text.lower(), pattern.lower())


def policy_statements(graph, policy):
    if is_unknown(graph, policy, "policy"):
        return None
    document = json.loads(value(graph, policy, "policy") or "{}")
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]  # a policy with a single statement
    return statements


def roles_of_instance(graph, instance):
    roles = []
    for profile in referenced(graph, instance, "iam_instance_profile", "aws_iam_instance_profile"):
        roles += referenced(graph, profile, "role", "aws_iam_role")
    return roles


def policies_of_role(graph, role, warnings):
    policies = referenced_by(graph, role, "role", "aws_iam_role_policy")
    for attachment in referenced_by(graph, role, "role", "aws_iam_role_policy_attachment"):
        attached = referenced(graph, attachment, "policy_arn", "aws_iam_policy")
        if attached:
            policies += attached
        else:
            warnings.append(f"{attachment}: the attached policy (e.g. an AWS-managed one) is not in the plan; not analysed")
    return policies


def bucket_name(graph, bucket):
    if is_unknown(graph, bucket, "bucket"):
        return None
    return value(graph, bucket, "bucket")


def s3_actions_on_bucket(statements, name):

    bucket_arns = [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/some-object"]
    actions = set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        resources = as_list(statement.get("Resource", "*"))
        covers_bucket = any(matches(arn, pattern) for arn in bucket_arns for pattern in resources)
        if name is not None and not covers_bucket:
            continue  # this statement is about other resources
        for action in as_list(statement.get("Action", "*")):
            service = action.split(":")[0]  # "s3:GetObject" -> "s3", "*" -> "*"
            if matches("s3", service):
                actions.add(action)
    return sorted(actions)


def find_iam_edges(graph, warnings):
    edges = []
    for instance in resources_of_type(graph, "aws_instance"):
        for role in roles_of_instance(graph, instance):
            for policy in policies_of_role(graph, role, warnings):
                statements = policy_statements(graph, policy)
                if statements is None:
                    warnings.append(f"{policy}: the policy document is only known after apply; assumed to allow everything")
                    statements = [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                for bucket in resources_of_type(graph, "aws_s3_bucket"):
                    actions = s3_actions_on_bucket(statements, bucket_name(graph, bucket))
                    if actions:
                        edges.append(
                            {
                                "source": instance,
                                "target": bucket,
                                "kind": "iam",
                                "label": ",".join(actions),  # e.g. "s3:*"
                                "cause": policy,  # the policy that creates this edge
                            }
                        )
    return edges