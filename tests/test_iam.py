import json

from helpers import make_graph, resource
from iacgraph import iam


def server_with_policy(*statements):
    policy = json.dumps({"Version": "2012-10-17", "Statement": list(statements)})
    return make_graph(
        resource("aws_s3_bucket.data", {"bucket": "my-data"}),
        resource("aws_iam_role.app"),
        resource("aws_iam_role_policy.app", {"policy": policy}, {"role": ["aws_iam_role.app"]}),
        resource("aws_iam_instance_profile.app", refs={"role": ["aws_iam_role.app"]}),
        resource("aws_instance.web", refs={"iam_instance_profile": ["aws_iam_instance_profile.app"]}),
    )


def access(graph):
    return [(edge["source"], edge["target"], edge["label"]) for edge in iam.find_iam_edges(graph, [])]


def test_matches_uses_iam_wildcards():
    assert iam.matches("arn:aws:s3:::my-data", "arn:aws:s3:::my-*")
    assert iam.matches("s3", "*")
    assert not iam.matches("arn:aws:s3:::other", "arn:aws:s3:::my-*")


def test_a_policy_on_the_bucket_gives_the_server_access():
    graph = server_with_policy({"Effect": "Allow", "Action": "s3:*", "Resource": ["arn:aws:s3:::my-data", "arn:aws:s3:::my-data/*"]})
    assert access(graph) == [("aws_instance.web", "aws_s3_bucket.data", "s3:*")]


def test_only_the_allowed_actions_are_listed():
    graph = server_with_policy({"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::my-data/*"})
    assert access(graph) == [("aws_instance.web", "aws_s3_bucket.data", "s3:GetObject,s3:PutObject")]


def test_a_policy_on_another_bucket_gives_no_access():
    graph = server_with_policy({"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::other/*"})
    assert access(graph) == []


def test_a_policy_for_another_service_gives_no_access():
    graph = server_with_policy({"Effect": "Allow", "Action": "ec2:*", "Resource": "*"})
    assert access(graph) == []


def test_an_unknown_policy_document_is_assumed_to_allow_everything():
    graph = server_with_policy()
    graph.nodes["aws_iam_role_policy.app"]["unknown"].add("policy")
    warnings = []
    assert [edge["label"] for edge in iam.find_iam_edges(graph, warnings)] == ["*"]
    assert "only known after apply" in warnings[0]


def test_the_demo_web_server_has_full_access_and_the_fixed_one_only_three_actions():
    from iacgraph.graph import build_infrastructure_graph
    from iacgraph.plan import get_references, get_resources, load_plan

    found = {}
    for name in ("demo-insecure", "demo-secure"):
        plan = load_plan(f"tests/fixtures/{name}.plan.json")
        resources = get_resources(plan, [])
        graph = build_infrastructure_graph(resources, get_references(plan, resources, []))
        found[name] = access(graph)
    assert found["demo-insecure"] == [("aws_instance.web", "aws_s3_bucket.data", "s3:*")]
    assert found["demo-secure"] == [("aws_instance.web", "aws_s3_bucket.data", "s3:GetObject,s3:ListBucket,s3:PutObject")]