from helpers import make_graph, resource
from iacgraph.graph import is_unknown, referenced, referenced_by, resources_of_type, value


def small_graph():
    return make_graph(
        resource("aws_vpc.main", {"cidr_block": "10.0.0.0/16"}),
        resource("aws_subnet.public", {"cidr_block": "10.0.1.0/24"}, {"vpc_id": ["aws_vpc.main"]}),
        resource("aws_security_group.web", refs={"vpc_id": ["aws_vpc.main"]}),
        resource(
            "aws_instance.web",
            {"associate_public_ip_address": True},
            {"subnet_id": ["aws_subnet.public"], "vpc_security_group_ids": ["aws_security_group.web"]},
            unknown=["public_ip"],
        ),
    )


def test_nodes_are_resources_and_edges_are_references():
    graph = small_graph()
    assert graph.number_of_nodes() == 4
    assert graph.number_of_edges() == 4
    assert graph.has_edge("aws_instance.web", "aws_subnet.public", key="subnet_id")


def test_resources_of_type():
    assert resources_of_type(small_graph(), "aws_instance") == ["aws_instance.web"]
    assert resources_of_type(small_graph(), "aws_s3_bucket") == []


def test_referenced_follows_edges_forward():
    graph = small_graph()
    assert referenced(graph, "aws_instance.web", "subnet_id") == ["aws_subnet.public"]
    assert referenced(graph, "aws_instance.web", "subnet_id", "aws_vpc") == []


def test_referenced_by_follows_edges_backward():
    graph = small_graph()
    assert referenced_by(graph, "aws_vpc.main", "vpc_id") == ["aws_security_group.web", "aws_subnet.public"]
    assert referenced_by(graph, "aws_vpc.main", "vpc_id", "aws_subnet") == ["aws_subnet.public"]


def test_value_and_is_unknown():
    graph = small_graph()
    assert value(graph, "aws_subnet.public", "cidr_block") == "10.0.1.0/24"
    assert value(graph, "aws_subnet.public", "not_set") is None
    assert is_unknown(graph, "aws_instance.web", "public_ip")
    assert not is_unknown(graph, "aws_instance.web", "associate_public_ip_address")