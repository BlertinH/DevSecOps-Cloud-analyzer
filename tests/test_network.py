from helpers import make_graph, resource
from iacgraph import network


def rule(protocol, from_port, to_port):
    """A firewall rule with only the fields these tests need."""
    return network.make_rule("r", "g", "ingress", protocol, from_port, to_port, [], [])


def test_describe_ports():
    assert network.describe_ports(rule("tcp", 22, 22)) == "tcp/22"
    assert network.describe_ports(rule("tcp", 0, 65535)) == "tcp/0-65535"
    assert network.describe_ports(rule("-1", None, None)) == "all"


def test_allows_port():
    assert network.allows_port(rule("tcp", 22, 22), "tcp", 22)
    assert not network.allows_port(rule("tcp", 22, 22), "tcp", 3389)
    assert not network.allows_port(rule("tcp", 22, 22), "udp", 22)
    assert network.allows_port(rule("-1", None, None), "tcp", 3389)


def test_same_traffic():
    assert network.same_traffic(rule("tcp", 3306, 3306), rule("-1", None, None))
    assert not network.same_traffic(rule("tcp", 3306, 3306), rule("tcp", 443, 443))


def test_cidr_contains():
    assert network.cidr_contains("0.0.0.0/0", "10.0.1.0/24")
    assert network.cidr_contains("10.0.0.0/16", "10.0.1.0/24")
    assert not network.cidr_contains("10.0.1.0/24", "10.0.0.0/16")
    assert not network.cidr_contains("::/0", "10.0.1.0/24")  # IPv6 never contains IPv4


def test_the_three_styles_of_firewall_rules_are_read_the_same_way():
    graph = make_graph(
        resource(
            "aws_security_group.a",
            {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]},
        ),
        resource(
            "aws_security_group_rule.legacy",
            {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]},
            {"security_group_id": ["aws_security_group.a"]},
        ),
        resource(
            "aws_vpc_security_group_ingress_rule.new",
            {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "0.0.0.0/0"},
            {"security_group_id": ["aws_security_group.a"]},
        ),
    )
    rules = network.get_firewall_rules(graph, [])
    assert len(rules) == 3
    for found in rules:
        assert found["group"] == "aws_security_group.a"
        assert found["direction"] == "ingress"
        assert network.describe_ports(found) == "tcp/22"
        assert found["cidrs"] == ["0.0.0.0/0"]


def test_a_rule_whose_security_group_is_not_in_the_plan_is_ignored():
    graph = make_graph(
        resource(
            "aws_vpc_security_group_ingress_rule.x",
            {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "0.0.0.0/0", "security_group_id": "sg-0123"},
        )
    )
    warnings = []
    assert network.get_firewall_rules(graph, warnings) == []
    assert "not in the plan" in warnings[0]