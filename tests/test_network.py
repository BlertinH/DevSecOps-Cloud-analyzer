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


def a_vpc_with_public_and_private_subnets():
    """VPC 10.0.0.0/16. public subnet: route 0.0.0.0/0 -> Internet gateway. private: -> NAT."""
    return [
        resource("aws_vpc.main", {"cidr_block": "10.0.0.0/16"}),
        resource("aws_internet_gateway.main", refs={"vpc_id": ["aws_vpc.main"]}),
        resource("aws_subnet.public", {"cidr_block": "10.0.1.0/24"}, {"vpc_id": ["aws_vpc.main"]}),
        resource("aws_subnet.private", {"cidr_block": "10.0.2.0/24"}, {"vpc_id": ["aws_vpc.main"]}),
        resource("aws_route_table.public", refs={"vpc_id": ["aws_vpc.main"]}),
        resource(
            "aws_route.public_internet",
            {"destination_cidr_block": "0.0.0.0/0"},
            {"route_table_id": ["aws_route_table.public"], "gateway_id": ["aws_internet_gateway.main"]},
        ),
        resource(
            "aws_route_table_association.public",
            refs={"subnet_id": ["aws_subnet.public"], "route_table_id": ["aws_route_table.public"]},
        ),
        resource("aws_nat_gateway.main", refs={"subnet_id": ["aws_subnet.public"]}),
        resource("aws_route_table.private", refs={"vpc_id": ["aws_vpc.main"]}),
        resource(
            "aws_route.private_nat",
            {"destination_cidr_block": "0.0.0.0/0"},
            {"route_table_id": ["aws_route_table.private"], "nat_gateway_id": ["aws_nat_gateway.main"]},
        ),
        resource(
            "aws_route_table_association.private",
            refs={"subnet_id": ["aws_subnet.private"], "route_table_id": ["aws_route_table.private"]},
        ),
        resource("aws_security_group.web", refs={"vpc_id": ["aws_vpc.main"]}),
    ]


def server(name, subnet, public_ip=True):
    """A server in one subnet, protected by the security group "web"."""
    return resource(
        f"aws_instance.{name}",
        {"associate_public_ip_address": public_ip},
        {"subnet_id": [f"aws_subnet.{subnet}"], "vpc_security_group_ids": ["aws_security_group.web"]},
    )


def workload(graph, address):
    return network.get_workloads(graph, [])[address]


def test_a_server_in_the_public_subnet_is_public_and_has_a_route():
    graph = make_graph(*a_vpc_with_public_and_private_subnets(), server("web", "public"))
    web = workload(graph, "aws_instance.web")
    assert web["kind"] == "compute"
    assert web["public"] and web["internet_route"]
    assert web["vpc"] == "aws_vpc.main"
    assert web["cidrs"] == ["10.0.1.0/24"]
    assert web["groups"] == ["aws_security_group.web"]


def test_without_a_public_ip_the_server_is_not_public():
    graph = make_graph(*a_vpc_with_public_and_private_subnets(), server("web", "public", public_ip=False))
    assert not workload(graph, "aws_instance.web")["public"]


def test_a_route_to_a_nat_gateway_is_not_a_way_in():
    graph = make_graph(*a_vpc_with_public_and_private_subnets(), server("web", "private"))
    assert not workload(graph, "aws_instance.web")["internet_route"]


def test_an_elastic_ip_makes_a_server_public():
    graph = make_graph(
        *a_vpc_with_public_and_private_subnets(),
        server("web", "public", public_ip=False),
        resource("aws_eip.web", refs={"instance": ["aws_instance.web"]}),
    )
    assert workload(graph, "aws_instance.web")["public"]


def test_a_server_without_its_own_setting_inherits_it_from_the_subnet():
    network_resources = a_vpc_with_public_and_private_subnets()
    network_resources[2]["values"]["map_public_ip_on_launch"] = True  # aws_subnet.public
    web = server("web", "public")
    web["values"] = {}
    web["unknown"] = ["associate_public_ip_address"]
    graph = make_graph(*network_resources, web)
    assert workload(graph, "aws_instance.web")["public"]


def test_a_subnet_without_its_own_route_table_uses_the_main_route_table():
    graph = make_graph(
        resource("aws_vpc.main", {"cidr_block": "10.0.0.0/16"}),
        resource("aws_internet_gateway.main", refs={"vpc_id": ["aws_vpc.main"]}),
        resource("aws_subnet.a", {"cidr_block": "10.0.1.0/24"}, {"vpc_id": ["aws_vpc.main"]}),
        resource(
            "aws_default_route_table.main",
            {"route": [{"cidr_block": "0.0.0.0/0"}]},
            {"default_route_table_id": ["aws_vpc.main"], "route": ["aws_internet_gateway.main"]},
        ),
        resource("aws_security_group.web"),
        server("web", "a"),
    )
    assert workload(graph, "aws_instance.web")["internet_route"]


def test_a_database_uses_the_subnets_of_its_subnet_group():
    graph = make_graph(
        *a_vpc_with_public_and_private_subnets(),
        resource("aws_db_subnet_group.main", refs={"subnet_ids": ["aws_subnet.private"]}),
        resource(
            "aws_db_instance.main",
            {"publicly_accessible": False},
            {"db_subnet_group_name": ["aws_db_subnet_group.main"], "vpc_security_group_ids": ["aws_security_group.web"]},
        ),
    )
    database = workload(graph, "aws_db_instance.main")
    assert database["kind"] == "database"
    assert database["subnets"] == ["aws_subnet.private"]
    assert not database["public"] and not database["internet_route"]