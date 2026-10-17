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


def ssh_from_anywhere():
    return resource(
        "aws_vpc_security_group_ingress_rule.web_ssh",
        {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "0.0.0.0/0"},
        {"security_group_id": ["aws_security_group.web"]},
    )


def edges(graph):
    """(source, target, label) of every network edge, sorted."""
    return sorted((edge["source"], edge["target"], edge["label"]) for edge in network.find_network_edges(graph, []))


def test_a_public_server_with_ssh_open_is_reachable_from_the_internet():
    graph = make_graph(*a_vpc_with_public_and_private_subnets(), ssh_from_anywhere(), server("web", "public"))
    assert edges(graph) == [(network.INTERNET, "aws_instance.web", "tcp/22")]


def test_the_same_rule_on_a_server_in_a_private_subnet_creates_no_edge():
    """The firewall rule alone looks dangerous; the graph shows nobody can reach it."""
    graph = make_graph(*a_vpc_with_public_and_private_subnets(), ssh_from_anywhere(), server("web", "private"))
    assert edges(graph) == []


def test_a_rule_for_one_office_network_is_not_the_whole_internet():
    office_ssh = resource(
        "aws_vpc_security_group_ingress_rule.office_ssh",
        {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv4": "203.0.113.0/24"},
        {"security_group_id": ["aws_security_group.web"]},
    )
    graph = make_graph(*a_vpc_with_public_and_private_subnets(), office_ssh, server("web", "public"))
    assert edges(graph) == []


def web_and_database(web_egress=True):
    """A private web server and a private database that accepts MySQL from the web group."""
    resources = [
        *a_vpc_with_public_and_private_subnets(),
        resource("aws_security_group.db", refs={"vpc_id": ["aws_vpc.main"]}),
        server("web", "public", public_ip=False),
        resource("aws_db_subnet_group.main", refs={"subnet_ids": ["aws_subnet.private"]}),
        resource(
            "aws_db_instance.main",
            {"publicly_accessible": False},
            {"db_subnet_group_name": ["aws_db_subnet_group.main"], "vpc_security_group_ids": ["aws_security_group.db"]},
        ),
        resource(
            "aws_vpc_security_group_ingress_rule.db_from_web",
            {"ip_protocol": "tcp", "from_port": 3306, "to_port": 3306},
            {"security_group_id": ["aws_security_group.db"], "referenced_security_group_id": ["aws_security_group.web"]},
        ),
    ]
    if web_egress:
        resources.append(
            resource(
                "aws_vpc_security_group_egress_rule.web_all",
                {"ip_protocol": "-1", "cidr_ipv4": "0.0.0.0/0"},
                {"security_group_id": ["aws_security_group.web"]},
            )
        )
    return make_graph(*resources)


def test_the_web_server_can_connect_to_the_database():
    assert edges(web_and_database()) == [("aws_instance.web", "aws_db_instance.main", "tcp/3306")]


def test_without_an_egress_rule_the_web_server_cannot_connect():
    assert edges(web_and_database(web_egress=False)) == []


def test_the_insecure_demo_has_ssh_and_https_from_the_internet_and_mysql_inside():
    from iacgraph.graph import build_infrastructure_graph
    from iacgraph.plan import get_references, get_resources, load_plan

    plan = load_plan("tests/fixtures/demo-insecure.plan.json")
    resources = get_resources(plan, [])
    graph = build_infrastructure_graph(resources, get_references(plan, resources, []))
    assert edges(graph) == [
        ("aws_instance.web", "aws_db_instance.main", "tcp/3306"),
        (network.INTERNET, "aws_instance.web", "tcp/22"),
        (network.INTERNET, "aws_instance.web", "tcp/443"),
    ]