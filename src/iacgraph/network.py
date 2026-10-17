import ipaddress

from .graph import is_unknown, referenced, referenced_by, resources_of_type, value

PROTOCOL_NAMES = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp"}


def make_rule(resource, group, direction, protocol, from_port, to_port, cidrs, peers):
    """One firewall rule in a simple, uniform format (a dictionary)."""
    protocol = str(protocol).lower()
    return {
        "resource": resource,  # the Terraform resource that defines the rule
        "group": group,  # the security group the rule belongs to
        "direction": direction,  # "ingress" (incoming) or "egress" (outgoing)
        "protocol": PROTOCOL_NAMES.get(protocol, protocol),
        "from_port": from_port,
        "to_port": to_port,
        "cidrs": [cidr for cidr in cidrs if cidr],  # address ranges, e.g. "0.0.0.0/0"
        "peers": peers,  # security groups allowed on the other side
    }


def get_firewall_rules(graph, warnings):
    """Every security-group rule of the plan, in the format of make_rule.

    Terraform has three ways to write a rule; all three are read here.
    """
    rules = []

    for direction in ("ingress", "egress"):
        for address in resources_of_type(graph, f"aws_vpc_security_group_{direction}_rule"):
            settings = graph.nodes[address]["values"]
            peers = referenced(graph, address, "referenced_security_group_id", "aws_security_group")
            for group in owner_groups(graph, address, warnings):
                rules.append(
                    make_rule(
                        address,
                        group,
                        direction,
                        settings.get("ip_protocol"),
                        settings.get("from_port"),
                        settings.get("to_port"),
                        [settings.get("cidr_ipv4"), settings.get("cidr_ipv6")],
                        peers,
                    )
                )

    for address in resources_of_type(graph, "aws_security_group_rule"):
        settings = graph.nodes[address]["values"]
        peers = referenced(graph, address, "source_security_group_id", "aws_security_group")
        for group in owner_groups(graph, address, warnings):
            rules.append(
                make_rule(
                    address,
                    group,
                    settings.get("type"),
                    settings.get("protocol"),
                    settings.get("from_port"),
                    settings.get("to_port"),
                    (settings.get("cidr_blocks") or []) + (settings.get("ipv6_cidr_blocks") or []),
                    peers + ([group] if settings.get("self") else []),
                )
            )

   
    for group in resources_of_type(graph, "aws_security_group"):
        for direction in ("ingress", "egress"):
            peers = referenced(graph, group, direction, "aws_security_group")
            for block in value(graph, group, direction) or []:
                rules.append(
                    make_rule(
                        group,
                        group,
                        direction,
                        block.get("protocol"),
                        block.get("from_port"),
                        block.get("to_port"),
                        (block.get("cidr_blocks") or []) + (block.get("ipv6_cidr_blocks") or []),
                        peers + ([group] if block.get("self") else []),
                    )
                )
    return rules


def owner_groups(graph, rule, warnings):
    """The security group a separate rule resource belongs to."""
    groups = referenced(graph, rule, "security_group_id", "aws_security_group")
    if not groups:
        warnings.append(f"{rule}: its security group is not in the plan, so the rule is ignored")
    return groups


def port_range(rule):
    """(first, last) port of a rule. A missing value means "all ports"."""
    first = rule["from_port"] if rule["from_port"] is not None else 0
    last = rule["to_port"] if rule["to_port"] is not None else 65535
    return first, last


def describe_ports(rule):
    """A short label for a rule: "tcp/22", "tcp/0-65535", "udp/53", "all"."""
    if rule["protocol"] not in ("tcp", "udp"):
        return rule["protocol"]
    first, last = port_range(rule)
    if first == last:
        return f"{rule['protocol']}/{first}"
    return f"{rule['protocol']}/{first}-{last}"


def allows_port(rule, protocol, port):
    """Does the rule let this traffic through? Example: allows_port(rule, "tcp", 22)."""
    if rule["protocol"] == "all":
        return True
    first, last = port_range(rule)
    return rule["protocol"] == protocol and first <= port <= last


def same_traffic(rule_a, rule_b):
    """Can some traffic pass both rules (same protocol and overlapping ports)?"""
    if rule_a["protocol"] == "all" or rule_b["protocol"] == "all":
        return True
    if rule_a["protocol"] != rule_b["protocol"]:
        return False
    if rule_a["protocol"] not in ("tcp", "udp"):
        return True
    first_a, last_a = port_range(rule_a)
    first_b, last_b = port_range(rule_b)
    return first_a <= last_b and first_b <= last_a


def is_anywhere(cidr):
    """0.0.0.0/0 (every IPv4 address) or ::/0 (every IPv6 address): the whole Internet."""
    return cidr in ("0.0.0.0/0", "::/0")


def cidr_contains(outer, inner):
    """Is every address of the range `inner` also in the range `outer`?"""
    try:
        outer_network = ipaddress.ip_network(outer, strict=False)
        inner_network = ipaddress.ip_network(inner, strict=False)
    except ValueError:
        return False
    return outer_network.version == inner_network.version and inner_network.subnet_of(outer_network)
    # ---------------------------------------------------------------------------
# 2. Workloads: public address, route to the Internet, security groups
# ---------------------------------------------------------------------------


def instance_is_public(graph, instance, subnets):
    """Will the server get a public IP address?"""
    # An Elastic IP attached to the server.
    if referenced_by(graph, instance, "instance", "aws_eip"):
        return True
    if referenced_by(graph, instance, "instance_id", "aws_eip_association"):
        return True
    # Set on the server itself.
    setting = value(graph, instance, "associate_public_ip_address")
    if setting is not None and not is_unknown(graph, instance, "associate_public_ip_address"):
        return setting is True
    # Not set: the subnet decides. If we do not know the subnet, assume the worst.
    if not subnets:
        return True
    for subnet in subnets:
        if value(graph, subnet, "map_public_ip_on_launch") is True:
            return True
        if is_unknown(graph, subnet, "map_public_ip_on_launch"):
            return True
    return False


def table_routes_to_internet(graph, table):
   
    # Routes written as separate aws_route resources.
    for route in referenced_by(graph, table, "route_table_id", "aws_route"):
        to_gateway = referenced(graph, route, "gateway_id", "aws_internet_gateway")
        existing_gateway = str(value(graph, route, "gateway_id")).startswith("igw-")
        if value(graph, route, "destination_cidr_block") == "0.0.0.0/0" and (to_gateway or existing_gateway):
            return True
    # Routes written as "route" blocks inside the route table.
    to_gateway = referenced(graph, table, "route", "aws_internet_gateway")
    for block in value(graph, table, "route") or []:
        existing_gateway = str(block.get("gateway_id")).startswith("igw-")
        if block.get("cidr_block") == "0.0.0.0/0" and (to_gateway or existing_gateway):
            return True
    return False


def main_route_tables(graph, vpc):
    """The VPC's main route table: used by every subnet without its own route table."""
    tables = referenced_by(graph, vpc, "default_route_table_id", "aws_default_route_table")
    for association in referenced_by(graph, vpc, "vpc_id", "aws_main_route_table_association"):
        tables += referenced(graph, association, "route_table_id")
    return tables


def subnet_routes_to_internet(graph, subnet):
    """Can the Internet reach a public address in this subnet?"""
    tables = []
    for association in referenced_by(graph, subnet, "subnet_id", "aws_route_table_association"):
        tables += referenced(graph, association, "route_table_id")
    if not tables:
        for vpc in referenced(graph, subnet, "vpc_id", "aws_vpc"):
            tables += main_route_tables(graph, vpc)
    return any(table_routes_to_internet(graph, table) for table in tables)


def get_workloads(graph, warnings):
    """Servers and databases, with everything that decides who can reach them.

    Returns a dictionary: address -> {"kind", "subnets", "public", "groups",
                                      "vpc", "cidrs", "internet_route"}
    """
    workloads = {}
    for address in resources_of_type(graph, "aws_instance"):
        subnets = referenced(graph, address, "subnet_id", "aws_subnet")
        public = instance_is_public(graph, address, subnets)
        workloads[address] = {"kind": "compute", "subnets": subnets, "public": public}

    for address in resources_of_type(graph, "aws_db_instance"):
        subnets = []
        for subnet_group in referenced(graph, address, "db_subnet_group_name", "aws_db_subnet_group"):
            subnets += referenced(graph, subnet_group, "subnet_ids", "aws_subnet")
        public = value(graph, address, "publicly_accessible") is True or is_unknown(graph, address, "publicly_accessible")
        workloads[address] = {"kind": "database", "subnets": subnets, "public": public}

    for address, workload in workloads.items():
        subnets = workload["subnets"]
        workload["groups"] = referenced(graph, address, "vpc_security_group_ids", "aws_security_group")
        vpcs = [vpc for subnet in subnets for vpc in referenced(graph, subnet, "vpc_id", "aws_vpc")]
        workload["vpc"] = vpcs[0] if vpcs else None
        workload["cidrs"] = [value(graph, subnet, "cidr_block") for subnet in subnets if value(graph, subnet, "cidr_block")]
        if subnets:
            workload["internet_route"] = any(subnet_routes_to_internet(graph, subnet) for subnet in subnets)
        else:
            warnings.append(f"{address}: its subnet is not in the plan; assumed to have a route to the Internet")
            workload["internet_route"] = True
        if not workload["groups"]:
            warnings.append(f"{address}: no security group of the plan is attached; its firewall rules are not visible")
    return workloads

INTERNET = "internet"


def rules_of(rules, groups, direction):
    """The rules of these security groups in one direction."""
    return [rule for rule in rules if rule["group"] in groups and rule["direction"] == direction]


def rule_admits(rule, workload):
    """Does the rule accept this workload as the other side of the connection?"""
    if set(rule["peers"]) & set(workload["groups"]):
        return True
    for cidr in rule["cidrs"]:
        if not workload["cidrs"]:
            return True  # the workload's addresses are not known: assume yes
        if any(cidr_contains(cidr, workload_cidr) for workload_cidr in workload["cidrs"]):
            return True
    return False


def same_network(workload_a, workload_b):
    """Are both in the same VPC? If a VPC is unknown, assume yes."""
    if workload_a["vpc"] is None or workload_b["vpc"] is None:
        return True
    return workload_a["vpc"] == workload_b["vpc"]


def network_edge(source, target, rule):
    return {
        "source": source,
        "target": target,
        "kind": "network",
        "label": describe_ports(rule),  # e.g. "tcp/22"
        "cause": rule["resource"],  # the resource that creates this edge
        "rule": rule,
    }


def find_network_edges(graph, warnings):
    """Every network edge of the attack graph. One edge per firewall rule."""
    rules = get_firewall_rules(graph, warnings)
    workloads = get_workloads(graph, warnings)
    edges = []

    # 1. From the Internet: a public address AND a route to an Internet gateway
    #    AND an ingress rule that accepts everyone (0.0.0.0/0).
    for address, workload in workloads.items():
        if not (workload["public"] and workload["internet_route"]):
            continue
        for rule in rules_of(rules, workload["groups"], "ingress"):
            if any(is_anywhere(cidr) for cidr in rule["cidrs"]):
                edges.append(network_edge(INTERNET, address, rule))

    # 2. Between workloads (lateral movement): the source's egress rule lets the
    #    traffic out AND the target's ingress rule lets it in.
    for source, source_workload in workloads.items():
        if source_workload["kind"] != "compute":
            continue  # a managed database never opens connections itself
        outgoing = rules_of(rules, source_workload["groups"], "egress")
        for target, target_workload in workloads.items():
            if target == source or not same_network(source_workload, target_workload):
                continue
            for incoming in rules_of(rules, target_workload["groups"], "ingress"):
                if not rule_admits(incoming, source_workload):
                    continue
                for rule_out in outgoing:
                    if rule_admits(rule_out, target_workload) and same_traffic(incoming, rule_out):
                        edges.append(network_edge(source, target, incoming))
                        break
    return edges