
import ipaddress

from .graph import referenced, resources_of_type, value

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