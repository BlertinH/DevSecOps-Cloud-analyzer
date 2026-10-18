
from .graph import is_unknown, resources_of_type, value
from .iam import as_list, policy_statements
from .network import INTERNET, allows_port
from .paths import is_accepted

SEVERITIES = ["low", "medium", "high", "critical"]

RULES = {
    "NET-01": {
        "severity": "high",
        "title": "Administrative port reachable from the Internet",
        "fix": "Remove the rule or limit its source addresses; use AWS Systems Manager instead of SSH/RDP.",
    },
    "NET-02": {
        "severity": "critical",
        "title": "Database reachable from the Internet",
        "fix": "Set publicly_accessible = false, use private subnets, allow only the application's security group.",
    },
    "PATH-01": {
        "severity": "high",
        "title": "Data store reachable through an attack path",
        "fix": "Break the path: close the exposed entry port, or remove a firewall rule or IAM permission on it.",
    },
    "CFG-01": {
        "severity": "medium",
        "title": "Database storage not encrypted",
        "fix": "Set storage_encrypted = true.",
    },
    "CFG-02": {
        "severity": "medium",
        "title": "IAM policy allows all actions of a service",
        "fix": "List only the actions the workload needs (least privilege).",
    },
}

ADMIN_PORTS = (22, 3389)  # SSH and RDP


def new_finding(rule_id, resource, message, target=""):
    return {
        "rule": rule_id,
        "resource": resource,  # the resource to fix
        "target": target,  # for NET-01: the server that the rule exposes
        "severity": RULES[rule_id]["severity"],
        "message": message,
        "raised": False,  # True if an attack path raised the severity
    }


def internet_edges(attack_graph, kind, accepted):
    edges = []
    for source, target, edge in attack_graph.edges(data=True):
        if source == INTERNET and attack_graph.nodes[target]["kind"] == kind and not is_accepted(edge, accepted):
            edges.append(edge)
    return edges


def check_net_01(attack_graph, accepted):
    findings = []
    for edge in internet_edges(attack_graph, "compute", accepted):
        ports = [port for port in ADMIN_PORTS if allows_port(edge["rule"], "tcp", port)]
        if ports:
            opened = ", ".join(f"tcp/{port}" for port in ports)
            message = f"{edge['target']} accepts {opened} from the Internet through {edge['cause']}"
            findings.append(new_finding("NET-01", edge["cause"], message, edge["target"]))
    return findings


def check_net_02(attack_graph, accepted):
    databases = sorted({edge["target"] for edge in internet_edges(attack_graph, "database", accepted)})
    return [new_finding("NET-02", database, f"{database} accepts connections from the Internet") for database in databases]


def check_path_01(paths):
  
    path_ids = {}  # data store -> ["AP-1", "AP-3", ...]
    for number, path in enumerate(paths, start=1):
        if len(path) >= 2:
            target = path[-1][1]  # the last node of the path
            if target not in path_ids:
                path_ids[target] = []
            path_ids[target].append(f"AP-{number}")
    findings = []
    for target, ids in sorted(path_ids.items()):
        message = f"{target} is reachable from the Internet through attack path(s) {', '.join(ids)}"
        findings.append(new_finding("PATH-01", target, message))
    return findings


def check_cfg_01(graph, warnings):
    findings = []
    for database in resources_of_type(graph, "aws_db_instance"):
        if is_unknown(graph, database, "storage_encrypted"):
            warnings.append(f"{database}: storage_encrypted is only known after apply; not checked")
        elif value(graph, database, "storage_encrypted") is not True:
            findings.append(new_finding("CFG-01", database, f"{database}: storage_encrypted is not true"))
    return findings


def check_cfg_02(graph, warnings):
    findings = []
    for policy in resources_of_type(graph, "aws_iam_role_policy") + resources_of_type(graph, "aws_iam_policy"):
        statements = policy_statements(graph, policy)
        if statements is None:
            warnings.append(f"{policy}: the policy document is only known after apply; not checked")
            continue
        wildcards = set()
        for statement in statements:
            if statement.get("Effect") == "Allow":
                for action in as_list(statement.get("Action")):
                    if action == "*" or action.endswith(":*"):
                        wildcards.add(action)
        if wildcards:
            findings.append(new_finding("CFG-02", policy, f"{policy} allows {', '.join(sorted(wildcards))}"))
    return findings


def raise_on_attack_paths(findings, attack_graph, paths):
   
    on_a_path = set()
    for path in paths:
        for source, target, key in path:
            on_a_path.update([source, target, attack_graph.edges[source, target, key]["cause"]])
    for finding in findings:
        if finding["rule"].startswith("CFG") and finding["resource"] in on_a_path:
            level = SEVERITIES.index(finding["severity"])
            finding["severity"] = SEVERITIES[min(level + 1, len(SEVERITIES) - 1)]
            finding["raised"] = True
    return findings


def run_rules(graph, attack_graph, paths, accepted, warnings):
    findings = (
        check_net_01(attack_graph, accepted)
        + check_net_02(attack_graph, accepted)
        + check_path_01(paths)
        + check_cfg_01(graph, warnings)
        + check_cfg_02(graph, warnings)
    )
    findings = raise_on_attack_paths(findings, attack_graph, paths)
    # Most severe first (critical = 3, so -3 comes first), then by rule and resource.
    findings.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), f["rule"], f["resource"], f["target"]))
    return findings
