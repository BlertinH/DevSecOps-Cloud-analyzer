
import networkx as nx

from .graph import resources_of_type
from .iam import find_iam_edges
from .network import INTERNET, find_network_edges

NODE_KINDS = {"aws_instance": "compute", "aws_db_instance": "database", "aws_s3_bucket": "bucket"}
DATA_STORES = ("database", "bucket")


def build_attack_graph(graph, warnings):
    """Create the attack graph from the infrastructure graph."""
    attack_graph = nx.MultiDiGraph()
    attack_graph.add_node(INTERNET, kind="internet")
    for resource_type, kind in NODE_KINDS.items():
        for address in resources_of_type(graph, resource_type):
            attack_graph.add_node(address, kind=kind)
    for edge in find_network_edges(graph, warnings) + find_iam_edges(graph, warnings):
        attack_graph.add_edge(edge["source"], edge["target"], **edge)
    return attack_graph


def is_accepted(edge, accepted):

    rule = edge.get("rule")
    if edge["source"] != INTERNET or rule is None or rule["protocol"] != "tcp":
        return False
    return rule["from_port"] == rule["to_port"] and (edge["target"], rule["from_port"]) in accepted


def describe_path(attack_graph, path):
    text = path[0][0]
    for source, target, key in path:
        text += f" -[{attack_graph.edges[source, target, key]['label']}]-> {target}"
    return text


def attacker_graph(attack_graph, accepted):
    graph = attack_graph.copy()
    for source, target, key, edge in attack_graph.edges(keys=True, data=True):
        if is_accepted(edge, accepted):
            graph.remove_edge(source, target, key)
    return graph


def shortest_attack_path(graph, target):
    nodes = nx.shortest_path(graph, INTERNET, target)
    path = []
    for source, next_node in zip(nodes, nodes[1:]):
        first_key = list(graph[source][next_node])[0]
        path.append((source, next_node, first_key))
    return path


def find_attack_paths(attack_graph, accepted, max_depth=8):
 
    graph = attacker_graph(attack_graph, accepted)

    hops = nx.single_source_shortest_path_length(graph, INTERNET)
    del hops[INTERNET]

    targets = [node for node in hops if graph.nodes[node]["kind"] in DATA_STORES]
    if not targets:
        return hops, []

    paths = list(nx.all_simple_edge_paths(graph, INTERNET, targets, cutoff=max_depth))

    reached = [path[-1][1] for path in paths]
    for target in targets:
        if target not in reached:
            paths.append(shortest_attack_path(graph, target))

    paths.sort(key=lambda path: (path[-1][1], describe_path(attack_graph, path)))
    return hops, paths
