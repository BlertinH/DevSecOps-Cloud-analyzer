import networkx as nx


def build_infrastructure_graph(resources, references):
    """Create the graph from the output of plan.get_resources and plan.get_references."""
    graph = nx.MultiDiGraph()
    for address, resource in resources.items():
        graph.add_node(address, type=resource["type"], values=resource["values"], unknown=resource["unknown"])
    for source, attribute, target in references:
        graph.add_edge(source, target, key=attribute)
    return graph


def resources_of_type(graph, resource_type):
    """All resources of one type, sorted by address."""
    return sorted(node for node, data in graph.nodes(data=True) if data["type"] == resource_type)


def referenced(graph, node, attribute, resource_type=None):
    """Resources that `node` refers to through `attribute` (follow edges forward).

    referenced(graph, "aws_instance.web", "subnet_id")  ->  ["aws_subnet.public_a"]
    """
    found = []
    for _, target, key in graph.out_edges(node, keys=True):
        if key == attribute and (resource_type is None or graph.nodes[target]["type"] == resource_type):
            found.append(target)
    return sorted(found)


def referenced_by(graph, node, attribute, resource_type=None):
    """Resources that refer to `node` through `attribute` (follow edges backward).

    referenced_by(graph, "aws_subnet.public_a", "subnet_id", "aws_instance")  ->  ["aws_instance.web"]
    """
    found = []
    for source, _, key in graph.in_edges(node, keys=True):
        if key == attribute and (resource_type is None or graph.nodes[source]["type"] == resource_type):
            found.append(source)
    return sorted(found)


def value(graph, node, name):
    """One setting of a resource, or None if it is not set (or not known yet)."""
    return graph.nodes[node]["values"].get(name)


def is_unknown(graph, node, name):
    """True if Terraform will only know this setting after apply."""
    return name in graph.nodes[node]["unknown"]