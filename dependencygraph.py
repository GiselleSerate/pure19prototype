__author__ = 'elubin'
# import logging
import networkx as nx


def filter_non_dependencies(nodes, get_deps_func):
    node_set = set(nodes)
    G = nx.DiGraph()
    G.add_nodes_from(nodes)

    # process the edges based on the dependency function
    for n in G:
        deps = get_deps_func(n)
        # logging.info('%s depends on %s' % (n, deps))
        for d in deps:
            if d in G:
                G.add_edge(n, d)



    # now filter the nodes and return them
    filtered_pkgs = {node for node, in_degree in G.in_degree() if in_degree == 0}

    # now find any strongly connected components with size greater than 1
    # these will all have in degree > 0, but should still be included
    glist = [g for g in [G.subgraph(c) for c in nx.strongly_connected_components(G)] if g.number_of_nodes() > 1]

    for g in glist:
        # only counts if it was the original list
        nodes = [n for n in g.nodes() if n in node_set]
        if len(nodes) > 0:
            # logging.debug('Strongly connected component: %s' % repr(nodes))
            print('Strongly connected component: %s' % repr(nodes))
            for n in nodes:
                filtered_pkgs.add(n)

    return filtered_pkgs
