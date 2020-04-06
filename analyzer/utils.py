'''
Provides structures, custom errors, and global helper functions for the rest of the code.
'''

import logging

from typing import NamedTuple
import networkx as nx



class Host(NamedTuple):
    '''Use Host to keep info about a system'''
    hostname: str
    port: int
    username: str


class DockerDaemonError(Exception):
    '''Cannot reach the Docker daemon.'''


class OrigSysError(ValueError):
    '''The given system cannot be replicated.'''


class OrigSysConnError(OrigSysError):
    '''We can't connect to the system you want to replicate.'''


class OpSysError(OrigSysError):
    '''Unsupported operating system.'''


class PermissionsError(OrigSysError):
    '''Insufficient permissions on target system.'''
    # f"Insufficient permissions on the target system for {user}."


def group_strings(indexable, char_count=100000):
    '''
    Generator to group the indexable's items into space-separated strings which are about char_count
    characters long.
    '''
    curr_string = ""
    for item in indexable:
        if len(curr_string) > char_count:
            yield curr_string
            curr_string = ""
        curr_string += item + " "
    if curr_string:
        yield curr_string


def analyze_dependencies(nodes, get_deps_func):
    '''
    Returns packages that can implicitly install due to dependencies and therefore may be removed
    from the install list.
    nodes -- the list of nodes to filter
    get_deps_func -- the function to call to figure out package dependencies.
    '''
    node_set = set(nodes)
    full_g = nx.DiGraph()
    full_g.add_nodes_from(nodes)

    # Process the edges based on the dependency function
    for node in full_g:
        deps = get_deps_func(node)
        for dep in deps:
            if dep in full_g:
                full_g.add_edge(node, dep)

    # Filter the nodes and return them
    filtered_pkgs = {node for node, in_degree in full_g.in_degree() if in_degree == 0}

    # Find any strongly connected components with size greater than 1
    # These will all have in degree > 0, but should still be included
    g_list = [sub_g for sub_g in
              [full_g.subgraph(comp) for comp in nx.strongly_connected_components(full_g)]
              if sub_g.number_of_nodes() > 1]

    for sub_g in g_list:
        # Only counts if it was the original list
        nodes = [node for node in sub_g.nodes() if node in node_set]
        if len(nodes) > 0:
            logging.info(f"Strongly connected component: {repr(nodes)}")
            for node in nodes:
                filtered_pkgs.add(node)

    return node_set - filtered_pkgs
