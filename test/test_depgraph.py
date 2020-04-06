'''
Provides tests to ensure that the dependency code is analyzing correctly.
'''

from analyzer.utils import analyze_dependencies



def test_simple_graph():
    '''
    Test dependency analysis with a toy example.
    a <- b -> e
    |   ^
    v  /
     c <- d
    d is necessary; a, b, c also necessary because they're in a fully connected component.
    e is expendable.
    '''
    # Who does this node depend on?
    graph = {'a': {'c'},
             'b': {'a', 'e'},
             'c': {'b'},
             'd': {'c'},
             'e': {}}

    def get_dep(name):
        return graph[name]

    assert analyze_dependencies(graph, get_dep) == {'e'}


def test_disconnected_graph():
    '''
    Test dependency analysis with a completely disconnected graph; everything is necessary.
    '''
    graph = {}
    for node in range(ord('a'), ord('z')+1):
        graph[chr(node)] = {}

    def get_dep(name):
        return graph[name]

    assert analyze_dependencies(graph, get_dep) == set()


def test_connected_graph():
    '''
    Test dependency analysis with a completely connected graph; everything is still necessary.
    '''
    graph = {}
    for node in range(ord('a'), ord('z')+1):
        graph[chr(node)] = {chr(letter) for letter in range(ord('a'), ord('z')+1)}

    def get_dep(name):
        return graph[name]

    assert analyze_dependencies(graph, get_dep) == set()


def test_one_graph():
    '''
    Test dependency analysis with a few individual connections from x to some other packages.
    All dependencies of x can be skipped.
    '''
    graph = {}
    for node in range(ord('a'), ord('z')+1):
        graph[chr(node)] = {}

    # x depends on these packages
    graph['x'] = {'a', 'z', 'p', 't', 's'}

    def get_dep(name):
        return graph[name]

    assert analyze_dependencies(graph, get_dep) == graph['x']


def test_two_graph():
    '''
    Test dependency analysis with a few individual connections from x and y to some other packages.
    a and b are shared dependencies. Thus, we can skip both x's deps and y's deps, including a and
    b.
    '''
    graph = {}
    for node in range(ord('a'), ord('z')+1):
        graph[chr(node)] = {}

    graph['x'] = {'a', 'b', 'z', 'p', 't', 's'}
    graph['y'] = {'a', 'b', 'q', 'i', 'e', 'u'}

    def get_dep(name):
        return graph[name]

    assert analyze_dependencies(graph, get_dep) == (graph['x'] | graph['y'])


def test_two_dependent_graph():
    '''
    Test dependency analysis with a few individual connections from x and y to some other packages.
    a and b are shared dependencies. Also, there's a cycle x -> y -> q -> x. Thus, we can skip both
    x's deps and y's deps, including a and b, but not q or y.
    '''
    graph = {}
    for node in range(ord('a'), ord('z')+1):
        graph[chr(node)] = {}

    graph['x'] = {'a', 'b', 'z', 'p', 't', 's', 'y'}
    graph['y'] = {'a', 'b', 'q', 'i', 'e', 'u'}
    graph['q'] = {'x'}

    def get_dep(name):
        return graph[name]

    assert analyze_dependencies(graph, get_dep) == ((graph['x'] | graph['y']) - {'q', 'y'})
