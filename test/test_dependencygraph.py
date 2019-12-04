from src.dependencygraph import filter_non_dependencies

def test_basic_dependency():
    '''
    Ensure we delete strictly linear dependencies
    '''
    packages = {'pizza', 'joe', 'docker', 'squirrel'}
    dependencies = {'pizza': {},
                    'joe': {},
                    'docker': {'joe'},
                    'squirrel': {'docker'}}
    result = filter_non_dependencies(packages, lambda pkg: dependencies[pkg])
    # Don't need 'joe' or 'docker' since another package needs both
    assert result == {'pizza', 'squirrel'}

def test_circular_dependency():
    '''
    Make sure we leave in circular dependencies
    '''
    packages = {'cauliflower', 'broccoli', 'beans', 'corn', 'spinach', 'potatoes'}
    dependencies = {'cauliflower': {'broccoli'},
                    'broccoli': {'cauliflower'},
                    'beans': {'corn'},
                    'corn': {'spinach'},
                    'spinach': {'potatoes'},
                    'potatoes': {'beans'}}
    result = filter_non_dependencies(packages, lambda pkg: dependencies[pkg])
    # cauliflower and broccoli have a circular dependency, so keep both;
    # beans/corn/spinach/potatoes have a not initially strongly connected but still circular dependency, so keep all
    assert result == {'cauliflower', 'broccoli', 'beans', 'corn', 'spinach', 'potatoes'}
