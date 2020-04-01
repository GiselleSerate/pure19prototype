'''
Provides local tests for Centos and Ubuntu. Don't run these in CI.
'''

from src.prototype import GeneralAnalyzer, SystemAnalyzer



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'



def test_local_basic_build_centos():
    '''
    Test that all packages from our CentOS system can be installed
    (first try with the specified version for all; failing that, try latest).
    '''
    port = 2222
    username = 'root'
    with GeneralAnalyzer(hostname=HOSTNAME, port=port, username=username) as kowalski:
        kowalski.analyzer.get_packages()
        kowalski.analyzer.filter_packages()
        no_wrong_versions = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.unversion)
        if no_wrong_versions:
            # Wish I had a meaningful assert for you, but if you hit this case you just pass.
            assert no_wrong_versions
        else:
            # Some wrong versions. Try to compensate.
            no_wrong_packages = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert no_wrong_packages

def test_local_basic_build_ubuntu():
    '''
    Test that all packages from our ubuntu system can be installed
    (first try with the specified version for all; failing that, try latest).
    '''
    port = 3333
    username = 'squirrel'
    with GeneralAnalyzer(hostname=HOSTNAME, port=port, username=username) as kowalski:
        kowalski.analyzer.get_packages()
        kowalski.analyzer.filter_packages()
        no_wrong_versions = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.unversion)
        if no_wrong_versions:
            # Wish I had a meaningful assert for you, but if you hit this case you just pass.
            assert no_wrong_versions
        else:
            # Some wrong versions. Try to compensate.
            no_wrong_packages = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert no_wrong_packages
