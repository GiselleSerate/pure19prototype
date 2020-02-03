import logging
import tempfile

from src.prototype import GeneralAnalyzer, SystemAnalyzer

# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'

def test_integration_basic_build_centos():
    '''
    Test that all packages from our CentOS system can be installed
    (first try with the specified version for all; failing that, try latest).
    '''
    PORT = 2222
    USERNAME = 'root'
    with GeneralAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.analyzer.get_packages()
        kowalski.analyzer.filter_packages()
        no_wrong_versions = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.unversion)
        if no_wrong_versions:
            # Wish I had a meaningful assert for you, but if you hit this case you just pass the test.
            assert no_wrong_versions
        else:
            # Some wrong versions. Try to compensate.
            no_wrong_packages = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert no_wrong_packages

def test_integration_basic_build_ubuntu():
    '''
    Test that all packages from our ubuntu system can be installed
    (first try with the specified version for all; failing that, try latest).
    '''
    PORT = 3333
    USERNAME = 'squirrel'
    with GeneralAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.analyzer.get_packages()
        kowalski.analyzer.filter_packages()
        no_wrong_versions = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.unversion)
        if no_wrong_versions:
            # Wish I had a meaningful assert for you, but if you hit this case you just pass the test.
            assert no_wrong_versions
        else:
            # Some wrong versions. Try to compensate.
            no_wrong_packages = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert no_wrong_packages



