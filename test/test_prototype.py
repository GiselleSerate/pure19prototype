'''
Provides local tests for Centos and Ubuntu. Don't run these in CI.
TODO: Please update the tests in this file.
'''
import configparser
import os

from analyzer.general import GeneralAnalyzer
from analyzer.utils import Host
from analyzer.system.system import SystemAnalyzer


# Read in constants
CFG = configparser.ConfigParser()
CFG.read(os.path.join('test', 'config.ini'))

C_HOSTNAME = CFG.get('CENTOS_VM', 'HOSTNAME')
C_PORT = CFG.getint('CENTOS_VM', 'PORT')
C_USERNAME = CFG.get('CENTOS_VM', 'USERNAME')
U_HOSTNAME = CFG.get('UBUNTU_VM', 'HOSTNAME')
U_PORT = CFG.getint('UBUNTU_VM', 'PORT')
U_USERNAME = CFG.get('UBUNTU_VM', 'USERNAME')


def test_local_basic_build_centos():
    '''
    Test that all packages from our CentOS system can be installed
    (first try with the specified version for all; failing that, try latest).
    '''
    host = Host(hostname=C_HOSTNAME, port=C_PORT, username=C_USERNAME)
    with GeneralAnalyzer(host=host) as kowalski:
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
    host = Host(hostname=U_HOSTNAME, port=U_PORT, username=U_USERNAME)
    with GeneralAnalyzer(host=host) as kowalski:
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
