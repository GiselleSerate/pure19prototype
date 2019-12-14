import logging
import tempfile

from src.prototype import SystemAnalyzer



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
PORT = 2222
USERNAME = 'root'
LOG_LEVEL = 'INFO'



def test_integration_basic_build():
    '''
    Test that all packages from our CentOS system can be installed
    (first try with the specified version for all; failing that, try latest).
    '''
    with SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.get_os()
        kowalski.get_packages()
        kowalski.filter_packages()
        no_wrong_versions = kowalski.verify_packages(mode=SystemAnalyzer.Mode.unversion)
        if no_wrong_versions:
            # Wish I had a meaningful assert for you, but if you hit this case you just pass the test.
            assert no_wrong_versions
        else:
            # Some wrong versions. Try to compensate.
            no_wrong_packages = kowalski.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert no_wrong_packages
