# NOTE: this test is broken because of imports, or something. sorry.

import logging
import tempfile

from src.prototype import SystemAnalyzer



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
PORT = 2222
USERNAME = 'root'
LOG_LEVEL = 'INFO'



def test_integration_basic_build():
    with SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.get_os()
        kowalski.get_packages()
        no_wrong_versions = kowalski.verify_packages(mode=SystemAnalyzer.Mode.unversion)
        no_wrong_packages = kowalski.verify_packages(mode=SystemAnalyzer.Mode.delete)
        no_probs_post_fix = kowalski.verify_packages(mode=SystemAnalyzer.Mode.dry)
        assert no_wrong_packages or no_wrong_versions or no_probs_post_fix