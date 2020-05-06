'''
What to run when you try to run the package as a program.
'''

import logging
import tempfile

from . import HOST, GeneralAnalyzer, SystemAnalyzer
from demo_utils import demo_pause

logging.info('Beginning analysis...')
with GeneralAnalyzer(host=HOST) as kowalski:
    kowalski.analyzer.get_packages()
    kowalski.analyzer.filter_packages()
    kowalski.analyzer.verify_packages()
    kowalski.analyzer.dockerize(tempfile.mkdtemp())
    kowalski.analyzer.analyze_files(allowlist=['/'],
                                    blocklist=['/var/tmp/*', '/var/log/*', '/tmp/*', '/proc/*',
                                               '/sys/*'])
    kowalski.analyzer.get_config_differences()
