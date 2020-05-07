'''
Example script to show how you could include the analyzer and use it in your own scripts.
'''

import logging
import tempfile

from analyzer import HOST, GeneralAnalyzer, SystemAnalyzer



logging.info('Beginning analysis...')
# HOST reads from the config.ini file. You can set it yourself manually and instead pass:
# Host(hostname=HOSTNAME, port=PORT, username=USERNAME)
with GeneralAnalyzer(host=HOST) as kowalski:
    kowalski.analyzer.get_packages()
    kowalski.analyzer.filter_packages(strict_versioning=False)
    kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.unversion)
    kowalski.analyzer.dockerize(tempfile.mkdtemp())
    kowalski.analyzer.analyze_files(allowlist=['/'],
                                    blocklist=['/var/tmp/*', '/var/log/*', '/tmp/*', '/proc/*',
                                               '/sys/*'])
    kowalski.analyzer.get_config_differences()
