'''
Example script to show how you could include the analyzer and use it in your own scripts.
'''

import logging
import tempfile

from analyzer import HOST, GeneralAnalyzer, SystemAnalyzer



logging.info('Beginning analysis...')
with GeneralAnalyzer(host=HOST) as kowalski:
    kowalski.analyzer.get_packages()
    kowalski.analyzer.filter_packages()
    for md in (SystemAnalyzer.Mode.unversion,
               SystemAnalyzer.Mode.delete):
        if kowalski.analyzer.verify_packages(mode=md):
            break
    kowalski.analyzer.dockerize(tempfile.mkdtemp())
    kowalski.analyzer.analyze_files(allowlist=['/bin/', '/etc/', '/lib/', '/opt/', '/sbin/',
                                               '/usr/', '/var/'],
                                    blocklist=['/var/tmp/*', '/var/log/*'])
    kowalski.analyzer.get_config_differences()
