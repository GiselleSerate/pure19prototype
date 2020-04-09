import logging
import tempfile

from . import HOST, GeneralAnalyzer, SystemAnalyzer



logging.info('Beginning analysis...')
with GeneralAnalyzer(host=HOST) as kowalski:
    kowalski.analyzer.get_packages()
    kowalski.analyzer.filter_packages()
    for md in (SystemAnalyzer.Mode.dry, SystemAnalyzer.Mode.unversion,
               SystemAnalyzer.Mode.delete):
        if kowalski.analyzer.verify_packages(mode=md):
            break
    kowalski.analyzer.dockerize(tempfile.mkdtemp())
    kowalski.analyzer.analyze_files(['/bin/', '/etc/', '/lib/', '/opt/', '/sbin/', '/usr/'], ['/var/tmp/'])
    kowalski.analyzer.get_config_differences()
