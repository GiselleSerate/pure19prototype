# NOTE: this test is broken because of imports, or something. sorry.

import logging

# from src.prototype import SystemAnalyzer



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
PORT = 2222
USERNAME = 'root'
LOG_LEVEL = 'INFO'



# def test_basic_build():
#     with SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
#         kowalski.get_os()
#         kowalski.get_packages()
#         kowalski.filter_packages()
#         kowalski.get_ports()
#         kowalski.get_procs()
#         kowalski.dockerize()
#         try:
#             kowalski.docker_client.images.build(path=kowalski.dir)
#         except Exception as e:
#             logging.error("Failed at building image")
#             logging.error(e)
#             raise e