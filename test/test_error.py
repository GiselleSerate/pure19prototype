'''
Provide tests which force the system into bad states and expect proper errors.
'''

import configparser
import os
import pytest

from test.utils import container_tester

from analyzer.utils import Host, OpSysError

# Read in constants
CFG = configparser.ConfigParser()
CFG.read(os.path.join('test', 'config.ini'))

HOSTNAME = CFG['CONTAINER']['HOSTNAME']
PORT = CFG.getint('CONTAINER', 'PORT')
USERNAME = CFG['CONTAINER']['USERNAME']

HOST = Host(hostname=HOSTNAME, port=PORT, username=USERNAME)


# # TODO: This only passes inconsistently because of SSH problems. I don't know why;
# # maybe kali is inconsistent, or slow, or something.
# def test_unknown_os():
#     '''
#     Test that Kali container errors out gracefully and immediately
#     '''
#     expected = []
#     pytest.raises(OpSysError, container_tester, name='unknown_os', op_sys='kali',
#                   host=HOST, expected=expected, install_str='apt-get install -y')
