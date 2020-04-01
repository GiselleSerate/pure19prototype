'''
Provide tests which force the system into bad states and expect proper errors.
'''

import pytest

from test.utils import container_tester
from src.structs import Host
from src.error import OpSysError



# Constants (which we can move into a config file later)
HOST = Host(hostname='127.0.0.1', port=1234, username='sshuser')



def test_unknown_os():
    '''
    Test that Kali container errors out gracefully and immediately
    '''
    expected = []
    pytest.raises(OpSysError, container_tester, name='unknown_os', op_sys='kali', host=HOST,
                  expected=expected, install_str='apt-get install -y')
