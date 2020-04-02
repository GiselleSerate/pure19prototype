'''
Provide tests which force the system into bad states and expect proper errors.
'''

import pytest

from test.utils import container_tester

from .context import analyzer



# Constants (which we can move into a config file later)
HOST = analyzer.Host(hostname='127.0.0.1', port=1234, username='sshuser')


# # TODO: This only passes inconsistently because of SSH problems. I don't know why.
# def test_unknown_os():
#     '''
#     Test that Kali container errors out gracefully and immediately
#     '''
#     expected = []
#     pytest.raises(analyzer.OpSysError, container_tester, name='unknown_os', op_sys='kali',
#                   host=HOST, expected=expected, install_str='apt-get install -y')
