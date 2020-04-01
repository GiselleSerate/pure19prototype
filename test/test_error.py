'''
Provide tests which force the system into bad states and expect proper errors.
'''

from src.structs import Host
from test.utils import container_tester



# Constants (which we can move into a config file later)
HOST = Host(hostname='127.0.0.1', port=1234, username='sshuser')



def test_unknown_os():
    '''
    Test that Kali container errors out gracefully and immediately
    '''
    expected = ['openssh-server', 'openssh-clients']
    container_tester(name='basic_centos', operating_sys='centos', host=HOST, expected=expected,
                     install_str='yum install -y')
