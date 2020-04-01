'''
Provides tests to verify that a container can be converted to another container.

container_tester is a helper function with the actual function of the tests.
test_*_container are the actual tests, which specify behaviors for the container_tester function.
'''

from src.structs import Host
from test.utils import container_tester



# Constants (which we can move into a config file later)
HOST = Host(hostname='127.0.0.1', port=1234, username='sshuser')



# # TODO: Something's weird with Ubuntu right now. I think libsqlite-0 was a default package that now
# # cannot be installed for some reason. This is bizarre.
# def test_basic_ubuntu_container():
#     '''
#     Test that basic sshable ubuntu container can be put through the prototype
#     '''
#     expected = ['openssh-server']
#     container_tester(name='basic_ubuntu', operating_sys='ubuntu', port=PORT, username=USERNAME,
#                      expected=expected, install_str='apt-get install -y')


# def test_assorted_ubuntu_container():
#     '''
#     Test that ubuntu container with a selection of assorted packages can be put through the
#     prototype
#     '''
#     expected = ['openssh-server', 'rolldice', 'ghc', 'git']
#     container_tester(name='assorted_ubuntu', operating_sys='ubuntu', port=PORT, username=USERNAME,
#                      expected=expected, install_str='apt-get install -y')


def test_basic_centos_container():
    '''
    Test that basic sshable centos container can be put through the prototype
    '''
    expected = ['openssh-server', 'openssh-clients']
    container_tester(name='basic_centos', operating_sys='centos', host=HOST, expected=expected,
                     install_str='yum install -y')


def test_assorted_centos_container():
    '''
    Test that centos container with a selection of assorted packages can be put through the
    prototype
    '''
    expected = ['openssh-server', 'openssh-clients', 'gdb', 'valgrind', 'wireshark']
    container_tester(name='assorted_centos', operating_sys='centos', host=HOST, expected=expected,
                     install_str='yum install -y')
