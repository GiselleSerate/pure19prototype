'''
Provides tests to verify that a container can be converted to another container. Uses Centos 7 and
Ubuntu 20.04.

test_*_container specify behaviors for the container_tester function. Basic means try to convert a
bare-bones container, and assorted means try to install a few arbitrary packages and make sure they
exist on the container after conversion.
'''

import configparser
import os

from test.utils import container_tester
from analyzer.utils import Host


# Read in constants
CFG = configparser.ConfigParser()
CFG.read(os.path.join('test', 'config.ini'))

HOSTNAME = CFG.get('CONTAINER', 'HOSTNAME')
PORT = CFG.getint('CONTAINER', 'PORT')
USERNAME = CFG.get('CONTAINER', 'USERNAME')

HOST = Host(hostname=HOSTNAME, port=PORT, username=USERNAME)



def test_basic_ubuntu_container():
    '''
    Test that basic sshable ubuntu container can be put through the prototype
    '''
    expected = ['openssh-server']
    container_tester(name='basic_ubuntu', op_sys='ubuntu', host=HOST, expected=expected,
                     install_str='apt-get install -y')


def test_assorted_ubuntu_container():
    '''
    Test that ubuntu container with a selection of assorted packages can be put through the
    prototype
    '''
    expected = ['openssh-server', 'rolldice', 'ghc', 'git']
    container_tester(name='assorted_ubuntu', op_sys='ubuntu', host=HOST, expected=expected,
                     install_str='apt-get install -y')


def test_basic_centos_container():
    '''
    Test that basic sshable centos container can be put through the prototype
    '''
    expected = ['openssh-server', 'openssh-clients']
    container_tester(name='basic_centos', op_sys='centos', host=HOST, expected=expected,
                     install_str='yum install -y')


def test_assorted_centos_container():
    '''
    Test that centos container with a selection of assorted packages can be put through the
    prototype
    '''
    expected = ['openssh-server', 'openssh-clients', 'gdb', 'valgrind', 'wireshark']
    container_tester(name='assorted_centos', op_sys='centos', host=HOST, expected=expected,
                     install_str='yum install -y')
