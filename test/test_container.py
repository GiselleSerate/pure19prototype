'''
Provides tests to verify that a container can be converted to another container.

container_tester is a helper function with the actual function of the tests.
test_*_container are the actual tests, which specify behaviors for the container_tester function.
'''

import logging
import os
import re
import tempfile

import docker

from src.prototype import GeneralAnalyzer, SystemAnalyzer

# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
USERNAME = 'sshuser'
PORT = 1234



def container_tester(name, operating_sys, port, username, expected, install_str):
    '''
    Test that specified container can be put through the prototype
    operating_sys -- name of folder in containers where the original Dockerfile is
    port -- port on the localhost side to SSH into the system through
    username -- user to ssh into system with
    expected -- packages expected to be in the resulting Docker container
    install_str -- the string (no trailing space!) to list packages to install
    '''

    # Set up sshable container
    logging.info(f"Setting up base {name} container . . .")
    docker_client = docker.from_env()
    base_image, _ = docker_client.images.build(tag=f'test_{name}_base_img',
                                               path=os.path.join(os.getcwd(),
                                                                 "containers",
                                                                 operating_sys))

    try:
        base_container = docker_client.containers.run(base_image.id, detach=True, ports={22: port})

        # Install expected packages
        for pkg in expected:
            ex_code, _ = base_container.exec_run(f"{install_str} {pkg}")
            assert ex_code == 0

        # Analyze container
        logging.info(f"Analyzing {name} container . . .")
        with GeneralAnalyzer(hostname=HOSTNAME, port=port, username=username, auto_add=True) as gen:
            gen.analyzer.get_packages()
            logging.info(gen.analyzer.all_packages)
            gen.analyzer.filter_packages()
            # All packages should be able to be installed (i.e. can find all packages with proper
            # versions).
            all_correct = gen.analyzer.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert all_correct

            # Create the Dockerfile
            tempdir = tempfile.mkdtemp()
            gen.analyzer.dockerize(tempdir)

            # Make a container from it
            logging.info(f"Verifying {name} container . . .")
            verify_image, _ = docker_client.images.build(tag=f'test_{name}_verify_img',
                                                         path=tempdir)
            verify_container = docker_client.containers.run(verify_image.id, detach=True,
                                                            command=gen.analyzer.LIST_INSTALLED)
            verify_container.wait()
            for pkg in expected:
                logging.info(f"Checking package {pkg} . . .")
                assert re.search(pkg, verify_container.logs().decode())

    finally:
        # Clean up after yourself
        base_container.remove(force=True)
        verify_container.remove(force=True)
        logging.info(f"Cleaned up {operating_sys} successfully.")

# TODO: Something's weird with Ubuntu right now. I think libsqlite-0 was a default package that now
# cannot be installed for some reason. This is bizarre.
def test_basic_ubuntu_container():
    '''
    Test that basic sshable ubuntu container can be put through the prototype
    '''
    expected = ['openssh-server']
    container_tester(name='basic_ubuntu', operating_sys='ubuntu', port=PORT, username=USERNAME,
                     expected=expected, install_str='apt-get install -y')


def test_assorted_ubuntu_container():
    '''
    Test that ubuntu container with a selection of assorted packages can be put through the
    prototype
    '''
    expected = ['openssh-server', 'rolldice', 'ghc', 'git']
    container_tester(name='assorted_ubuntu', operating_sys='ubuntu', port=PORT, username=USERNAME,
                     expected=expected, install_str='apt-get install -y')


def test_basic_centos_container():
    '''
    Test that basic sshable centos container can be put through the prototype
    '''
    expected = ['openssh-server', 'openssh-clients']
    container_tester(name='basic_centos', operating_sys='centos', port=PORT, username=USERNAME,
                     expected=expected, install_str='yum install -y')


def test_assorted_centos_container():
    '''
    Test that centos container with a selection of assorted packages can be put through the
    prototype
    '''
    expected = ['openssh-server', 'openssh-clients', 'gdb', 'valgrind', 'wireshark']
    container_tester(name='assorted_centos', operating_sys='centos', port=PORT, username=USERNAME,
                     expected=expected, install_str='yum install -y')
