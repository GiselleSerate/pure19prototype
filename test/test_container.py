import logging
import os
import re
import tempfile

import docker
from paramiko import SSHClient
from paramiko.ssh_exception import NoValidConnectionsError

from src.prototype import GeneralAnalyzer, SystemAnalyzer

# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
USERNAME = 'sshuser'
PORT = 1022

# CircleCI constants
HOSTNAME = 'remote-docker'
USERNAME = 'sshuser'
PORT = 1022



def container_tester(operating_sys, port, username, expected):
    '''
    Test that specified container can be put through the prototype
    operating_sys -- name of folder in containers where the original Dockerfile is
    port -- port on the localhost side to SSH into the system through
    username -- user to ssh into system with
    expected -- packages expected to be in the resulting Docker container
    '''

    # Set up sshable container
    logging.info(f"Setting up base {operating_sys} container . . .")
    docker_client = docker.from_env()
    base_image, _ = docker_client.images.build(tag=f'test_basic_{operating_sys}_base_img', path=os.path.join(os.getcwd(), "containers", operating_sys))

    try:
        base_container = docker_client.containers.run(base_image.id, detach=True, ports={22: port})

        # Analyze container
        logging.info(f"Analyzing {operating_sys} container . . .")
        with GeneralAnalyzer(hostname=HOSTNAME, port=port, username=username, auto_add=True) as kowalski:
            kowalski.analyzer.get_packages()
            kowalski.analyzer.filter_packages()
            # All packages should be able to be installed (i.e. can find all packages with proper versions).
            all_correct = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert all_correct

            # Create the Dockerfile
            tempdir = tempfile.mkdtemp()
            kowalski.analyzer.dockerize(tempdir)

            # Make a container from it
            logging.info(f"Verifying {operating_sys} container . . .")
            verify_image, _ = docker_client.images.build(tag=f'test_basic_{operating_sys}_verify_img', path=tempdir)
            verify_container = docker_client.containers.run(verify_image.id, detach=True, command=kowalski.analyzer.LIST_INSTALLED)
            verify_container.wait()
            for pkg in expected:
                logging.info(f"Checking package {pkg} . . .")
                assert re.search(pkg, verify_container.logs().decode())

    finally:
        # Clean up after yourself
        base_container.remove(force=True)
        verify_container.remove(force=True)
        logging.info(f"Cleaned up {operating_sys} successfully.")


def test_basic_ubuntu_container():
    '''
    Test that basic sshable ubuntu container can be put through the prototype
    '''
    expected = ['openssh-server']
    container_tester(operating_sys='ubuntu', port=PORT, username=USERNAME, expected=expected)


def test_basic_centos_container():
    '''
    Test that basic sshable centos container can be put through the prototype
    '''
    expected = ['openssh-server', 'openssh-clients']
    container_tester(operating_sys='centos', port=PORT, username=USERNAME, expected=expected)
