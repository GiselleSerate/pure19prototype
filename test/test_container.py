import logging
import os
import re
import tempfile

import docker

from src.prototype import GeneralAnalyzer, SystemAnalyzer

# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'


def test_basic_ubuntu_container():
    '''
    Test that basic sshable ubuntu container can be put through the prototype
    '''
    PORT = 1022
    USERNAME = 'sshuser'
    expected = ['openssh-server']

    # Set up sshable ubuntu container
    logging.info("Setting up base container . . .")
    docker_client = docker.from_env()
    base_image, _ = docker_client.images.build(tag='test_basic_ubuntu_base_img', path=os.path.join(os.getcwd(), "containers/ubuntu"))

    try:
        base_container = docker_client.containers.run(base_image.id, detach=True, ports={PORT: 22})

        # Analyze container
        logging.info("Analyzing container . . .")
        with GeneralAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
            kowalski.analyzer.get_packages()
            kowalski.analyzer.filter_packages()
            # All packages should be able to be installed (i.e. can find all packages with proper versions).
            all_correct = kowalski.analyzer.verify_packages(mode=SystemAnalyzer.Mode.dry)
            assert all_correct

            # Create the Dockerfile
            tempdir = tempfile.mkdtemp()
            kowalski.analyzer.dockerize(tempdir)

            # Make a container from it
            logging.info("Verifying container . . .")
            verify_image, _ = docker_client.images.build(tag='test_basic_ubuntu_verify_img', path=tempdir)
            verify_container = docker_client.containers.run(base_image.id, detach=True, command=kowalski.analyzer.LIST_INSTALLED)
            verify_container.wait()
            for pkg in expected:
                logging.info(f"Checking package {pkg} . . .")
                assert re.search(pkg, verify_container.logs().decode())

    finally:
        # Clean up after yourself
        base_container.remove(force=True)
        verify_container.remove(force=True)
        logging.info("Cleaned up successfully.")


