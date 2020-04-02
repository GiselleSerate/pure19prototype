'''
Provide utils for running tests.

container_tester tries to construct a container out of another container.
'''

import logging
import os
import re
import tempfile

import docker

from analyzer.general import GeneralAnalyzer
from analyzer.system.system import SystemAnalyzer



def container_tester(name, op_sys, host, expected, install_str):
    '''
    Test that specified container can be put through the prototype
    op_sys -- name of folder in containers where the original Dockerfile is
    host -- a Host structure for the system under analysis
    expected -- packages expected to be in the resulting Docker container
    install_str -- the string (no trailing space!) to list packages to install
    '''

    # Set up sshable container
    logging.info(f"Setting up base {name} container . . .")
    docker_client = docker.from_env()
    base_image, _ = docker_client.images.build(tag=f'test_{name}_base_img',
                                               path=os.path.join(os.getcwd(), "containers", op_sys))

    try:
        base_container = docker_client.containers.run(base_image.id, detach=True,
                                                      ports={22: host.port})

        # Install expected packages
        for pkg in expected:
            ex_code, _ = base_container.exec_run(f"{install_str} {pkg}")
            assert ex_code == 0

        # Analyze container
        logging.info(f"Analyzing {name} container . . .")
        with GeneralAnalyzer(host=host, auto_add=True) as gen:
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
        try:
            base_container.remove(force=True)
            verify_container.remove(force=True)
        except UnboundLocalError:
            # This just means one or more of these containers didn't get created; it's fine.
            logging.warning("Cleanup didn't need to remove both containers.")
        logging.info(f"Cleaned up {op_sys} successfully.")
