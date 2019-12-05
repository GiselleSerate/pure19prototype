# NOTE: this test is broken because of imports, or something. sorry.

import logging

from src.prototype import SystemAnalyzer



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
PORT = 2222
USERNAME = 'root'
LOG_LEVEL = 'INFO'



def test_integration_basic_build():
    with SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.get_os()
        kowalski.get_packages()
        kowalski.dockerize()

        # Now that we have a Dockerfile, build and check the packages are there
        image, _ = kowalski.docker_client.images.build(tag='pytest', path=kowalski.dir)
        container = kowalski.docker_client.containers.run(image=image.id, command="yum list installed", detach=True)
        # Block until the command's done, then check its output.
        container.wait()
        output = container.logs()
        output = output.decode()
        logging.error(output)

        there = 0
        total = 0
        missing = []
        for package in kowalski.packages.keys():
            if package in output:
                there += 1
            else:
                missing.append(package)
            total += 1

        # Fully aware this isn't how you should be writing a test, thanks
        if there < total:
            logging.error(f"{there}/{total}")
            logging.error(f"The following packages were missing: {missing}")
        assert there == total