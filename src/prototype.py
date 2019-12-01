import logging
from logging.config import dictConfig
import os
import re
import tempfile

from paramiko import SSHClient

from dependencygraph import filter_non_dependencies



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
PORT = 2222
USERNAME = 'root'
LOG_LEVEL = 'INFO'


# Configure logging
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://sys.stdout',
        'formatter': 'default'
    }},
    'root': {
        'level': LOG_LEVEL,
        'handlers': ['wsgi']
    }
})



class SystemAnalyzer:
    def __init__(self, hostname=HOSTNAME, port=PORT, username=USERNAME):
        self.client = SSHClient()
        # Explore ~/.ssh/ for keys
        self.client.load_system_host_keys()
        # Establish SSH connection
        self.client.connect(hostname, port=port, username=username)

        self.operating_sys = None
        self.version = None
        self.packages = set()
        self.filtered_packages = set()

        self.dir = tempfile.mkdtemp()

    def __del__(self):
        # Make sure you kill the connection when you're done
        self.client.close()

    def get_os(self):
        logging.info("Getting operating system and version...")
        stdin, stdout, stderr = self.client.exec_command('cat /etc/os-release')
        # Extract operating system and version
        for line in stdout:
            if re.match(r'ID=', line):
                operating_sys = line.split('=')[1].split('"')[1]
            elif re.match(r'VERSION_ID=', line):
                version = line.split('=')[1].split('"')[1]
        self.operating_sys = operating_sys
        self.version = version
        logging.debug(f"FROM {operating_sys}:{version}")

    def get_packages(self):
        logging.info("Getting packages...")
        while self.operating_sys == None:
            logging.info("No operating system yet.")
            self.get_os()
        if self.operating_sys == 'centos':
            stdin, stdout, stderr = self.client.exec_command("rpm -qa --queryformat '%{NAME}\n'")
            self.packages = {line.strip() for line in stdout}
            logging.debug(self.packages)
        else:
            raise Exception(f"Unsupported operating system {operating_sys}: we don't know what package manager you're using.")

    def get_dependencies(self, package):
        # logging.debug(f"Getting dependencies for {package}...")
        # Issue--/bin/sh doesn't look like a package to me. what do we do about that?
        _, stdout, stderr = self.client.exec_command(f"rpm -qR {package}")
        # I have no idea which regex is correct--one takes me from 420 to 256 and the other goes to 311
        # deps = [re.split('\W+', line.strip())[0] for line in stdout]
        deps = {line.strip() for line in stdout}
        logging.debug(f"{package} > {deps}")
        return deps

    def get_ports(self):
        # TODO: How do I know I'm not getting my own port that I'm using for ssh? Is it just literally port 22?
        # What if we try to run this on something that uses 22?
        stdin, stdout, stderr = self.client.exec_command('netstat -lntp')
        for line in stdout:
            # Skip header
            if (re.match(r'Proto Recv-Q Send-Q Local', line)
                or re.match(r'Active Internet', line)):
                continue
            proto, recv_q, send_q, local, foreign, state, pid = line.split()
            pid, progname = pid.split('/')
            logging.debug(f"proto:{proto} recv_q:{recv_q} send_q:{send_q} local:{local} foreign:{foreign} state:{state} pid:{pid} progname:{progname}")

    def get_procs(self):
        # Normally we'd have to grep out the command we ran, but we don't have to because ssh. 
        # stdin, stdout, stderr = client.exec_command('ps -ao pid,cmd')
        stdin, stdout, stderr = self.client.exec_command('ps -eo pid,cmd')
        # stdin, stdout, stderr = client.exec_command('ps -aux')
        for line in stdout:
            if not re.match(r'[0-9]+', line.split()[0]):
                continue
            logging.debug(line.rstrip())

    def filter_packages(self):
        '''
        Get a filtered list of packages after figuring out dependencies.
        TODO: in future you can get the base image figured out and not install those packages.
        '''
        self.filtered_packages = filter_non_dependencies(self.packages, self.get_dependencies)
        logging.debug(f"Filter by dependency cut down {len(self.packages)} packages to {len(self.filtered_packages)}")

    def dockerize(self):
        with open(os.path.join(self.dir, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}")
        logging.info(f"Your Dockerfile is in {self.dir}")



if __name__ == "__main__":
    logging.info('Beginning analysis...')
    kowalski = SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME)
    kowalski.get_os()
    kowalski.get_packages()
    kowalski.filter_packages()
    kowalski.get_ports()
    kowalski.get_procs()
    kowalski.dockerize()
