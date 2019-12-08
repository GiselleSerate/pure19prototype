import logging
from logging.config import dictConfig
import os
import re
import tempfile

import docker
from paramiko import SSHClient



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
        self.ssh_client = SSHClient()
        self.hostname = hostname
        self.port = port
        self.username = username

        self.docker_client = docker.from_env()

        self.operating_sys = None
        self.version = None
        self.image = None
        self.packages = {}

        self.dir = tempfile.mkdtemp()


    def __enter__(self):
        # Explore ~/.ssh/ for keys
        self.ssh_client.load_system_host_keys()
        # Establish SSH connection
        self.ssh_client.connect(self.hostname, port=self.port, username=self.username)

        return self


    def __exit__(self, *args):
        # Make sure you kill the connection when you're done
        self.ssh_client.close()


    def get_os(self):
        logging.info("Getting operating system and version...")
        stdin, stdout, stderr = self.ssh_client.exec_command('cat /etc/os-release')
        # Extract operating system and version
        for line in stdout:
            if re.match(r'ID=', line):
                operating_sys = line.split('=')[1].split('"')[1]
            elif re.match(r'VERSION_ID=', line):
                version = line.split('=')[1].split('"')[1]
        self.operating_sys = operating_sys
        self.version = version
        logging.debug(f"FROM {operating_sys}:{version}")
        self.image = self.docker_client.images.pull(f"{operating_sys}:{version}")
        logging.info(f"Pulled {self.image} from Docker hub.")


    @staticmethod
    def parse_pkg_line(line):
        #assumes line comes in as something like 'curl.x86_64   [1:]7.29.0-42.el7'
        name = line.strip().split()[0] #curl.x86_64
        name = name.split('.')[0]   #curl
        ver = line.strip().split()[1] #1:7.29.0-42.el7
        ver = ver.split('-')[0]    #1:7.29.0
        if (':' in ver):
            ver = ver.split(':')[1] #7.29.0
        return (name, ver)


    def get_packages(self):
        logging.info("Getting packages...")
        while self.operating_sys == None:
            logging.warning("No operating system yet.")
            self.get_os()
        if self.operating_sys == 'centos':
            stdin, stdout, stderr = self.ssh_client.exec_command("yum list installed")
            #'yum list installed' prints some extra lines before the actual packages, so I want to ignore them
            passedChaff = False;
            for line in stdout:
                if (passedChaff):
                    pkgName, pkgVer = self.parse_pkg_line(line)
                    self.packages[pkgName] = pkgVer
                elif (re.match(r'Installed Packages', line)):
                        passedChaff = True

            logging.debug(self.packages)
        else:
            raise Exception(f"Unsupported operating system {operating_sys}: we don't know what package manager you're using.")


    def get_dependencies(self, package):
        # logging.debug(f"Getting dependencies for {package}...")
        # Issue--/bin/sh doesn't look like a package to me. what do we do about that?
        _, stdout, stderr = self.ssh_client.exec_command(f"rpm -qR {package}")
        # I have no idea which regex is correct--one takes me from 420 to 256 and the other goes to 311
        # deps = [re.split('\W+', line.strip())[0] for line in stdout]
        deps = {line.strip() for line in stdout}
        logging.debug(f"{package} > {deps}")
        return deps


    def get_ports(self):
        # TODO: How do I know I'm not getting my own port that I'm using for ssh? Is it just literally port 22?
        # What if we try to run this on something that uses 22?
        stdin, stdout, stderr = self.ssh_client.exec_command('netstat -lntp')
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
        stdin, stdout, stderr = self.ssh_client.exec_command('ps -eo pid,cmd')
        # stdin, stdout, stderr = client.exec_command('ps -aux')
        for line in stdout:
            if not re.match(r'[0-9]+', line.split()[0]):
                continue
            logging.debug(line.rstrip())


    def dockerize(self):
        with open(os.path.join(self.dir, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}\n")

            dockerfile.write("RUN yum -y install ")
            for name, ver in self.packages.items():
                dockerfile.write(f"{name}-{ver} ")
            dockerfile.write("\n")
        logging.info(f"Your Dockerfile is in {self.dir}")



if __name__ == "__main__":
    logging.info('Beginning analysis...')
    with SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.get_os()
        kowalski.get_packages()
        kowalski.get_ports()
        kowalski.get_procs()
        kowalski.dockerize()
