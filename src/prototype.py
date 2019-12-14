from enum import Enum
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
    Mode = Enum('Mode', 'dry unversion delete')

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

        self.tempdir = tempfile.mkdtemp()


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
        '''
        Gets the operating system and version of the target system.
        '''
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
        '''
        Parses yum-style package lines. 
        Returns a tuple of package name, package version.
        '''
        #assumes line comes in as something like 'curl.x86_64   [1:]7.29.0-42.el7'
        clean_line = line.strip().split(maxsplit=2)
        name = clean_line[0] #curl.x86_64
        name = name.rsplit(sep='.', maxsplit=1)[0]   #curl
        ver = clean_line[1] #1:7.29.0-42.el7
        ver = ver.split(sep='-', maxsplit=2)[0]    #1:7.29.0
        # If epoch number exists, get rid of it.
        ver = ver.split(':')[-1] #7.29.0
        return (name, ver)


    @staticmethod
    def parse_all_pkgs(iterable):
        '''
        Parses an iterable of yum list installed -d 0 style output.
        Returns a dictionary of package versions keyed on package name.
        '''
        packages = {}
        passedChaff = False;
        for line in iterable:
            if (re.match(r'Installed Packages', line)):
                continue    
            pkgName, pkgVer = SystemAnalyzer.parse_pkg_line(line)
            packages[pkgName] = pkgVer
        return packages


    def get_packages(self):
        '''
        Gets all packages and versions from the target system.
        '''
        logging.info("Getting packages...")
        while self.operating_sys == None:
            logging.warning("No operating system yet.")
            self.get_os()
        if self.operating_sys == 'centos':
            stdin, stdout, stderr = self.ssh_client.exec_command("yum list installed -d 0")
            self.packages = SystemAnalyzer.parse_all_pkgs(stdout)
            logging.debug(self.packages)
        else:
            raise Exception(f"Unsupported operating system {operating_sys}: we don't know what package manager you're using.")


    def get_dependencies(self, package):
        '''
        Gets the dependencies of a particular package on the target system. (Currently uses rpm.)
        package -- the package to get deps for
        '''
        # logging.debug(f"Getting dependencies for {package}...")
        # Issue--/bin/sh doesn't look like a package to me. what do we do about that?
        _, stdout, stderr = self.ssh_client.exec_command(f"rpm -qR {package}")
        # I have no idea which regex is correct--one takes me from 420 to 256 and the other goes to 311
        # deps = [re.split('\W+', line.strip())[0] for line in stdout]
        deps = {line.strip() for line in stdout}
        logging.debug(f"{package} > {deps}")
        return deps


    def get_ports(self):
        '''
        Gets the open ports on the target machine. (Currently just a printout of a netstat call.)
        '''
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
        '''
        Gets the running processes on the target machine. (Currently just a printout of ps.)
        '''
        # Normally we'd have to grep out the command we ran, but we don't have to because ssh. 
        # stdin, stdout, stderr = client.exec_command('ps -ao pid,cmd')
        stdin, stdout, stderr = self.ssh_client.exec_command('ps -eo pid,cmd')
        # stdin, stdout, stderr = client.exec_command('ps -aux')
        for line in stdout:
            if not re.match(r'[0-9]+', line.split()[0]):
                continue
            logging.debug(line.rstrip())


    def filter_packages(self):
        '''
        Removes packages from the list to be installed which are already in the base image. 
        '''
        logging.info("Filtering packages...")
        num_packages = len(self.packages)
        if num_packages == 0:
            logging.warning("No packages yet. Have you run get_packages?")
            return

        # Get default-installed packages from Docker base image we're going to use
        # pkg_bytestring = self.docker_client.containers.run(f"{self.operating_sys}:{self.version}", "rpm -qa --queryformat '%{NAME}\n'") # TODO rpm? no thx
        pkg_bytestring = self.docker_client.containers.run(f"{self.operating_sys}:{self.version}", "yum list installed -d 0") # TODO rpm? no thx
        # Last element is a blank line; remove it.
        pkg_list = pkg_bytestring.decode().split('\n')[:-1]
        default_packages = SystemAnalyzer.parse_all_pkgs(pkg_list).keys()
        # Delete default packages from what we'll install
        for pkg_name in default_packages:
            try:
                del self.packages[pkg_name]
            except KeyError:
                pass
        logging.info(f"Removing defaults cut down {num_packages} packages to {len(self.packages)}.")


    def verify_packages(self, mode=Mode.dry):
        '''
        Looks through package list to see which packages are uninstallable.
        mode -- in dry mode, just log bad pkgs. in delete mode, delete bad pkgs from the list. in unversion mode, unspecify version.
        Returns True if all packages got installed correctly; returns False otherwise. 
        '''
        logging.info(f"Verifying packages in {mode.name} mode...")
        self.dockerize(self.tempdir)
        # Now that we have a Dockerfile, build and check the packages are there
        image, _ = self.docker_client.images.build(tag='pytest', path=self.tempdir)
        container = self.docker_client.containers.run(image=image.id, command="yum list installed", detach=True)
        # Block until the command's done, then check its output.
        container.wait()
        output = container.logs()
        output = output.decode()
        logging.debug(output)

        there = 0
        total = 0
        missing = []
        for package in self.packages.keys():
            if package in output:
                there += 1
            else:
                missing.append(package)
            total += 1

        if there < total:
            logging.error(f"{there}/{total} packages installed.")
            logging.error(f"The following packages could not be installed: {missing}")
            if mode == self.Mode.unversion:
                logging.info(f"Now removing version numbers from bad packages...")
                for pkg_name in missing:
                    self.packages[pkg_name] = False
            elif mode == self.Mode.delete:
                logging.info(f"Now removing bad packages...")
                for pkg_name in missing:
                    del self.packages[pkg_name]
        else:
            logging.info(f"All {total} packages installed properly.")

        return there == total


    def dockerize(self, folder):
        '''
        Creates Dockerfile from parameters discovered by the class.
        Make sure to call all analysis functions beforehand; this function doesn't actually check for that.
        folder -- the folder to put the Dockerfile in
        '''
        logging.info("Creating Dockerfile...")
        with open(os.path.join(folder, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}\n")

            dockerfile.write("RUN yum -y install ")
            for name, ver in self.packages.items():
                if ver:
                    dockerfile.write(f"{name}-{ver} ")
                else:
                    dockerfile.write(f"{name} ")
            dockerfile.write("\n")
        logging.info(f"Your Dockerfile is in {folder}")



if __name__ == "__main__":
    logging.info('Beginning analysis...')
    with SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.get_os()
        kowalski.get_packages()
        kowalski.filter_packages()
        kowalski.verify_packages(mode=SystemAnalyzer.Mode.unversion)
        kowalski.dockerize(tempfile.mkdtemp())
