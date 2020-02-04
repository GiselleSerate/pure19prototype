from abc import ABC, abstractmethod
from enum import Enum
import itertools
import logging
from logging.config import dictConfig
import os
import re
import tempfile

import docker
import hashlib
from paramiko import SSHClient, SFTP



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
LOG_LEVEL = 'INFO'

# Centos
PORT = 2222
USERNAME = 'root'

# Ubuntu
PORT = 3333
USERNAME = 'squirrel'

# Ubuntu container
PORT = 1022
USERNAME = 'sshuser'


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


class GeneralAnalyzer:
    '''Does all analysis of a system that you know nothing about.'''
    def __init__(self, hostname=HOSTNAME, port=PORT, username=USERNAME):
        self.ssh_client = SSHClient()
        self.hostname = hostname
        self.port = port
        self.username = username

        self.docker_client = docker.from_env()

        self.operating_sys = None
        self.version = None

        self.analyzer = None


    def __enter__(self):
        # Explore ~/.ssh/ for keys
        self.ssh_client.load_system_host_keys()
        # Establish SSH connection
        self.ssh_client.connect(self.hostname, port=self.port, username=self.username)

        self.get_os()
        self.get_analyzer()

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
            if re.match(r'VERSION_ID=', line):
                line = line.strip().replace('"', '')
                version = line.split('=')[1]
            elif re.match(r'ID=', line):
                line = line.strip().replace('"', '')
                operating_sys = line.split('=')[1]
        self.operating_sys = operating_sys
        self.version = version


    def get_analyzer(self):
        '''
        Creates an instance of the applicable SystemAnalyzer child class based on self.operating_sys.
        '''
        if self.operating_sys == 'centos':
            self.analyzer = CentosAnalyzer(self.ssh_client, self.docker_client, self.operating_sys, self.version)
        elif self.operating_sys == 'ubuntu':
            self.analyzer = UbuntuAnalyzer(self.ssh_client, self.docker_client, self.operating_sys, self.version)
        else:
            logging.error(f"Unknown operating system {self.operating_sys}. This likely means we haven't written a SystemAnalyzer child class for this system yet.")


class SystemAnalyzer(ABC):
    '''
    Does analysis of a system that you know some information about. Use as a base class where child classes know about more specific systems.
    '''
    Mode = Enum('Mode', 'dry unversion delete')

    def __init__(self, ssh_client, docker_client, operating_sys, version):
        self.ssh_client = ssh_client
        self.docker_client = docker_client

        self.operating_sys = operating_sys
        self.version = version
        logging.debug(f"FROM {operating_sys}:{version}")
        self.image = self.docker_client.images.pull(f"{operating_sys}:{version}")
        logging.info(f"Pulled {self.image} from Docker hub.")

        self.packages = {}

        self.tempdir = tempfile.mkdtemp()


    @property
    @abstractmethod
    def LIST_INSTALLED(self):
        '''The command to list all installed packages.'''
        return NotImplementedError


    @staticmethod
    @abstractmethod
    def parse_all_pkgs(iterable):
        '''
        Parse the output of the applicable LIST_INSTALLED command. Return a dictionary of package: version.
        '''
        ...


    @abstractmethod
    def get_packages(self):
        '''
        Gets all packages and versions from the target system and puts them in self.packages.
        '''
        logging.info("Getting packages...")


    @abstractmethod
    def get_dependencies(self, package):
        '''
        Gets the dependencies of a particular package on the target system and returns a dictionary of them.
        package -- the package to get deps for
        '''
        logging.debug(f"Getting dependencies for {package}...")

    @abstractmethod
    def get_config_files_for(self, package): 
        '''
        Returns a list of file paths to configuration files for the specified package.
        package -- the pacakge whose configurations we are interested in
        '''
        logging.debug(f"Getting configuration files associated with {package}...")


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
        pkg_bytestring = self.docker_client.containers.run(f"{self.operating_sys}:{self.version}", type(self).LIST_INSTALLED, remove=True)
        # Last element is a blank line; remove it.
        pkg_list = pkg_bytestring.decode().split('\n')[:-1]
        default_packages = type(self).parse_all_pkgs(pkg_list).keys()
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
        self.dockerize(self.tempdir, verbose=False)
        # Now that we have a Dockerfile, build and check the packages are there
        self.image, _ = self.docker_client.images.build(tag=f'verify{self.operating_sys}', path=self.tempdir)
        container = self.docker_client.containers.run(image=self.image.id, command=type(self).LIST_INSTALLED, detach=True)
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

        container.remove()
        return there == total


    def get_hash_from_container(self, filepath):
        '''
        Given a filepath, returns a checksum of the indicated file.
        Target docker image must have sha1sum available for use.
        Must be called after verify_packages, as it relies on the container having
        already been built and its packages installed.
        '''
        logging.debug(f"hashing default configuration file {filepath} from the container")
        container = self.docker_client.containers.run(image=self.image.id, command=f"sha1sum {filepath}", detach=True)
        container.wait()
        output = container.logs().decode()
        if 'No such file' in output:
            hash = 'No such file'
        else:
            hash = output.split()[0]
        logging.debug(hash)
        return hash



    def get_filesystem_differences(self):
        '''
        Returns a list of the hashes of configuration files that are different
        *** so far only returns hashes of configs from original system ***
        '''
        hash_algorithm = sha1()
        packages = get_packages()
        original_config_hashes = []
        for package in packages:
            configs = get_config_files_for(package)
            for config in configs: 
                config_SFTPFile = ssh_client(config)
                config_hash = config_SFTPFile.check(hash_algorithm)
                original_config_hashes.append(config_hash)
                logging.debug(f"{config} has the following config files: {config_hash}")


    @abstractmethod
    def dockerize(self, folder, verbose=True):
        '''
        Creates Dockerfile from parameters discovered by the class.
        Make sure to call all analysis functions beforehand; this function doesn't actually check for that.
        folder -- the folder to put the Dockerfile in
        verbose -- whether to emit log statements
        '''
        if verbose:
            logging.info("Creating Dockerfile...")



class CentosAnalyzer(SystemAnalyzer):
    LIST_INSTALLED = 'yum list installed -d 0'

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


    def parse_all_pkgs(iterable):
        '''
        Parses an iterable of yum list installed -d 0 style output.
        Returns a dictionary of package versions keyed on package name.
        '''
        packages = {}
        for line in iterable:
            if (re.match(r'Installed Packages', line)):
                continue
            pkgName, pkgVer = CentosAnalyzer.parse_pkg_line(line)
            packages[pkgName] = pkgVer
        return packages


    def get_packages(self):
        '''
        Gets all packages and versions from the target system.
        '''
        super().get_packages()
        stdin, stdout, stderr = self.ssh_client.exec_command(CentosAnalyzer.LIST_INSTALLED)
        self.packages = CentosAnalyzer.parse_all_pkgs(stdout)
        logging.debug(self.packages)


    def get_dependencies(self, package):
        '''
        Gets the dependencies of a particular package on the target system. (Currently uses rpm.)
        package -- the package to get deps for
        '''
        super().get_dependencies(package)
        # Issue--/bin/sh doesn't look like a package to me. what do we do about that?
        _, stdout, stderr = self.ssh_client.exec_command(f"rpm -qR {package}")
        # I have no idea which regex is correct--one takes me from 420 to 256 and the other goes to 311
        # deps = [re.split('\W+', line.strip())[0] for line in stdout]
        deps = {line.strip() for line in stdout}
        logging.debug(f"{package} > {deps}")
        return deps

    def get_config_files_for(self, package): 
        '''
        Returns a list of file paths to configuration files for the specified package.
        package -- the pacakge whose configurations we are interested in
        '''
        super().get_config_files_for(package)
        _, stdout, stderr = self.ssh_client.exec_command(f"rpm -qc {package}")
        configs = {line.strip() for line in stdout}
        logging.debug(f"{package} has the following config files: {configs}")
        return configs

    def dockerize(self, folder, verbose=True):
        '''
        Creates Dockerfile from parameters discovered by the class.
        Make sure to call all analysis functions beforehand; this function doesn't actually check for that.
        folder -- the folder to put the Dockerfile in
        verbose -- whether to emit log statements
        '''
        super().dockerize(folder, verbose)
        with open(os.path.join(folder, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}\n")

            dockerfile.write(f"RUN yum -y install ")
            for name, ver in self.packages.items():
                if ver:
                    dockerfile.write(f"{name}-{ver} ")
                else:
                    dockerfile.write(f"{name} ")
            dockerfile.write("\n")
        if verbose:
            logging.info(f"Your Dockerfile is in {folder}")


class UbuntuAnalyzer(SystemAnalyzer):
    LIST_INSTALLED = 'apt list --installed'


    @staticmethod
    def parse_pkg_line(line):
        '''
        Parses apt-style package lines. 
        Returns a tuple of package name, package version.
        '''
        #assumes line comes in as something like 'accountsservice/bionic,now 0.6.45-1ubuntu1 amd64 [installed,automatic]'
        clean_line = line.strip() # Trim whitespace
        name = clean_line.split('/')[0]
        ver = clean_line.split('now ')[1] # 0.6.45-1ubuntu1 amd64 [installed,automatic]
        ver = ver.split(' ')[0] # 0.6.45-1ubuntu1
        return (name, ver)


    def parse_all_pkgs(iterable):
        '''
        Parses an iterable of apt list --installed style output.
        Returns a dictionary of package versions keyed on package name.
        '''
        packages = {}
        for line in iterable:
            if (re.match(r'Listing', line)):
                continue
            pkgName, pkgVer = UbuntuAnalyzer.parse_pkg_line(line)
            packages[pkgName] = pkgVer
        return packages


    def get_packages(self):
        '''
        Gets all packages and versions from the target system.
        '''
        super().get_packages()
        stdin, stdout, stderr = self.ssh_client.exec_command(UbuntuAnalyzer.LIST_INSTALLED)
        self.packages = UbuntuAnalyzer.parse_all_pkgs(stdout)
        logging.debug(self.packages)


    def get_dependencies(self, package):
        '''
        NEVER CALLED :/
        Gets the dependencies of a particular package on the target system. (Currently uses rpm.)
        package -- the package to get deps for
        '''
        super().get_dependencies(package)
        # Issue--/bin/sh doesn't look like a package to me. what do we do about that?
        _, stdout, stderr = self.ssh_client.exec_command(f"rpm -qR {package}")
        # I have no idea which regex is correct--one takes me from 420 to 256 and the other goes to 311
        # deps = [re.split('\W+', line.strip())[0] for line in stdout]
        deps = {line.strip() for line in stdout}
        logging.debug(f"{package} > {deps}")
        return deps

    def get_config_files_for(self, package): 
        '''
        Returns a list of file paths to configuration files for the specified package.
        package -- the pacakge whose configurations we are interested in
        '''
        super().get_config_files_for(package)
        _, stdout, stderr = self.ssh_client.exec_command(f"cat /var/lib/dpkg/info/{package}.conffiles")
        configs = {line.strip() for line in stdout}
        logging.debug(f"{package} has the following config files: {configs}")
        return configs

    def assemble_packages(self):
        '''
        Assembles all packages and versions (if applicable) into a string for installer, and returns the string.
        '''
        install_all = ""
        for name, ver in self.packages.items():
            if ver:
                install_all += f"{name}={ver} "
            else:
                install_all += f"{name} "
        return install_all

    def verify_packages(self, mode=SystemAnalyzer.Mode.dry):
        '''
        Looks through package list to see which packages are uninstallable.
        mode -- in dry mode, just log bad pkgs. in delete mode, delete bad pkgs from the list. in unversion mode, unspecify version.
        Returns True if all packages got installed correctly; returns False otherwise. 
        '''
        logging.info(f"Verifying packages in {mode.name} mode...")
        # Write prelude, create image.
        with open(os.path.join(self.tempdir, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}\n")
            dockerfile.write(f"ENV DEBIAN_FRONTEND=noninteractive\n")
            dockerfile.write(f"RUN apt-get update\n") # I know this is supposed to go on the same line as the installs normally, but
        self.image, _ = self.docker_client.images.build(tag=f'verify{self.operating_sys}', path=self.tempdir)
        
        # Try installing all of the packages.
        install_all = "apt-get -y install "
        install_all += self.assemble_packages()

        # Spin up the container and let it do its thing.
        container = self.docker_client.containers.run(self.image.id, command=install_all, detach=True)
        container.wait()

        # Parse the container's output.
        missing_pkgs = re.findall("E: Unable to locate package (.*)\n", container.logs().decode())
        missing_vers = re.findall("' for '(.*)' was not found\n", container.logs().decode())

        if not re.search("E: ", container.logs().decode()):
            logging.info("All packages installed properly.")
            container.remove()
            return True
        
        if not missing_pkgs and not missing_vers: 
            logging.error(f"No missing packages or versions found, but there was an error:\n{container.logs().decode()}")
            # Intentionally not removing the container for debugging purposes. 
            return False

        # Report on missing packages.
        logging.warning(f"Could not find the following packages: {missing_pkgs}")
        logging.warning(f"Could not find versions for the following packages: {missing_vers}")
        if mode == self.Mode.unversion:
            logging.info(f"Now removing version numbers from bad packages...")
            for pkg_name in missing_vers:
                self.packages[pkg_name] = False
        elif mode == self.Mode.delete:
            logging.info(f"Now removing bad packages...")
            for pkg_name in itertools.chain(missing_pkgs, missing_vers):
                del self.packages[pkg_name]

        container.remove()
        return False



    def dockerize(self, folder, verbose=True):
        '''
        Creates Dockerfile from parameters discovered by the class.
        Make sure to call all analysis functions beforehand; this function doesn't actually check for that.
        folder -- the folder to put the Dockerfile in
        verbose -- whether to emit log statements
        '''
        super().dockerize(folder, verbose)
        with open(os.path.join(folder, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}\n")

            dockerfile.write(f"ENV DEBIAN_FRONTEND=noninteractive\n")

            dockerfile.write(f"RUN apt-get update && apt-get install -y ")
            dockerfile.write(self.assemble_packages())
            dockerfile.write("\n")
        if verbose:
            logging.info(f"Your Dockerfile is in {folder}")


if __name__ == "__main__":
    logging.info('Beginning analysis...')
    with GeneralAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.analyzer.get_packages()
        kowalski.analyzer.filter_packages()
        for mode in (SystemAnalyzer.Mode.dry, SystemAnalyzer.Mode.unversion, SystemAnalyzer.Mode.delete):
            if kowalski.analyzer.verify_packages(mode=mode):
                break
        kowalski.analyzer.dockerize(tempfile.mkdtemp())
        # DEBUG: for testing config hashing
        # for pkg in kowalski.analyzer.packages:
        #     confs = kowalski.analyzer.get_config_files_for(pkg)
        #     for conf in confs:
        #         kowalski.analyzer.get_hash_from_container(conf)
