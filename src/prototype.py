'''
Provides classes to analyze an SSHable system from the ground up and convert it to a container.

GeneralAnalyzer begins from no knowledge and sets up an environment to look at a system.
SystemAnalyzer is an abstract base class which may be extended to create more specific analyzers
    for certain OSs or package managers.
UbuntuAnalyzer inherits from SystemAnalyzer and contains methods to analyze Ubuntu/apt systems.
CentosAnalyzer inherits from SystemAnalyzer and contains methods to analyze CentOS/yum systems.
'''

from abc import ABC, abstractmethod
from enum import Enum
import itertools
import logging
from logging.config import dictConfig
import os
import re
import tempfile

import docker
from paramiko import SSHClient



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
LOG_LEVEL = 'INFO'

# Centos
PORT = 2222
USERNAME = 'root'

# Ubuntu
# PORT = 3333
# USERNAME = 'root'

# # Ubuntu container
# PORT = 1022
# USERNAME = 'sshuser'


# Configure logging
dictConfig({
    'version': 1,
    'formatters': {
        'default': {
            'format': '%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        },
        'minimal': {
            'format': '[%(filename)s:%(lineno)d] %(message)s',
        }
    },
    'handlers': {
        'wsgi': {
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'formatter': 'default'
        },
        'filehandler': {
            'class': 'logging.FileHandler',
            'filename': 'pure_prototype_files.log',
            'mode': 'w',
            'level': 'DEBUG',
            'formatter': 'minimal'
        }
    },
    'loggers': {
        'filenames': {
            'propagate': False,
            'handlers': ['filehandler']
        }
    },
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
        _, stdout, _ = self.ssh_client.exec_command('cat /etc/os-release')
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
        Creates an instance of the applicable SystemAnalyzer child class based on
        self.operating_sys.
        '''
        if self.operating_sys == 'centos':
            self.analyzer = CentosAnalyzer(self.ssh_client, self.docker_client, self.operating_sys,
                                           self.version)
        elif self.operating_sys == 'ubuntu':
            self.analyzer = UbuntuAnalyzer(self.ssh_client, self.docker_client, self.operating_sys,
                                           self.version)
        else:
            logging.error(f"Unknown operating system {self.operating_sys}. This likely means we "
                          f"haven't written a SystemAnalyzer child class for this system yet.")


class SystemAnalyzer(ABC):
    '''
    Does analysis of a system that you know some information about. Use as a base class where child
    classes know about more specific systems.
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

        # All packages on the system
        self.all_packages = {}
        # Only (and all) the packages we want to install
        self.install_packages = {}
        # A list of packages (and their new versions) that we installed on a version
        # number different from the original system
        self.unversion_packages = {}

        # Keyed on path, each contains dictionary: {'hash': hash, 'size': size}
        self.vm_hashes = {}
        self.container_hashes = {}

        # Specificallly config file differences
        self.diff_configs = set()
        self.vm_configs = set()
        self.container_configs = set()

        self.tempdir = tempfile.mkdtemp()

        self.file_logger = logging.getLogger('filenames')


    @property
    @abstractmethod
    def LIST_INSTALLED(self):
        '''The command to list all installed packages.'''
        return NotImplementedError


    @staticmethod
    @abstractmethod
    def parse_all_pkgs(iterable):
        '''
        Parse the output of the applicable LIST_INSTALLED command. Return a dictionary of
        package: version.
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
        Gets the dependencies of a particular package on the target system and returns a dictionary
        of them.
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
        # TODO: How do I know I'm not getting my own port that I'm using for ssh? Is it just
        # literally port 22?
        # What if we try to run this on something that uses 22?
        _, stdout, _ = self.ssh_client.exec_command('netstat -lntp')
        for line in stdout:
            # Skip header
            if (re.match(r'Proto Recv-Q Send-Q Local', line)
                    or re.match(r'Active Internet', line)):
                continue
            proto, recv_q, send_q, local, foreign, state, pid = line.split()
            pid, progname = pid.split('/')
            logging.debug(f"proto:{proto} recv_q:{recv_q} send_q:{send_q} local:{local} "
                          f"foreign:{foreign} state:{state} pid:{pid} progname:{progname}")


    def get_procs(self):
        '''
        Gets the running processes on the target machine. (Currently just a printout of ps.)
        '''
        # Normally we'd have to grep out the command we ran, but we don't have to because ssh.
        # stdin, stdout, stderr = client.exec_command('ps -ao pid,cmd')
        _, stdout, _ = self.ssh_client.exec_command('ps -eo pid,cmd')
        # stdin, stdout, stderr = client.exec_command('ps -aux')
        for line in stdout:
            if not re.match(r'[0-9]+', line.split()[0]):
                continue
            logging.debug(line.rstrip())


    def filter_packages(self, strict_versioning=True):
        '''
        Removes packages from the list to be installed which are already in the base image.
        strict_versioning -- if True, we'll only remove the package if the versions match
        Note that we leave them (and their versions) in self.all_packages
        '''
        logging.info("Filtering packages...")
        num_packages = len(self.all_packages)
        if num_packages == 0:
            logging.warning("No packages yet. Have you run get_packages?")
            return

        # Get default-installed packages from Docker base image we're going to use
        pkg_bytestring = self.docker_client.containers.run(f"{self.operating_sys}:{self.version}",
                                                           type(self).LIST_INSTALLED, remove=True)
        # Last element is a blank line; remove it.
        pkg_list = pkg_bytestring.decode().split('\n')[:-1]
        default_packages = type(self).parse_all_pkgs(pkg_list)
        # Delete default packages from what we'll install
        for pkg_name, pkg_ver in default_packages.items():
            try:
                existing_version = self.install_packages[pkg_name]
                # If we don't care about version mismatch (or there is none)
                if not strict_versioning or existing_version == pkg_ver:
                    del self.install_packages[pkg_name]
                    if not strict_versioning:
                        # Record mismatch
                        self.unversion_packages[pkg_name] = pkg_ver
            except KeyError:
                # Package not slated to be installed anyway
                pass
        logging.info(f"Removing defaults cut down {num_packages} packages to "
                     f"{len(self.install_packages)}.")


    def verify_packages(self, mode=Mode.dry):
        '''
        Looks through package list to see which packages are uninstallable.
        mode -- in dry mode, just log bad pkgs. in delete mode, delete bad pkgs from the list.
                in unversion mode, unspecify version.
        Returns True if all packages got installed correctly; returns False otherwise.
        '''
        logging.info(f"Verifying packages in {mode.name} mode...")
        self.dockerize(self.tempdir, verbose=False)
        # Now that we have a Dockerfile, build and check the packages are there
        self.image, _ = self.docker_client.images.build(tag=f'verify{self.operating_sys}',
                                                        path=self.tempdir)
        container = self.docker_client.containers.run(image=self.image.id,
                                                      command=type(self).LIST_INSTALLED,
                                                      detach=True)
        # Block until the command's done, then check its output.
        container.wait()
        output = container.logs()
        output = output.decode()
        logging.debug(output)

        there = 0
        total = 0
        missing = []
        for package in self.install_packages:
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
                    self.install_packages[pkg_name] = False # TODO: I know we're going to change this later
            elif mode == self.Mode.delete:
                logging.info(f"Now removing bad packages...")
                for pkg_name in missing:
                    del self.install_packages[pkg_name]
        else:
            logging.info(f"All {total} packages installed properly.")

        container.remove()
        return there == total


    def get_hash_from_container(self, filepath, is_directory=False):
        '''
        Given a filepath, returns a checksum of the indicated file.
        You may also pass a space-separated list of files.
        If your path is a directory, it must end in a slash. I don't check for this but you gotta.
        If is_directory is True, go into subdirectories, else assume it is a single file.
        Target docker image must have cksum available for use.
        Must be called after verify_packages, as it relies on the container having
        already been built and its packages installed.
        '''
        if not filepath:
            logging.warning("Please pass a filepath.")
            return None
        logging.debug(f"Hashing filepath {filepath} from the container...")
        if is_directory:
            container = self.docker_client.containers.run(image=self.image.id,
                                                          command=f"find {filepath} -type f "
                                                                  f"-exec cksum '{{}}' \\;",
                                                          detach=True)
        else:
            container = self.docker_client.containers.run(image=self.image.id,
                                                          command=f"cksum {filepath}",
                                                          detach=True)
        container.wait()
        crc = None
        output = container.logs().decode()
        # Extract hashes and sizes from output.
        lines = output.split('\n')
        for line in lines:
            if line == "":
                continue
            if 'No such file' in line:
                # Couldn't find the file. This is expected to happen sometimes; just keep going.
                logging.warning(f"From container: {line}")
                continue
            try:
                crc, size, file = line.split()
                self.container_hashes[file] = {'hash': crc, 'size': size}
            except ValueError:
                logging.error(f"Unexpected number of values returned from line: {line.split()}")
                raise
        if is_directory:
            # In this case, the returned hash would just be the last thing hashed; not meaningful,
            # so don't return it.
            return None
        return crc


    def get_hash_from_vm(self, filepath, is_directory=False):
        '''
        Given a filepath, returns a checksum of the indicated file from a VM.
        You may also pass a space-separated list of files.
        If your path is a directory, it must end in a slash. I don't check for this but you gotta.
        If is_directory is True, go into subdirectories, else assume it is a single file.
        '''
        if not filepath:
            logging.warning("Please pass a filepath.")
            return None
        logging.debug(f"Hashing file {filepath} from the VM...")
        if is_directory:
            _, stdout, _ = self.ssh_client.exec_command(f"find {filepath} -type f "
                                                        f"-exec cksum '{{}}' \\;")
        else:
            _, stdout, _ = self.ssh_client.exec_command(f'cksum {filepath}')
        crc = None
        for line in stdout:
            if line == "":
                continue
            if 'No such file' in line:
                # Couldn't find the file. This is expected to happen sometimes; just keep going.
                continue
            try:
                crc, size, file = line.split()
                self.vm_hashes[file] = {'hash': crc, 'size': size}
            except ValueError:
                logging.error(f"Unexpected number of values returned from line: {line.split()}")
                raise
        if is_directory:
            # In this case, the returned hash would just be the last thing hashed; not meaningful,
            # so don't return it.
            return None
        return crc


    def analyze_files(self, places):
        '''
        Analyze all subdirectories of places (list of directories). Determine how many are on the
        container/VM/both, and of the files in common which are different.
        Currently we just dump everything to logs; eventually we may want to return some of this.
        '''
        logging.info(f"Diffing subdirectories of {places}")
        unique = {}
        for place in places:
            unique[place] = self.compare_names([place])
        for place, diff_tuple in unique.items():
            logging.info(f"{place} has {len(diff_tuple[0])} files unique to the container, "
                         f"{len(diff_tuple[1])} files shared, and {len(diff_tuple[2])} files "
                         "unique to the VM")
            self.file_logger.info(f"PLACE: {place}")
            self.file_logger.info(f"Just container ({len(diff_tuple[0])}):\n"
                                  f"{diff_tuple[0]}")
            self.file_logger.info(f"Shared ({len(diff_tuple[1])}):\n{diff_tuple[1]}")
            self.file_logger.info(f"Just VM ({len(diff_tuple[2])}):\n{diff_tuple[2]}")
            # Now cksum the shared ones
            modified_files = []
            spaced_strs = group_strings(list(diff_tuple[1]))
            for place_str in spaced_strs:
                self.get_hash_from_container(place_str, is_directory=False)
                self.get_hash_from_vm(place_str, is_directory=False)
            for file in diff_tuple[1]:
                container_h = self.container_hashes[file]["hash"]
                vm_h = self.vm_hashes[file]["hash"]
                if container_h != vm_h:
                    modified_files.append(file)
            logging.info(f"In {place}, {len(modified_files)} out of {len(diff_tuple[1])} files "
                         f"found on both systems were different.")
            logging.debug(f"These files in {place} were different: {modified_files}")
            self.file_logger.info(f"Same name, but different cksum "
                                  f"({len(modified_files)}):\n{modified_files}")


    def get_config_differences(self):
        '''
        Compares the checksums of all config files on the system.
        Clears and repopulates self.diff_configs, self.vm_configs, and self.container_configs with
        the appropriate files that are on both systems but different, on the VM (possibly also the
        container), and on the container (possibly also the VMs).
        Returns True if it succeeded, False otherwise.
        '''
        if not self.all_packages:
            logging.error("Attempted to get config differences but haven't run get_packages() yet. "
                          "Stopping.")
            return False
        logging.info("Getting config differences...")
        
        # Clear configs (else if we run this twice and things have changed, could be confusing)
        self.diff_configs = set()
        self.vm_configs = set()
        self.container_configs = set()

        # Populate full set of all config files on the system
        configs = set()
        for pkg in self.all_packages:
            configs |= self.get_config_files_for(pkg)

        # Hash and save all files in configs
        split_files = group_strings(list(configs))
        for file_group in split_files:
            self.get_hash_from_vm(file_group)
            self.get_hash_from_container(file_group)

        # Determine what got hashed
        for config in configs:
            vm_hash = None
            container_hash = None
            try:
                vm_hash = self.vm_hashes[config]
                # The file is on the VM
                self.vm_configs.add(config)
            except KeyError:
                pass
            try:
                container_hash = self.container_hashes[config]
                # The file is on the container
                self.container_configs.add(config)
            except KeyError:
                pass
            # If we got both hashes, compare them
            if vm_hash and container_hash and vm_hash != container_hash:
                self.diff_configs.add(config)

        # Log what we've found
        logging.info(f"Number of configs on vm: {len(self.vm_configs)}")
        logging.info(f"Number of configs on container: {len(self.container_configs)}")
        logging.info(f"Number of identical config files: "
                     f"{len(self.vm_configs & self.container_configs - self.diff_configs)}")
        logging.info(f"Config differences ({len(self.diff_configs)}) are {self.diff_configs}")
        logging.info(f"Configs missing on vm ({len(self.container_configs - self.vm_configs)}) "
                     f"are {self.container_configs - self.vm_configs}")
        logging.info(f"Configs missing on container "
                     f"({len(self.vm_configs - self.container_configs)}) are "
                     f"{self.vm_configs - self.container_configs}")
        self.file_logger.info(f"Number of configs on vm: {len(self.vm_configs)}")
        self.file_logger.info(f"Number of configs on container: {len(self.container_configs)}")
        self.file_logger.info(f"Number of identical configs on both vm and container: "
                              f"{len(self.vm_configs & self.container_configs - self.diff_configs)}")
        self.file_logger.info(f"Config differences ({len(self.diff_configs)}):\n"
                              f"{self.diff_configs}")
        self.file_logger.info(f"Configs missing on vm "
                              f"({len(self.container_configs - self.vm_configs)}):\n"
                              f"{self.container_configs - self.vm_configs}")
        self.file_logger.info(f"Configs missing on container "
                              f"({len(self.vm_configs - self.container_configs)}):\n"
                              f"{self.vm_configs - self.container_configs}")
        return True

    def compare_names(self, places):
        '''
        Takes an iterable of folders to look in for differences.
        Returns a tuple of filenames only on the container, filenames on both, and filenames only on
        the VM.
        '''
        docker_filenames = set()
        vm_filenames = set()
        for folder in places:
            _, stdout, _ = self.ssh_client.exec_command(f"find {folder} -type f")
            for line in stdout:
                vm_filenames.add(line.strip())
            container = self.docker_client.containers.run(image=self.image.id,
                                                          command=f"find {folder} -type f",
                                                          detach=True)
            container.wait()
            output = container.logs().decode()
            for line in output.split():
                docker_filenames.add(line)
        logging.debug(f"The total number of files in the VM is {len(vm_filenames)}")
        logging.debug(f"The total number of files in the container is {len(docker_filenames)}")
        return (docker_filenames - vm_filenames,
                vm_filenames & docker_filenames,
                vm_filenames - docker_filenames)

    @abstractmethod
    def dockerize(self, folder, verbose=True):
        '''
        Creates Dockerfile from parameters discovered by the class.
        Make sure to call all analysis functions beforehand; this function doesn't actually check
        for that.
        folder -- the folder to put the Dockerfile in
        verbose -- whether to emit log statements
        '''
        if verbose:
            logging.info("Creating Dockerfile...")



class CentosAnalyzer(SystemAnalyzer):
    '''
    Inherits from SystemAnalyzer to provide functions for analyzing CentOS/yum style systems.
    '''
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

    @staticmethod
    def parse_all_pkgs(iterable):
        '''
        Parses an iterable of yum list installed -d 0 style output.
        Returns a dictionary of package versions keyed on package name.
        '''
        packages = {}
        for line in iterable:
            if re.match(r'Installed Packages', line):
                continue
            pkg_name, pkg_ver = CentosAnalyzer.parse_pkg_line(line)
            packages[pkg_name] = pkg_ver
        return packages


    def get_packages(self):
        '''
        Gets all packages and versions from the target system.
        '''
        super().get_packages()
        _, stdout, _ = self.ssh_client.exec_command(CentosAnalyzer.LIST_INSTALLED)
        self.all_packages = CentosAnalyzer.parse_all_pkgs(stdout)
        # Note that this is a shallow copy; if you add more info to the dictionaries later on,
        # you'll have to change this.
        self.install_packages = self.all_packages.copy()
        logging.debug(self.all_packages)


    def get_dependencies(self, package):
        '''
        Gets the dependencies of a particular package on the target system. (Currently uses rpm.)
        package -- the package to get deps for
        '''
        super().get_dependencies(package)
        # Issue--/bin/sh doesn't look like a package to me. what do we do about that?
        _, stdout, _ = self.ssh_client.exec_command(f"rpm -qR {package}")
        # TODO: I have no idea which regex is correct--one takes me from 420 to 256 and
        # the other goes to 311
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
        _, stdout, _ = self.ssh_client.exec_command(f"rpm -qc {package}")
        configs = {line.strip() for line in stdout}
        # This is an alias for no files.
        if '(contains no files)' in configs:
            configs = set()
        logging.debug(f"{package} has the following config files: {configs}")
        return configs

    def dockerize(self, folder, verbose=True):
        '''
        Creates Dockerfile from parameters discovered by the class.
        Make sure to call all analysis functions beforehand; this function doesn't actually check
        for that.
        folder -- the folder to put the Dockerfile in
        verbose -- whether to emit log statements
        '''
        super().dockerize(folder, verbose)
        with open(os.path.join(folder, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}\n")

            dockerfile.write(f"RUN yum -y install ")
            for name, ver in self.install_packages.items():
                if ver:
                    dockerfile.write(f"{name}-{ver} ")
                else:
                    dockerfile.write(f"{name} ")
            dockerfile.write("\n")
        if verbose:
            logging.info(f"Your Dockerfile is in {folder}")


class UbuntuAnalyzer(SystemAnalyzer):
    '''
    Inherits from SystemAnalyzer to provide functions for analyzing Ubuntu/apt style systems.
    '''
    LIST_INSTALLED = 'apt list --installed'


    @staticmethod
    def parse_pkg_line(line):
        '''
        Parses apt-style package lines.
        Returns a tuple of package name, package version.
        '''
        #assumes line comes in as something like
        # 'accountsservice/bionic,now 0.6.45-1ubuntu1 amd64 [installed,automatic]'
        clean_line = line.strip() # Trim whitespace
        name = clean_line.split('/')[0]
        ver = clean_line.split('now ')[1] # 0.6.45-1ubuntu1 amd64 [installed,automatic]
        ver = ver.split(' ')[0] # 0.6.45-1ubuntu1
        return (name, ver)

    @staticmethod
    def parse_all_pkgs(iterable):
        '''
        Parses an iterable of apt list --installed style output.
        Returns a dictionary of package versions keyed on package name.
        '''
        packages = {}
        for line in iterable:
            if re.match(r'Listing', line):
                continue
            pkg_name, pkg_ver = UbuntuAnalyzer.parse_pkg_line(line)
            packages[pkg_name] = pkg_ver
        return packages


    def get_packages(self):
        '''
        Gets all packages and versions from the target system.
        '''
        super().get_packages()
        _, stdout, _ = self.ssh_client.exec_command(UbuntuAnalyzer.LIST_INSTALLED)
        self.all_packages = UbuntuAnalyzer.parse_all_pkgs(stdout)
        # Note that this is a shallow copy; if you add more info to the dictionaries later on,
        # you'll have to change this.
        self.install_packages = self.all_packages.copy()
        logging.debug(self.all_packages)


    def get_dependencies(self, package):
        '''
        TODO: this function is never called, and it's for rpm besides
        NEVER CALLED :/
        Gets the dependencies of a particular package on the target system. (Currently uses rpm.)
        package -- the package to get deps for
        '''
        super().get_dependencies(package)
        # Issue--/bin/sh doesn't look like a package to me. what do we do about that?
        _, stdout, _ = self.ssh_client.exec_command(f"rpm -qR {package}")
        # I have no idea which regex is correct--one takes me from 420 to 256 and the other goes to
        # 311
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
        _, stdout, _ = self.ssh_client.exec_command(f"cat /var/lib/dpkg/info/{package}.conffiles")
        configs = {line.strip() for line in stdout}
        logging.debug(f"{package} has the following config files: {configs}")
        return configs

    def assemble_packages(self):
        '''
        Assembles all packages and versions (if applicable) into a string for installer, and returns
        the string.
        '''
        install_all = ""
        for name, ver in self.install_packages.items():
            if ver:
                install_all += f"{name}={ver} "
            else:
                install_all += f"{name} "
        return install_all

    def verify_packages(self, mode=SystemAnalyzer.Mode.dry):
        '''
        Looks through package list to see which packages are uninstallable.
        mode -- in dry mode, just log bad pkgs. in delete mode, delete bad pkgs from the list.
                in unversion mode, unspecify version.
        Returns True if all packages got installed correctly; returns False otherwise.
        '''
        logging.info(f"Verifying packages in {mode.name} mode...")
        # Write prelude, create image.
        with open(os.path.join(self.tempdir, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}\n")
            dockerfile.write(f"ENV DEBIAN_FRONTEND=noninteractive\n")
            dockerfile.write(f"RUN apt-get update\n")
            # I know this is supposed to go on the same line as the installs normally, but
        self.image, _ = self.docker_client.images.build(tag=f'verify{self.operating_sys}',
                                                        path=self.tempdir)

        # Try installing all of the packages.
        install_all = "apt-get -y install "
        install_all += self.assemble_packages()

        # Spin up the container and let it do its thing.
        container = self.docker_client.containers.run(self.image.id, command=install_all,
                                                      detach=True)
        container.wait()

        # Parse the container's output.
        missing_pkgs = re.findall("E: Unable to locate package (.*)\n", container.logs().decode())
        missing_vers = re.findall("' for '(.*)' was not found\n", container.logs().decode())

        if not re.search("E: ", container.logs().decode()):
            logging.info("All packages installed properly.")
            container.remove()
            return True

        if not missing_pkgs and not missing_vers:
            logging.error("No missing packages or versions found, but there was an error:\n"
                          f"{container.logs().decode()}")
            # Intentionally not removing the container for debugging purposes.
            return False

        # Report on missing packages.
        logging.warning(f"Could not find the following packages: {missing_pkgs}")
        logging.warning(f"Could not find versions for the following packages: {missing_vers}")
        if mode == self.Mode.unversion:
            logging.info(f"Now removing version numbers from bad packages...")
            for pkg_name in missing_vers:
                self.install_packages[pkg_name] = False
        elif mode == self.Mode.delete:
            logging.info(f"Now removing bad packages...")
            for pkg_name in itertools.chain(missing_pkgs, missing_vers):
                del self.install_packages[pkg_name]

        container.remove()
        return False



    def dockerize(self, folder, verbose=True):
        '''
        Creates Dockerfile from parameters discovered by the class.
        Make sure to call all analysis functions beforehand; this function doesn't actually check
        for that.
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


def group_strings(indexable, char_count=100000):
    '''
    Group the indexable into a set of space-separated strings. There will be char_count characters
    or fewer in each string.
    '''
    return_set = set()
    curr_string = ""
    for item in indexable:
        if len(curr_string) > char_count:
            return_set.add(curr_string)
            curr_string = ""
        curr_string += item + " "
    if curr_string:
        return_set.add(curr_string)
    logging.error(f"COUNT: {len(return_set)}")
    return return_set


if __name__ == "__main__":
    logging.info('Beginning analysis...')
    with GeneralAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME) as kowalski:
        kowalski.analyzer.get_packages()
        kowalski.analyzer.filter_packages()
        for md in (SystemAnalyzer.Mode.dry, SystemAnalyzer.Mode.unversion,
                   SystemAnalyzer.Mode.delete):
            if kowalski.analyzer.verify_packages(mode=md):
                break
        kowalski.analyzer.dockerize(tempfile.mkdtemp())
        kowalski.analyzer.analyze_files(['/bin/', '/etc/', '/lib/', '/opt/', '/sbin/', '/usr/'])
        kowalski.analyzer.get_config_differences()
