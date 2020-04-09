'''
SystemAnalyzer is an abstract base class which may be extended to create more specific analyzers
    for certain OSs or package managers.
'''

import logging
import tempfile

from abc import ABC, abstractmethod
from enum import Enum
import requests.exceptions

from ..utils import analyze_dependencies, DockerDaemonError, group_strings



class SystemAnalyzer(ABC):
    '''
    Does analysis of a system that you know some information about. Use as a base class where child
    classes know about more specific systems.
    '''
    Mode = Enum('Mode', 'dry unversion delete')

    def __init__(self, ssh_client, docker_client, op_sys, version):
        self.ssh_client = ssh_client
        self.docker_client = docker_client

        self.op_sys = op_sys
        self.version = version
        logging.debug(f"FROM {op_sys}:{version}")
        try:
            self.image = self.docker_client.images.pull(f"{op_sys}:{version}")
        except requests.exceptions.ConnectionError as err:
            raise DockerDaemonError("Could not reach the Docker daemon. Is it on?")
        logging.info(f"Pulled {self.image} from Docker hub.")

        # All packages on the system (and versions)
        self.all_packages = {}
        # Only (and all) the packages we want to install (and versions)
        self.install_packages = {}
        # A list of packages (and their /new/ versions) that we installed on a version
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


    def filter_packages(self, strict_versioning=True):
        '''
        Removes packages from the list to be installed if they would be installed as a dependency of
        another or if they are already in the base image. Note that we leave them (and their
        versions) in self.all_packages.
        strict_versioning -- if True, we'll only remove the package if the versions match the base
            image, and we will NOT do dependency analysis.
        '''
        logging.info("Filtering packages...")
        assert self.all_packages, "No packages yet. Have you run get_packages?"

        # Optionally simplify the package list by analyzing dependencies.
        if not strict_versioning:
            pkgs_to_remove = analyze_dependencies(self.all_packages, self.get_dependencies)
            for pkg_name in pkgs_to_remove:
                del self.install_packages[pkg_name]
            logging.info(f"Removing extra packages based on dependency analysis cut down "
                         f"{len(self.all_packages)} packages to {len(self.install_packages)}.")

        # Get default-installed packages from Docker base image we're going to use
        pkg_bytestring = self.docker_client.containers.run(f"{self.op_sys}:{self.version}",
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

        logging.info(f"Removing defaults cut down {len(self.all_packages)} packages to "
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
        self.image, _ = self.docker_client.images.build(tag=f'verify{self.op_sys}',
                                                        path=self.tempdir)

        try:
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

            return there == total
        finally:
            container.remove()


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

        try:
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
                # In this case, the returned hash would just be the last thing hashed; not
                # meaningful, so don't return it.
                return None
            return crc
        finally:
            container.remove()


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


    def analyze_files(self, allowlist = {}, blocklist = {}):
        '''
        Analyze all subdirectories of places (list of directories). Determine how many are on the
        container/VM/both, and of the files in common which are different.
        Currently we just dump everything to logs; eventually we may want to return some of this.
        '''
        logging.info(f"Diffing subdirectories of {allowlist}")
        unique = {}
        for folder in allowlist:
            unique[folder] = self.compare_names([folder], blocklist)
        for folder, diff_tuple in unique.items():
            logging.info(f"{folder} has {len(diff_tuple[0])} files unique to the container, "
                         f"{len(diff_tuple[1])} files shared, and {len(diff_tuple[2])} files "
                         "unique to the VM")
            self.file_logger.info(f"PLACE: {folder}")
            self.file_logger.info(f"Just container ({len(diff_tuple[0])}):\n"
                                  f"{diff_tuple[0]}")
            self.file_logger.info(f"Shared ({len(diff_tuple[1])}):\n{diff_tuple[1]}")
            self.file_logger.info(f"Just VM ({len(diff_tuple[2])}):\n{diff_tuple[2]}")
            # Now cksum the shared ones
            modified_files = []
            for folder_str in group_strings(list(diff_tuple[1])):
                self.get_hash_from_container(folder_str, is_directory=False)
                self.get_hash_from_vm(folder_str, is_directory=False)
            for file in diff_tuple[1]:
                container_h = self.container_hashes[file]["hash"]
                vm_h = self.vm_hashes[file]["hash"]
                if container_h != vm_h:
                    modified_files.append(file)
            logging.info(f"In {folder}, {len(modified_files)} out of {len(diff_tuple[1])} files "
                         f"found on both systems were different.")
            logging.debug(f"These files in {folder} were different: {modified_files}")
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
        assert self.all_packages, "No packages yet. Have you run get_packages?"
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
        for file_group in group_strings(list(configs)):
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


    def compare_names(self, allowlist, blocklist):
        '''
        Takes an iterable of folders to look in for differences.
        Returns a tuple of filenames only on the container, filenames on both, and filenames only on
        the VM.
        '''
        docker_filenames = set()
        vm_filenames = set()
        blocklist_string = '\('
        for folder in blocklist:
            blocklist_string = blocklist_string + ' -name ' + folder + ' -o'
        blocklist_string = blocklist_string[:-2] + '\)'
        for folder in allowlist:
            _, stdout, _ = self.ssh_client.exec_command(f"find {folder} -type f  {blocklist_string} -prune")
            for line in stdout:
                vm_filenames.add(line.strip())
            try:
                container = self.docker_client.containers.run(image=self.image.id,
                                                              command=f"find {folder} -type f",
                                                              detach=True)
                container.wait()
                output = container.logs().decode()
            finally:
                container.remove()
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
        assert self.install_packages, "No packages yet. Have you run get_packages?"
        if verbose:
            logging.info("Creating Dockerfile...")
