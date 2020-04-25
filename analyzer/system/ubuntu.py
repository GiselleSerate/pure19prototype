'''
UbuntuAnalyzer inherits from SystemAnalyzer and contains methods to analyze Ubuntu/apt systems.
'''

import itertools
import logging
import os
import re

import requests.exceptions

from .system import SystemAnalyzer
from ..utils import group_strings



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
            if line == '':
                continue
            if re.match(r'WARNING:', line):
                continue
            if re.match(r'Listing', line):
                continue
            pkg_name, pkg_ver = UbuntuAnalyzer.parse_pkg_line(line)
            packages[pkg_name] = pkg_ver
        return packages

    def list_files_in_packages(self, pkgs):
        '''
        Takes an iterable of packages.
        Gets the list of files installed as part of each package.
        Returns a list of lists of filenames.
        '''
        files = [[]] * len(pkgs)
        i = -1
        pkg_strings = group_strings(pkgs)

        temp = []
        for pkg_string in pkg_strings:
            _, stdout, _ = self.ssh_client.exec_command(f"dpkg-query -L {pkg_string}")
            for line in stdout:
                line = line.strip()
                if re.search("is not installed", line):
                    #do nothing
                    ...
                elif re.search("contains no files", line):
                    # do nothing
                    ...
                elif line == '':
                    #do nothing
                    ...
                elif line == '/.':
                    files[i] = temp
                    temp = []
                    i += 1
                else:
                    temp.append(line)
        files[i] = temp

        # remove directories from 'files'
        for file_list in files:
            for file in file_list:
                split = file.split('/')
                if len(split) >= 3:
                    try:
                        file_list.remove('/'.join(split[:-1]))
                    except ValueError:
                        pass
        return files

    def files_changed_from_package(self, pkg):
        '''
        Returns the list of files coming from pkg whose checksums don't match their original
        checksums.
        '''
        files = []
        _, stdout, _ = self.ssh_client.exec_command(f"dpkg --verify {pkg}")
        for line in stdout:
            if re.search("is not installed", line):
                return []
            if re.search("contains no files", line):
                return []
            if '5' in line.split()[0]:
                files.append(line.split()[2].strip())
        return files


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
        Gets the dependencies of a particular package on the target system using apt-cache.
        package -- the package to get deps for
        '''
        super().get_dependencies(package)
        _, stdout, _ = self.ssh_client.exec_command(f"apt-cache depends {package}")
        deps = {line.split("Depends:")[1].strip() for line in stdout if "Depends:" in line}
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
        assert self.install_packages, "No packages yet. Have you run get_packages?"
        logging.info(f"Verifying packages in {mode.name} mode...")
        # Write prelude, create image.
        with open(os.path.join(self.tempdir, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.op_sys}:{self.version}\n")
            dockerfile.write(f"ENV DEBIAN_FRONTEND=noninteractive\n")
            dockerfile.write(f"RUN apt-get update\n")
            # I know this is supposed to go on the same line as the installs normally, but
        self.image, _ = self.docker_client.images.build(tag=f'verify{self.op_sys}',
                                                        path=self.tempdir)

        # Try installing all of the packages.
        install_all = "apt-get -y install "
        install_all += self.assemble_packages()

        try:
            # Spin up the container and let it do its thing.
            container = self.docker_client.containers.run(self.image.id, command=install_all,
                                                          detach=True)
            container.wait()

            # Parse the container's output.
            missing_pkgs = re.findall("E: Unable to locate package (.*)\n",
                                      container.logs().decode())
            missing_vers = re.findall("' for '(.*)' was not found\n", container.logs().decode())

            if not re.search("E: ", container.logs().decode()):
                logging.info("All packages installed properly.")
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
            return False
        finally:
            container.remove(force=True)


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
            dockerfile.write(f"FROM {self.op_sys}:{self.version}\n")

            dockerfile.write(f"ENV DEBIAN_FRONTEND=noninteractive\n")

            dockerfile.write(f"RUN apt-get update && apt-get install -y ")
            dockerfile.write(self.assemble_packages())
            dockerfile.write("\n")
        if verbose:
            logging.info(f"Your Dockerfile is in {folder}")
