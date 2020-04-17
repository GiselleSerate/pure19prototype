'''
CentosAnalyzer inherits from SystemAnalyzer and contains methods to analyze CentOS/yum systems.
'''

import logging
import os
import re

import requests.exceptions

from .system import SystemAnalyzer
from ..utils import group_strings




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

    def list_files_in_packages(self, pkgs):
        '''
        Takes an iterable of packages.
        Gets the list of files installed as part of each package.
        Returns a list of lists of filenames.
        '''
        files = [[]] * len(pkgs)
        i = 0
        pkg_strings = group_strings(pkgs)
        cmd_strings = []
        for pkg_string in pkg_strings:
            cmd_string = ""
            for pkg in pkg_string.split():
                cmd_string += f" && echo \"\" && rpm -ql {pkg}"
            cmd_strings.append(cmd_string[15:])

        temp = []
        for cmd in cmd_strings:
            _, stdout, _ = self.ssh_client.exec_command(cmd)
            for line in stdout:
                line = line.strip()
                if re.search("is not installed", line):
                    #do nothing
                    ...
                elif re.search("contains no files", line):
                    # do nothing
                    ...
                elif line == '':
                    files[i] = temp
                    temp = []
                    i += 1
                else:
                    temp.append(line)
            files[i] = temp
            temp = []
            i += 1

        return files

    def files_changed_from_package(self, pkg):
        '''
        Returns the list of files coming from pkg whose checksums don't match their original
        checksums.
        '''
        files = []
        _, stdout, _ = self.ssh_client.exec_command(f"rpm -V {pkg}")
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
            dockerfile.write(f"FROM {self.op_sys}:{self.version}\n")

            # Normal installs
            if self.install_packages:
                dockerfile.write(f"RUN yum -y install ")
                for name, ver in self.install_packages.items():
                    if ver:
                        dockerfile.write(f"{name}-{ver} ")
                dockerfile.write("\n")

            # Unversioned packages: original ver in comment, installed ver in yum line
            if self.unversion_packages:
                comment = "# Original versions: "
                install_line = "RUN yum -y install "
                for name, new_ver in self.unversion_packages.items():
                    old_ver = self.all_packages[name]
                    if new_ver:
                        comment += f"{name}: {old_ver}->{new_ver} "
                        install_line += f"{name}-{new_ver} "
                    else:
                        comment += f"{name}: {old_ver}->? "
                        install_line += f"{name} "
                dockerfile.write(comment + '\n')
                dockerfile.write(install_line + '\n')

        if verbose:
            logging.info(f"Your Dockerfile is in {folder}")
