'''
UbuntuAnalyzer inherits from SystemAnalyzer and contains methods to analyze Ubuntu/apt systems.
'''

import itertools
import logging
import os
import re

import requests.exceptions

from .system import SystemAnalyzer



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
            return False
        finally:
            container.remove()


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
