'''
Provides a general analysis tool to analyze an SSHable system from the ground up and convert it to a
container.

GeneralAnalyzer begins from no knowledge and sets up an environment to look at a system.
'''

import logging
import re

import docker
from paramiko import AutoAddPolicy, SSHClient
from paramiko.ssh_exception import NoValidConnectionsError

from . import HOST
from .utils import OpSysError, OrigSysConnError # TODO: PermissionsError
from .system.centos import CentosAnalyzer
from .system.ubuntu import UbuntuAnalyzer



class GeneralAnalyzer:
    '''Does all analysis of a system that you know nothing about.'''
    def __init__(self, host=HOST, auto_add=False):
        self.ssh_client = SSHClient()
        if auto_add:
            self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        self.host = host

        self.docker_client = docker.from_env()

        self.op_sys = None
        self.version = None

        self.analyzer = None


    def __enter__(self):
        # Explore ~/.ssh/ for keys
        self.ssh_client.load_system_host_keys()
        # Establish SSH connection
        try:
            self.ssh_client.connect(self.host.hostname, port=self.host.port,
                                    username=self.host.username)
        except NoValidConnectionsError:
            raise OrigSysConnError("Can't connect to the system you want to replicate. Is it up?")

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
                op_sys = line.split('=')[1]
        self.op_sys = op_sys
        self.version = version


    def get_analyzer(self):
        '''
        Creates an instance of the applicable SystemAnalyzer child class based on
        self.op_sys.
        '''
        if self.op_sys == 'centos':
            self.analyzer = CentosAnalyzer(self.ssh_client, self.docker_client, self.op_sys,
                                           self.version)
        elif self.op_sys == 'ubuntu':
            self.analyzer = UbuntuAnalyzer(self.ssh_client, self.docker_client, self.op_sys,
                                           self.version)
        else:
            raise OpSysError(f"Unknown operating system {self.op_sys}. This likely means we "\
                             f"haven't written a SystemAnalyzer child class for this system yet.")
