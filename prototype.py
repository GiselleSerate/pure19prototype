# Proof of concept: here's a pretty basic thing to say "we can actually get stuff over SSH"

import os
import re
import tempfile

from paramiko import SSHClient
# from tempfile import mkdtemp



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
PORT = 2222
USERNAME = 'root'



class SystemAnalyzer:
    def __init__(self, hostname=HOSTNAME, port=PORT, username=USERNAME):
        self.client = SSHClient()
        # Explore ~/.ssh/ for keys
        self.client.load_system_host_keys()
        # Establish SSH connection
        self.client.connect(hostname, port=port, username=username)

        self.operating_sys = None
        self.version = None
        self.packages = []

        self.dir = tempfile.mkdtemp()

    def __del__(self):
        # Make sure you kill the connection when you're done
        self.client.close()

    def get_os(self):
        print("Getting operating system and version...")
        stdin, stdout, stderr = self.client.exec_command('cat /etc/os-release')
        # Extract operating system and version
        for line in stdout:
            if re.match(r'ID=', line):
                operating_sys = line.split('=')[1].split('"')[1]
            elif re.match(r'VERSION_ID=', line):
                version = line.split('=')[1].split('"')[1]
        self.operating_sys = operating_sys
        self.version = version
        print(f"FROM {operating_sys}:{version}")

    def get_packages(self):
        print("Getting packages...")
        while self.operating_sys == None:
            print("No operating system yet.")
            self.get_os()
        if self.operating_sys == 'centos':
            stdin, stdout, stderr = self.client.exec_command("rpm -qa --queryformat '%{NAME}\n'")
            self.packages = [line.strip() for line in stdout]
            print(self.packages)
        else:
            raise Exception(f"Unsupported operating system {operating_sys}: we don't know what package manager you're using.")

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
            print(f"proto:{proto} recv_q:{recv_q} send_q:{send_q} local:{local} foreign:{foreign} state:{state} pid:{pid} progname:{progname}")

    def get_procs(self):
        # Normally we'd have to grep out the command we ran, but we don't have to because ssh. 
        # stdin, stdout, stderr = client.exec_command('ps -ao pid,cmd')
        stdin, stdout, stderr = self.client.exec_command('ps -eo pid,cmd')
        # stdin, stdout, stderr = client.exec_command('ps -aux')
        for line in stdout:
            if not re.match(r'[0-9]+', line.split()[0]):
                continue
            print(line.rstrip())

    def dockerize(self):
        with open(os.path.join(self.dir, 'Dockerfile'), 'w') as dockerfile:
            dockerfile.write(f"FROM {self.operating_sys}:{self.version}")
        print(f"Your Dockerfile is in {self.dir}")



if __name__ == "__main__":
    kowalski = SystemAnalyzer(hostname=HOSTNAME, port=PORT, username=USERNAME)
    kowalski.get_os()
    kowalski.get_packages()
    kowalski.get_ports()
    kowalski.get_procs()
    kowalski.dockerize()
