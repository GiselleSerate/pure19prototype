# Proof of concept: here's a pretty basic thing to say "we can actually get stuff over SSH"

import re

from paramiko import SSHClient



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
HOSTPORT = 2222
USERNAME = 'root'



if __name__ == "__main__":
    client = SSHClient()
    # Explore ~/.ssh/ for keys
    client.load_system_host_keys()
    # Establish SSH connection
    client.connect(HOSTNAME, port=HOSTPORT, username=USERNAME)

    # GET OS
    stdin, stdout, stderr = client.exec_command('cat /etc/os-release')
    # Extract operating system and version
    for line in stdout:
        if re.match(r'ID=', line):
            operating_sys = line.split('=')[1].split('"')[1]
        elif re.match(r'VERSION_ID=', line):
            version = line.split('=')[1].split('"')[1]
    print(f"FROM {operating_sys}:{version}")


    # GET PACKAGES
    if operating_sys == 'centos':
        stdin, stdout, stderr = client.exec_command('yum list installed')
        for line in stdout:
            print(line.strip())
    else:
        raise Exception(f"Unsupported operating system {operating_sys}: we don't know what package manager you're using.")

    # Make sure you kill the connection when you're done
    client.close()
