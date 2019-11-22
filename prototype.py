# Proof of concept: here's a pretty basic thing to say "we can actually get stuff over SSH"

import re

from paramiko import SSHClient



# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
HOSTPORT = 2222
USERNAME = 'root'



# TODO: this is a lot of sequential scripting. How do we feel about a class?
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
    # packages = [] # lol we aren't actually using this line are we
    if operating_sys == 'centos':
        stdin, stdout, stderr = client.exec_command('yum list installed')
        for line in stdout:
            # Skip not-data
            if not re.match(r'.+ +.+ +@[A-Za-z]+', line):
                continue
            pkg, ver, src = line.split()
            print(f"pkg:{pkg} ver:{ver} src:{src}")
    else:
        raise Exception(f"Unsupported operating system {operating_sys}: we don't know what package manager you're using.")

    # GET PORTS
    # TODO: How do I know I'm not getting my own port that I'm using for ssh? Is it just literally port 22?
    # What if we try to run this on something that uses 22?
    stdin, stdout, stderr = client.exec_command('netstat -lntp')
    for line in stdout:
        # Skip header
        if (re.match(r'Proto Recv-Q Send-Q Local', line)
            or re.match(r'Active Internet', line)):
            continue
        proto, recv_q, send_q, local, foreign, state, pid = line.split()
        pid, progname = pid.split('/')
        print(f"proto:{proto} recv_q:{recv_q} send_q:{send_q} local:{local} foreign:{foreign} state:{state} pid:{pid} progname:{progname}")

    # GET RUNNING PROCS
    # stdin, stdout, stderr = client.exec_command('ps -ao pid,cmd | grep -v \\ps -ao pid,cmd\\')
    # stdin, stdout, stderr = client.exec_command('ps -ao pid,cmd')
    stdin, stdout, stderr = client.exec_command('ps -aux')
    for line in stdout:
        print(line.rstrip())

    # Make sure you kill the connection when you're done
    client.close()
