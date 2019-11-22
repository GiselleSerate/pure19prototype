# Proof of concept: here's a pretty basic thing to say "we can actually get stuff over SSH"

from paramiko import SSHClient
import os

# Constants (which we can move into a config file later)
HOSTNAME = '127.0.0.1'
HOSTPORT = 2222
USERNAME = 'root'

client = SSHClient()
# Explore ~/.ssh/ for keys
client.load_system_host_keys()
# Establish SSH connection
client.connect(HOSTNAME, port=HOSTPORT, username=USERNAME, key_filename=os.path.expanduser("~/.ssh/id_rsa"))
# Run command on server
stdin, stdout, stderr = client.exec_command('ls -l')
# These are now all files and you can treat them as such; do fancy regex stuff or whatever
for line in stdout:
	print(f"Here's a line: {line}")
# Make sure you kill the connection when you're done
client.close()