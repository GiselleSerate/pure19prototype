from paramiko import SSHClient
import os

HOSTNAME = '127.0.0.1'
HOSTPORT = 2222
USERNAME = 'root'

client = SSHClient()
client.load_system_host_keys()
client.connect(HOSTNAME, port=HOSTPORT, username=USERNAME, key_filename=os.path.expanduser("~/.ssh/id_rsa"))
stdin, stdout, stderr = client.exec_command('ls -l')
for line in stdout:
	print(f"Here's a line: {line}")
client.close()