# Minimal Kali with support for ssh and that's about it. 

# This is the only version they maintain; hopefully it's all good
FROM kalilinux/kali-rolling:latest
RUN apt-get update && apt-get -y install openssh-server
RUN groupadd sshgroup && useradd -ms /bin/bash -g sshgroup sshuser
ARG home=/home/sshuser
RUN mkdir $home/.ssh
COPY test_rsa.pub $home/.ssh/authorized_keys
RUN chown sshuser:sshgroup $home/.ssh/authorized_keys && \
    chmod 600 $home/.ssh/authorized_keys
CMD service ssh start && tail -f dev/null
