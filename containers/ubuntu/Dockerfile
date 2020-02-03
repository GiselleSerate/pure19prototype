# Minimal Ubuntu with support for ssh and that's about it. 

FROM ubuntu:16.04
RUN apt-get update && apt-get -y install openssh-server
RUN groupadd sshgroup && useradd -ms /bin/bash -g sshgroup sshuser
ARG home=/home/sshuser
RUN mkdir $home/.ssh
COPY test_rsa.pub $home/.ssh/authorized_keys
RUN chown sshuser:sshgroup $home/.ssh/authorized_keys && \
    chmod 600 $home/.ssh/authorized_keys
CMD service ssh start && tail -f dev/null
