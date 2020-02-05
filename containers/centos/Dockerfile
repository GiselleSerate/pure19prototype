# Minimal CentOS with support for ssh and that's about it. 

FROM centos/systemd

RUN yum -y install openssh-server openssh-clients
RUN groupadd sshgroup && useradd -ms /bin/bash -g sshgroup sshuser
ARG home=/home/sshuser
RUN mkdir $home/.ssh
COPY test_rsa.pub $home/.ssh/authorized_keys
RUN chown sshuser:sshgroup $home/.ssh/authorized_keys && \
    chmod 600 $home/.ssh/authorized_keys
RUN /usr/bin/ssh-keygen -A
ENTRYPOINT /usr/sbin/sshd -D