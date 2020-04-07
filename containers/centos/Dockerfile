# Minimal CentOS with support for ssh and that's about it. 

FROM centos/systemd

RUN echo "pass" | passwd root --stdin
RUN yum -y install openssh-server openssh-clients
ARG home=/root
COPY test_rsa.pub $home/.ssh/authorized_keys
RUN chown root:root $home/.ssh/authorized_keys && \
    chmod 600 $home/.ssh/authorized_keys

RUN sed -i 's/#PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config
RUN /usr/bin/ssh-keygen -A
ENTRYPOINT /usr/sbin/sshd -D