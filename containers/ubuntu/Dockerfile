# Minimal Ubuntu with support for ssh and that's about it. 

FROM ubuntu:20.04

RUN apt-get update && apt-get -y install openssh-server
RUN echo "root:pass" | chpasswd
ARG home=/root
COPY test_rsa.pub $home/.ssh/authorized_keys
RUN chown root:root $home/.ssh/authorized_keys && \
    chmod 600 $home/.ssh/authorized_keys

# Workaround for: https://askubuntu.com/questions/1110828/ssh-failed-to-start-missing-privilege-separation-directory-var-run-sshd
RUN mkdir /run/sshd && chmod 0755 /run/sshd
RUN sed -i 's/#PermitRootLogin/PermitRootLogin/g' /etc/ssh/sshd_config
RUN /usr/bin/ssh-keygen -A
ENTRYPOINT /usr/sbin/sshd -D
CMD service ssh start && tail -f dev/null
