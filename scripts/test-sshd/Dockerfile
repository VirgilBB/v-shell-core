# Throwaway sshd for integration tests only. Test credentials are public on purpose.
FROM alpine:3.22
RUN apk add --no-cache openssh tmux bash \
 && adduser -D -s /bin/bash vshell && echo 'vshell:vshell-test' | chpasswd \
 && ssh-keygen -A \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
