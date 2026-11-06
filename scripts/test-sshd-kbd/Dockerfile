# Mimics macOS Remote Login: publickey + keyboard-interactive (PAM), NO plain password.
FROM alpine:3.22
RUN apk add --no-cache openssh-server-pam openssh-keygen linux-pam tmux bash \
 && adduser -D -s /bin/bash vshell && echo 'vshell:vshell-test' | chpasswd \
 && ssh-keygen -A \
 && printf 'UsePAM yes\nKbdInteractiveAuthentication yes\nPasswordAuthentication no\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd.pam", "-D", "-e"]
