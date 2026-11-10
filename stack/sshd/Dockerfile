FROM alpine:3.19

RUN apk add --no-cache openssh-server bash sudo

# Generate host keys
RUN ssh-keygen -A

# Create forge_admin user
RUN adduser -D -s /bin/bash forge_admin && \
    echo "forge_admin:forge_secret_pass" | chpasswd && \
    mkdir -p /home/forge_admin/.ssh && \
    chmod 700 /home/forge_admin/.ssh

# Generate a sample keypair for bastion access
RUN ssh-keygen -t rsa -b 2048 -f /home/forge_admin/.ssh/id_rsa -N "" && \
    cp /home/forge_admin/.ssh/id_rsa.pub /home/forge_admin/.ssh/authorized_keys && \
    chmod 600 /home/forge_admin/.ssh/authorized_keys && \
    chown -R forge_admin:forge_admin /home/forge_admin/.ssh

# Copy private key to easily accessible spot for testing
RUN cp /home/forge_admin/.ssh/id_rsa /etc/ssh/test_id_rsa && \
    chmod 644 /etc/ssh/test_id_rsa

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
