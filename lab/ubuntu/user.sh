#!/bin/bash
set -euo pipefail

# Ubuntu Server Hardening Script
# Based on CIS Benchmark and DISA STIG

echo "Creating New User..."


# Create k8admin user
adduser --gecos '' --disabled-password k8admin
echo 'k8admin:M0rB0ss@84' | chpasswd
usermod -aG sudo k8admin

# Set up SSH keys for k8admin
mkdir -p /home/k8admin/.ssh
chmod 700 /home/k8admin/.ssh

# Add your public SSH key here
cat > /home/k8admin/.ssh/authorized_keys << 'SSHKEY'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBUEBpd8uyg2y72qrvyNdWaKFMsyze4PtN4epu/4ad31 murtadah.haddad@gmail.com
SSHKEY

chmod 600 /home/k8admin/.ssh/authorized_keys
chown -R k8admin:k8admin /home/k8admin/.ssh