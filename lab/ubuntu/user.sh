#!/usr/bin/env bash
#
# set-static-ip-interactive.sh
# Description: Set new user, add ssh key
# Compatible with: Ubuntu 20.04, 22.04, 24.04 (Focal, Jammy, Noble)
#

set -euo pipefail

# === ROOT CHECK ===
if [[ $EUID -ne 0 ]]; then
    echo "❌ Please run as root: sudo $0"
    exit 1
fi

# === INTRO ===
echo "============================================"
echo "   🧠 Ubuntu Hostname and Static IP Config   "
echo "============================================"

# === PROMPTS ===
read -rp "Enter new Password: " PASSWORD

# === VALIDATION ===
if [[ -z "$PASSWORD"  ]]; then
    echo "❌ Password is required are required."
    exit 1
fi

# Ubuntu Server Hardening Script
# Based on CIS Benchmark and DISA STIG

echo "Creating New User..."


# Create k8admin user
adduser --gecos '' --disabled-password k8admin
echo 'k8admin:$PASSWORD' | chpasswd
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