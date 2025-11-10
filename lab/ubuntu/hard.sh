#!/usr/bin/env bash
#
# Ubuntu Server Hardening Script
# Target: Ubuntu 22.04 / 24.04 (Jammy / Noble)
# Author: Murtadah’s paranoid side 😄
#
# What it does:
# - Calls user.sh (create secure admin user)
# - Calls set-static-ip-interactive.sh (convert current IP to static)
# - Sets timezone to Asia/Baghdad + enables NTP
# - SSH hardening (port 2222, no root login, key-only, strong ciphers)
# - UFW firewall + Fail2Ban
# - Unattended upgrades
# - Kernel hardening (sysctl)
# - Auditd rules (immutable)
# - Password policy (pwquality + PAM)
# - Filesystem hardening
# - AppArmor, AIDE, logrotate
# - Security monitoring script + cron
# - Lynis quick audit
#

set -euo pipefail

#############################################
# Root Check
#############################################
if [[ $EUID -ne 0 ]]; then
    echo "❌ Please run as root: sudo $0"
    exit 1
fi

#############################################
# Logging
#############################################
LOGFILE="/var/log/hardening.log"
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"
chmod 600 "$LOGFILE"

exec > >(tee -a "$LOGFILE") 2>&1

echo "========================================"
echo "  🚀 Starting Ubuntu Server Hardening"
echo "========================================"

#############################################
# Timezone & NTP
#############################################
echo "🕒 Setting timezone to Asia/Baghdad & enabling NTP..."
timedatectl set-timezone Asia/Baghdad || echo "⚠️ Failed to set timezone."
timedatectl set-ntp true || echo "⚠️ Failed to enable NTP."

#############################################
# Run user.sh (create secure admin user)
#############################################
if [[ -f ./user.sh ]]; then
    echo "👤 Running user.sh to create secure user..."
    chmod +x ./user.sh
    ./user.sh
else
    echo "⚠️ user.sh not found. Skipping user creation."
fi

#############################################
# Run set-static-ip-interactive.sh
#############################################
apt update && apt install -y iproute2 systemd systemd-sysv dbus
if [[ -f ./set-static-ip-interactive.sh ]]; then
    echo "🌐 Running set-static-ip-interactive.sh to configure static IP..."
    chmod +x ./set-static-ip-interactive.sh
    ./set-static-ip-interactive.sh
else
    echo "⚠️ set-static-ip-interactive.sh not found. Skipping static IP config."
fi

#############################################
# System Update
#############################################
echo "📦 Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

#############################################
# Install Security & Utility Packages
#############################################
echo "📦 Installing security tooling..."
apt-get install -y \
    openssh-server \
    ufw \
    fail2ban \
    unattended-upgrades \
    apt-listchanges \
    auditd \
    apparmor \
    apparmor-utils \
    aide \
    rkhunter \
    lynis \
    libpam-pwquality \
    libpam-tmpdir \
    mailutils \
    cron \
    rsyslog

systemctl enable ssh --now

#############################################
# SSH Hardening
#############################################
echo "🔐 Hardening SSH..."

SSHD_CFG="/etc/ssh/sshd_config"
SSHD_BAK="/etc/ssh/sshd_config.bak.$(date +%s)"
cp "$SSHD_CFG" "$SSHD_BAK"

cat > "$SSHD_CFG" << 'EOF'
Port 2222
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
SyslogFacility AUTH
AllowUsers k8admin
EOF

# Test SSH config before restart
if sshd -t 2>/dev/null; then
    systemctl restart ssh || systemctl restart sshd
else
    echo "❌ sshd_config invalid. Restoring backup."
    cp "$SSHD_BAK" "$SSHD_CFG"
    systemctl restart ssh || systemctl restart sshd
fi

#############################################
# UFW Firewall
#############################################
echo "🛡️ Configuring UFW..."
ufw default deny incoming
ufw default allow outgoing
ufw logging on
ufw allow 2222/tcp comment 'SSH Hardened'
ufw --force enable

#############################################
# Fail2Ban
#############################################
echo "🧱 Configuring Fail2Ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
destemail = murtadah.haddad@gmail.com
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[sshd-aggressive]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
findtime = 300
bantime = 86400
EOF

systemctl enable fail2ban
systemctl restart fail2ban || echo "⚠️ Fail2Ban restart failed."

#############################################
# Unattended Upgrades
#############################################
echo "🔄 Configuring unattended upgrades..."

if command -v lsb_release >/dev/null 2>&1; then
    DISTRO_ID=$(lsb_release -is)
    DISTRO_CODENAME=$(lsb_release -cs)
else
    # Fallback
    . /etc/os-release
    DISTRO_ID=$ID
    DISTRO_CODENAME=$VERSION_CODENAME
fi

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "${DISTRO_ID}:${DISTRO_CODENAME}";
    "${DISTRO_ID}:${DISTRO_CODENAME}-security";
    "${DISTRO_ID}:${DISTRO_CODENAME}-updates";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "murtadah.haddad@gmail.com";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

#############################################
# Kernel / sysctl Hardening
#############################################
echo "⚙️ Applying kernel hardening (sysctl)..."

cat > /etc/sysctl.d/99-security.conf << 'EOF'
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.printk = 3 3 3 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.unprivileged_userns_clone = 0
kernel.perf_event_paranoid = 3

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.ip_forward = 0

fs.file-max = 65535
vm.swappiness = 1
EOF

sysctl --system

#############################################
# Auditd Configuration
#############################################
echo "📋 Configuring auditd..."

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
-D
-b 8192
-f 1

# Time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Identity files
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network
-a always,exit -F arch=b32 -S sethostname,setdomainname -k network
-w /etc/issue -p wa -k network
-w /etc/issue.net -p wa -k network
-w /etc/hosts -p wa -k network
-w /etc/network -p wa -k network

# Mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# File deletions
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Perm / ownership changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

-e 2
EOF

systemctl enable auditd
systemctl restart auditd || echo "⚠️ auditd restart failed."

#############################################
# Password Policy (pwquality + PAM)
#############################################
echo "🔑 Configuring password policy..."

cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 2
maxsequence = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF

# Harden PAM common-password (Debian/Ubuntu)
if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    sed -i 's#^password\s\+.*pam_unix.so.*#password required pam_unix.so obscure sha512 remember=5 rounds=65536#' /etc/pam.d/common-password
fi

#############################################
# Filesystem Hardening
#############################################
echo "📂 Hardening filesystem permissions..."

chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

# Disable core dumps
cat > /etc/security/limits.d/10-no-core.conf << 'EOF'
* hard core 0
EOF

cat > /etc/sysctl.d/10-no-core.conf << 'EOF'
fs.suid_dumpable = 0
EOF

sysctl --system

#############################################
# AppArmor
#############################################
echo "🛡️ Enforcing AppArmor..."
systemctl enable apparmor || true
systemctl start apparmor || true
aa-enforce /etc/apparmor.d/* || true

#############################################
# AIDE (File Integrity)
#############################################
echo "🔍 Initializing AIDE..."
aideinit || true
if [[ -f /var/lib/aide/aide.db.new ]]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report $(hostname)" murtadah.haddad@gmail.com || true
EOF
chmod +x /etc/cron.daily/aide

#############################################
# Disable Unnecessary Services
#############################################
echo "🚫 Disabling unnecessary services..."
for svc in avahi-daemon cups isc-dhcp-server isc-dhcp-server6 nfs-server rpcbind rsync snmpd; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl stop "$svc" 2>/dev/null || true
done

#############################################
# Security Limits
#############################################
cat > /etc/security/limits.d/99-security.conf << 'EOF'
* soft nproc 1024
* hard nproc 2048
* soft nofile 65535
* hard nofile 65535
EOF

#############################################
# Logrotate for Security Logs
#############################################
cat > /etc/logrotate.d/security << 'EOF'
/var/log/auth.log
/var/log/syslog
{
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
}
EOF

#############################################
# Security Monitoring Script
#############################################
echo "📝 Creating security-check.sh..."

cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
REPORT="/tmp/security-report.txt"
{
echo "Security Report - $(date)"
echo "============================="

echo -e "\n=== Failed Login Attempts ==="
grep "Failed password" /var/log/auth.log | tail -20 || true

echo -e "\n=== Firewall Status ==="
ufw status verbose || true

echo -e "\n=== Listening Services ==="
ss -tulpn || true

echo -e "\n=== Recent sudo commands ==="
grep "sudo" /var/log/auth.log | tail -20 || true

echo -e "\n=== Disk Usage ==="
df -h

echo -e "\n=== Fail2Ban Status ==="
fail2ban-client status || true
} > "$REPORT"

mail -s "Security Report $(hostname)" murtadah.haddad@gmail.com < "$REPORT" || true
EOF

chmod +x /usr/local/bin/security-check.sh

cat > /etc/cron.d/security-check << 'EOF'
0 2 * * 0 root /usr/local/bin/security-check.sh
EOF

#############################################
# Lynis Quick Audit
#############################################
echo "🔎 Running Lynis quick audit (non-fatal)..."
lynis audit system --quick || true

#############################################
# Final Message
#############################################
echo "========================================"
echo "✅ Hardening Complete!"
echo "SSH now on port 2222 with key-only login."
echo "Timezone: Asia/Baghdad"
echo "Logs: $LOGFILE"
echo "⚠️ IMPORTANT: Test SSH on port 2222 BEFORE closing your current session."
echo "⚠️ Recommended: Reboot the system to apply all changes."
echo "========================================"
