#!/bin/bash
set -euo pipefail

# Ubuntu Server Hardening Script
# Based on CIS Benchmark and DISA STIG

echo "Starting Ubuntu Server Hardening..."

# Update system
apt-get update && apt-get upgrade -y

# Install security packages
apt-get install -y \
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
    libpam-tmpdir

#############################################
# SSH Hardening
#############################################
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
cat > /etc/ssh/sshd_config << 'EOF'
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
EOF

#############################################
# Firewall Configuration (UFW)
#############################################
ufw default deny incoming
ufw default allow outgoing
ufw logging on
ufw allow 2222/tcp comment 'SSH'
echo "y" | ufw enable

#############################################
# Fail2Ban Configuration
#############################################
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
systemctl restart fail2ban

#############################################
# Automatic Updates
#############################################
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}:${distro_codename}-updates";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
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
# Kernel Hardening (sysctl)
#############################################
cat > /etc/sysctl.d/99-security.conf << 'EOF'
# Kernel hardening
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

# Network security
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

# Increase system file descriptor limit
fs.file-max = 65535

# Discourage Linux from swapping idle processes to disk
vm.swappiness = 1
EOF

sysctl -p /etc/sysctl.d/99-security.conf

#############################################
# Audit Configuration (auditd)
#############################################
cat > /etc/audit/rules.d/audit.rules << 'EOF'
# Remove all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (2 = panic)
-f 1

# Audit time changes
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Audit user/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Audit network changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network
-a always,exit -F arch=b32 -S sethostname,setdomainname -k network
-w /etc/issue -p wa -k network
-w /etc/issue.net -p wa -k network
-w /etc/hosts -p wa -k network
-w /etc/network -p wa -k network

# Audit system calls
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Audit file deletions
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Audit sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Audit kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules

# Audit login/logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Audit session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Audit permission changes
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Make audit configuration immutable
-e 2
EOF

systemctl enable auditd
systemctl restart auditd

#############################################
# Password Policy
#############################################
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

# Configure PAM
sed -i 's/^password.*pam_unix.so.*/password required pam_unix.so obscure sha512 remember=5 rounds=65536/' /etc/pam.d/common-password

#############################################
# File System Hardening
#############################################
# Set secure permissions
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg

# Disable core dumps
cat > /etc/security/limits.d/10-no-core.conf << 'EOF'
* hard core 0
EOF

cat > /etc/sysctl.d/10-no-core.conf << 'EOF'
fs.suid_dumpable = 0
EOF

#############################################
# AppArmor
#############################################
systemctl enable apparmor
aa-enforce /etc/apparmor.d/*

#############################################
# AIDE (Intrusion Detection)
#############################################
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Schedule daily AIDE checks
cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report $(hostname)" murtadah.haddad@gmail.com
EOF
chmod +x /etc/cron.daily/aide

#############################################
# Disable Unnecessary Services
#############################################
systemctl disable avahi-daemon 2>/dev/null || true
systemctl disable cups 2>/dev/null || true
systemctl disable isc-dhcp-server 2>/dev/null || true
systemctl disable isc-dhcp-server6 2>/dev/null || true
systemctl disable nfs-server 2>/dev/null || true
systemctl disable rpcbind 2>/dev/null || true
systemctl disable rsync 2>/dev/null || true
systemctl disable snmpd 2>/dev/null || true

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
# Logrotate Configuration
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
}
EOF

#############################################
# Create Security Monitoring Script
#############################################
cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash

REPORT="/tmp/security-report.txt"
echo "Security Report - $(date)" > $REPORT
echo "=============================" >> $REPORT

echo -e "\n=== Failed Login Attempts ===" >> $REPORT
grep "Failed password" /var/log/auth.log | tail -20 >> $REPORT

echo -e "\n=== Firewall Status ===" >> $REPORT
ufw status >> $REPORT

echo -e "\n=== Listening Services ===" >> $REPORT
ss -tulpn >> $REPORT

echo -e "\n=== Recent sudo commands ===" >> $REPORT
grep sudo /var/log/auth.log | tail -20 >> $REPORT

echo -e "\n=== Disk Usage ===" >> $REPORT
df -h >> $REPORT

echo -e "\n=== Failed2ban Status ===" >> $REPORT
fail2ban-client status >> $REPORT

cat $REPORT | mail -s "Security Report $(hostname)" murtadah.haddad@gmail.com
EOF

chmod +x /usr/local/bin/security-check.sh

# Schedule weekly security checks
echo "0 2 * * 0 root /usr/local/bin/security-check.sh" > /etc/cron.d/security-check

#############################################
# Final Steps
#############################################
echo "Running security scan with Lynis..."
lynis audit system --quick

echo "=============================="
echo "Hardening Complete!"
echo "=============================="
echo "IMPORTANT: Reboot the system to apply all changes"
echo "Run 'lynis audit system' for detailed security audit"