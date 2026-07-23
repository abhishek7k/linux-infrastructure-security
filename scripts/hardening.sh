#!/usr/bin/env bash
#
# hardening.sh - Linux System Hardening & Security Compliance Script
# Target: Arch Linux / Debian / RHEL-based distributions
# Usage: sudo ./hardening.sh [--non-interactive]
#

# --- Visual Styling & Logging ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[*] $1${NC}"; }
log_success() { echo -e "${GREEN}[+] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[!] $1${NC}"; }
log_err() { echo -e "${RED}[-] ERROR: $1${NC}"; exit 1; }

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   log_err "This script must be run as root (sudo)."
fi

NON_INTERACTIVE=false
if [[ "$1" == "--non-interactive" ]]; then
    NON_INTERACTIVE=true
fi

log_info "Starting Linux System Hardening Process..."
log_warn "This script will modify system settings. Ensure backups are available."

if ! $NON_INTERACTIVE; then
    read -p "Do you want to proceed with hardening? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Hardening aborted by user."
        exit 0
    fi
fi

# --- 1. Enforce Password Policies & Least Privilege ---
log_info "1. Enforcing password policy and account restrictions..."

# Backup login.defs
if [ -f /etc/login.defs ]; then
    cp /etc/login.defs /etc/login.defs.bak
    # Enforce password expiration, length, and history parameters
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    log_success "Password expiration limits set (Max: 90 days, Min: 7 days, Warning: 14 days)."
fi

# Lock system/service accounts (those that do not require login shells)
log_info "Locking inactive system accounts..."
for user in bin daemon mail ftp news uucp nobody; do
    if id "$user" &>/dev/null; then
        usermod -s /sbin/nologin "$user" 2>/dev/null
        usermod -L "$user" 2>/dev/null
    fi
done
log_success "System accounts locked and shells set to nologin."

# --- 2. Secure File Permissions ---
log_info "2. Securing sensitive system file permissions..."

# Restrict permissions on sensitive configuration and credential files
chmod 0600 /etc/shadow
chmod 0600 /etc/gshadow
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chmod 0600 /etc/ssh/sshd_config 2>/dev/null

log_success "File permissions secured on credential stores."

# Restrict access to compilers to prevent local exploit compilation (Least Privilege)
if [ -f /usr/bin/gcc ]; then
    chmod 0700 /usr/bin/gcc
    log_success "Restricted access to GCC compiler."
fi

# --- 3. Hardening SSH Daemon ---
log_info "3. Hardening SSH Configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BAK="/etc/ssh/sshd_config.bak"

if [ -f "$SSHD_CONFIG" ]; then
    cp "$SSHD_CONFIG" "$SSHD_BAK"
    
    # Overwrite sshd_config with secure configurations
    cat << 'EOF' > "$SSHD_CONFIG"
# Hardened SSH Daemon Configuration
Port 2222
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Authentication
LoginGraceTime 30
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2

# Public Key Authentication Only
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Access Control & Shell
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:100
Banner /etc/issue
EOF
    
    log_success "Hardened sshd_config deployed. Port configured to 2222, root login disabled, key-only authentication enforced."
    
    # Reload SSH service if it's running
    if systemctl is-active sshd &>/dev/null; then
        systemctl restart sshd
        log_success "SSHD service restarted."
    elif systemctl is-active ssh &>/dev/null; then
        systemctl restart ssh
        log_success "SSH service restarted."
    fi
else
    log_warn "SSH config not found at $SSHD_CONFIG. Skipping SSH hardening."
fi

# --- 4. Network Hardening (Kernel Parameters via sysctl) ---
log_info "4. Configuring kernel and network hardening parameters..."

SYSCTL_CONF="/etc/sysctl.d/99-security-hardening.conf"

cat << 'EOF' > "$SYSCTL_CONF"
# Kernel Hardening configuration for security compliance

# IP Forwarding - Disable routing unless node is a dedicated router
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# ICMP Redirects - Prevent MITM attacks
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# IP Source Routing - Prevent packet routing manipulation
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# IP Spoofing protection (Reverse Path Filtering)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Log Martian packets (spoofed, route loops)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable ICMP echo broadcast requests (Smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Address Space Layout Randomization (ASLR) - Prevent buffer overflow execution
kernel.randomize_va_space = 2
EOF

# Apply sysctl parameters
sysctl -p "$SYSCTL_CONF" &>/dev/null || sysctl --system &>/dev/null
log_success "Hardened kernel/networking sysctl settings loaded."

# --- 5. Host Firewall Configuration (UFW) ---
log_info "5. Configuring local firewall (UFW) for least privilege access..."

if command -v ufw &>/dev/null; then
    # Reset to defaults
    ufw --force reset &>/dev/null
    
    # Default policies: Deny all incoming, allow all outgoing
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow custom SSH port
    ufw allow 2222/tcp comment 'Hardened SSH'
    
    # Enable firewall
    ufw --force enable
    log_success "UFW firewall enabled. Default deny policy applied, incoming TCP Port 2222 allowed."
else
    log_warn "UFW is not installed. Setting up iptables fallback..."
    # Basic iptables rules
    iptables -F
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
    log_success "Iptables firewall rules configured (port 2222 open, all other incoming traffic dropped)."
fi

# --- 6. Warning Banners ---
log_info "6. Deploying system banner warnings..."

BANNER_FILE="/etc/issue"
cat << 'EOF' > "$BANNER_FILE"
***************************************************************************
*                             WARNING NOTICE                              *
*                                                                         *
* This system is restricted solely to authorized users for authorized     *
* purposes. All activities on this system are monitored and recorded.     *
* Anyone using this system expressly consents to such monitoring and is   *
* advised that if such monitoring reveals possible evidence of criminal   *
* activity, system administration personnel may provide the evidence of   *
* such activity to law enforcement officials.                             *
*                                                                         *
* Unauthorized access is strictly prohibited and subject to prosecution.  *
***************************************************************************
EOF
cp "$BANNER_FILE" /etc/issue.net
log_success "Security banner warning deployed to /etc/issue and /etc/issue.net."

# --- 7. Security Auditing (Auditd) ---
log_info "7. Setting up security auditing rules..."

if [ -d /etc/audit ]; then
    AUDIT_RULES="/etc/audit/rules.d/audit.rules"
    [ ! -f "$AUDIT_RULES" ] && AUDIT_RULES="/etc/audit/audit.rules"
    
    cat << 'EOF' > "$AUDIT_RULES"
# First rule - delete all previous rules
-D

# Increase buffer size
-b 8192

# Monitor changes to time/date settings
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change

# Monitor identity changes (/etc/passwd, etc.)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor system network environment changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Monitor changes to the sudoers configuration
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Log privilege escalations and commands executed by root
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k exec-priv-escalation

# Lock rules configuration (requires system reboot to change)
-e 2
EOF
    log_success "Custom auditd policy rules configured."
    if systemctl is-active auditd &>/dev/null; then
        systemctl restart auditd
        log_success "Auditd service restarted to load new security rules."
    fi
else
    log_warn "Auditd utility is not installed. Skipping rule enforcement."
fi

log_success "System Hardening Complete!"
log_info "Please reboot the system to apply all network kernel parameters."
