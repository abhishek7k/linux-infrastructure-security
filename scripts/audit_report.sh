#!/usr/bin/env bash
#
# audit_report.sh - System Hardening Compliance Auditor
# Checks system configurations against the hardening profile and generates a score.
#

# --- Visual Styling ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_header() {
    echo -e "\n${CYAN}======================================================================${NC}"
    echo -e "${CYAN}                  SYSTEM SECURITY COMPLIANCE REPORT                   ${NC}"
    echo -e "${CYAN}======================================================================${NC}"
}

TOTAL_CHECKS=0
PASSED_CHECKS=0

audit_check() {
    local check_desc="$1"
    local status="$2"
    local details="$3"
    
    ((TOTAL_CHECKS++))
    if [[ "$status" == "PASS" ]]; then
        ((PASSED_CHECKS++))
        printf "  [ ${GREEN}PASS${NC} ] %-45s - %s\n" "$check_desc" "$details"
    else
        printf "  [ ${RED}FAIL${NC} ] %-45s - %s\n" "$check_desc" "$details"
    fi
}

log_header
log_header_info() {
    echo -e "Audit Date: $(date)"
    echo -e "Hostname:   $(hostname)"
    echo -e "Kernel:     $(uname -r)"
    echo -e "----------------------------------------------------------------------"
}
log_header_info

# --- Check 1: User & Password Policies ---
# Password limits in /etc/login.defs
if [ -f /etc/login.defs ]; then
    max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
    if [[ "$max_days" -le 90 && "$min_days" -ge 7 ]]; then
        audit_check "Password Age Limits (login.defs)" "PASS" "Max: $max_days, Min: $min_days"
    else
        audit_check "Password Age Limits (login.defs)" "FAIL" "Max: $max_days, Min: $min_days (Should be Max<=90, Min>=7)"
    fi
else
    audit_check "Password Age Limits (login.defs)" "FAIL" "login.defs file missing"
fi

# Inactive system users shells
invalid_shells=0
for user in bin daemon mail ftp news uucp nobody; do
    if id "$user" &>/dev/null; then
        shell=$(getent passwd "$user" | cut -d: -f7)
        if [[ "$shell" != "/sbin/nologin" && "$shell" != "/usr/bin/nologin" && "$shell" != "/bin/false" ]]; then
            ((invalid_shells++))
        fi
    fi
done
if [[ $invalid_shells -eq 0 ]]; then
    audit_check "System Account Login Restrictions" "PASS" "All service shells disabled"
else
    audit_check "System Account Login Restrictions" "FAIL" "$invalid_shells accounts have active login shells"
fi

# --- Check 2: File System Permissions ---
# check /etc/shadow
shadow_perm=$(stat -c "%a" /etc/shadow 2>/dev/null)
if [[ "$shadow_perm" == "600" || "$shadow_perm" == "000" ]]; then
    audit_check "Shadow File Access Rules (/etc/shadow)" "PASS" "Permissions: $shadow_perm"
else
    audit_check "Shadow File Access Rules (/etc/shadow)" "FAIL" "Permissions: $shadow_perm (Should be 600 or 000)"
fi

# check /etc/passwd
passwd_perm=$(stat -c "%a" /etc/passwd 2>/dev/null)
if [[ "$passwd_perm" == "644" ]]; then
    audit_check "Passwd File Access Rules (/etc/passwd)" "PASS" "Permissions: $passwd_perm"
else
    audit_check "Passwd File Access Rules (/etc/passwd)" "FAIL" "Permissions: $passwd_perm (Should be 644)"
fi

# --- Check 3: SSH Configuration ---
SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
    ssh_port=$(grep -i "^Port" "$SSHD_CONFIG" | awk '{print $2}')
    ssh_root=$(grep -i "^PermitRootLogin" "$SSHD_CONFIG" | awk '{print $2}')
    ssh_pass=$(grep -i "^PasswordAuthentication" "$SSHD_CONFIG" | awk '{print $2}')
    
    # Check custom Port
    if [[ "$ssh_port" == "2222" ]]; then
        audit_check "SSH Custom Listening Port" "PASS" "Listening on Port 2222"
    else
        audit_check "SSH Custom Listening Port" "FAIL" "Port set to: ${ssh_port:-22}"
    fi
    
    # Check PermitRootLogin
    if [[ "$ssh_root" == "no" ]]; then
        audit_check "SSH Root Access Policy" "PASS" "Root login disabled"
    else
        audit_check "SSH Root Access Policy" "FAIL" "PermitRootLogin is: ${ssh_root:-yes}"
    fi

    # Check Password Authentication
    if [[ "$ssh_pass" == "no" ]]; then
        audit_check "SSH Passwordless Authentication" "PASS" "Passwords disabled (Keys only)"
    else
        audit_check "SSH Passwordless Authentication" "FAIL" "PasswordAuthentication is: ${ssh_pass:-yes}"
    fi
else
    audit_check "SSH Hardening Policies" "FAIL" "SSHD Configuration file missing"
    ((TOTAL_CHECKS += 2)) # offset checks
fi

# --- Check 4: Host Firewalls ---
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    audit_check "Host Firewall Enforcement (UFW)" "PASS" "Firewall is active"
elif iptables -L INPUT -n | grep -q "DROP (policy)"; then
    audit_check "Host Firewall Enforcement (iptables)" "PASS" "Default input policy set to DROP"
else
    audit_check "Host Firewall Enforcement" "FAIL" "Firewall inactive or default policy is ACCEPT"
fi

# --- Check 5: Warning Banners ---
if [ -f /etc/issue ] && grep -q "WARNING NOTICE" /etc/issue; then
    audit_check "System Banner Policy (/etc/issue)" "PASS" "Legal warning present"
else
    audit_check "System Banner Policy (/etc/issue)" "FAIL" "Legal banner missing or standard default"
fi

# --- Check 6: Kernel Parameters ---
rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)
syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)

if [[ "$rp_filter" == "1" && "$syncookies" == "1" && "$ip_forward" == "0" ]]; then
    audit_check "Kernel Network Sysctl Protection" "PASS" "SYN Cookies: ON, Spoof Check: ON, Forwarding: OFF"
else
    audit_check "Kernel Network Sysctl Protection" "FAIL" "SYN Cookies: $syncookies, Spoof Check: $rp_filter, Forwarding: $ip_forward"
fi

# --- Check 7: Auditing Systems ---
if systemctl is-active auditd &>/dev/null; then
    audit_check "Audit Daemon Service Status" "PASS" "auditd is running"
else
    audit_check "Audit Daemon Service Status" "FAIL" "auditd is inactive or not installed"
fi

# --- Compute Compliance Score ---
COMPLIANCE_SCORE=$(( (PASSED_CHECKS * 100) / TOTAL_CHECKS ))

echo -e "${CYAN}----------------------------------------------------------------------${NC}"
echo -e "  Compliance Rate:  [ ${PASSED_CHECKS} / ${TOTAL_CHECKS} checks passed ]"

if [[ $COMPLIANCE_SCORE -ge 85 ]]; then
    COLOR=$GREEN
    GRADE="Secure (Excellent compliance)"
elif [[ $COMPLIANCE_SCORE -ge 70 ]]; then
    COLOR=$YELLOW
    GRADE="Needs Review (Moderate risk)"
else
    COLOR=$RED
    GRADE="Vulnerable (Critical risk)"
fi

echo -e "  Hardening Score:  ${COLOR}${COMPLIANCE_SCORE}% - ${GRADE}${NC}"
echo -e "${CYAN}======================================================================${NC}"
