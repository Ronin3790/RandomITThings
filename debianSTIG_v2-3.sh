#!/bin/bash

# Security & Audit Check Script with Failure Detection
# Run with root privileges

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

LOG_FILE="security_audit_report_$(date +%F_%T).log"

echo "Starting system audit at $(date)" | tee "$LOG_FILE"

run_check() {
    local title="$1"
    local command="$2"

    echo -e "\n--- $title ---" | tee -a "$LOG_FILE"
    echo "Command: $command" >> "$LOG_FILE"
    
    OUTPUT=$(eval "$command" 2>&1)
    if [[ -n "$OUTPUT" ]]; then
        echo "$OUTPUT" | tee -a "$LOG_FILE"
        echo -e "${GREEN}!! CHECK SUCCEEDED ${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}!! CHECK FAILED: No output returned ${NC}" | tee -a "$LOG_FILE"
        FAILED_CHECKS+=("[X] $title ")
    fi
}
run_check_null() {
    local title="$1"
    local command="$2"

    echo -e "\n--- $title ---" | tee -a "$LOG_FILE"
    echo "Command: $command" >> "$LOG_FILE"

    OUTPUT=$(eval "$command" 2>&1)
    if [[ -n "$OUTPUT" ]]; then
        echo "$OUTPUT" | tee -a "$LOG_FILE"
        echo -e "${RED}!! CHECK FAILED ${NC}"
        FAILED_CHECKS+=("[X] $title ")

    fi

}

run_check_out() {
    local title="$1"
    local command="$2"
    local match="$3"

    echo -e "\n--- $title ---" | tee -a "$LOG_FILE"
    echo "Command: $command" >> "$LOG_FILE"

    OUTPUT=$(eval "$command" 2>&1)
    if [[ "$OUTPUT" == "$match" ]]; then
        echo "$OUTPUT" |tee -a "$LOG_FILE"
        echo -e "${GREEN}!! CHECK SUCCEEDED ${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}!! CHECK FAILED: No output returned ${NC}" | tee -a "$LOG_FILE"
        FAILED_CHECKS+=("[X] $title ")
    fi    
}

# Helper to run many auditctl checks in a loop
run_auditctl_check() {
    local pattern="$1"
    run_check "Audit: $pattern" "sudo auditctl -l | grep $pattern"
}

# Helper to run policy checks in a loop

# Start of checks
run_check "Audit: passwd rule" "sudo auditctl -l | grep '\-w /etc/passwd -p wa -k usergroup_modification'"
run_check "Audit: group rule" "sudo auditctl -l | grep '\-w /etc/group -p wa -k usergroup_modification'"
run_check "Audit: gshadow rule" "sudo auditctl -l | grep '\-w /etc/gshadow -p wa -k usergroup_modification'"
run_check "Audit: opasswd rule" "sudo auditctl -l | grep '\-w /etc/security/opasswd -p wa -k usergroup_modification'"

# Replace <temporary_account_name> before running
#run_check "Temporary Account Expiry" "sudo chage -l <temporary_account_name> | grep -E '(Password|Account) expires'"

run_check "GRUB password config" "sudo grep -i password /boot/grub/grub.cfg"
run_check "Audit: execve rule" "sudo auditctl -l | grep '\-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv'"
run_check "Audit 2: execve rule" "sudo auditctl -l | grep '\-a always,exit -F arch=b64 -S execve -C uid!=euid -F egid=0 -F key=execpriv'"
run_check "PAM: faillock in common-auth" "grep faillock /etc/pam.d/common-auth"
run_check "PAM: faillock.conf options" "sudo grep -Ew 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf"
run_check "GDM3 Banner Message" "grep -i banner-message-enable=true /etc/lightdm/lightdm-gtk-greeter.conf"
run_check "vlock Package" "dpkg -l | grep 'vlock'"
#run_check "GNOME Screensaver Lock Enabled" "sudo gsettings get org.gnome.desktop.screensaver lock-enabled"
check_xfce_screensaver_lock() {
    echo "Checking XFCE screensaver lock settings..." | tee -a "$LOG_FILE"

    # Check if xfce4-screensaver is installed
    if ! command -v xfconf-query &> /dev/null; then
        echo -e "${RED}!! CHECK FAILED: xfconf-query not found (is xfce4-screensaver installed?) ${NC}" | tee -a "$LOG_FILE"
        return 1
    fi

    local lock_enabled
    local lock_delay
    local idle_delay

    lock_enabled=$(xfconf-query -c xfce4-screensaver -p /lock-enabled 2>/dev/null)
    lock_delay=$(xfconf-query -c xfce4-screensaver -p /lock-delay 2>/dev/null)
    idle_delay=$(xfconf-query -c xfce4-screensaver -p /idle-delay 2>/dev/null)

    # Check lock-enabled
    if [[ "$lock_enabled" == "true" ]]; then
        echo -e "${GREEN}!! CHECK SUCCEEDED: lock-enabled is true ${NC}" | tee -a "$LOG_FILE"
    else
        echo -e  "${RED}!! CHECK FAILED: lock-enabled is not true (value: $lock_enabled) ${NC}" | tee -a "$LOG_FILE"
    fi

    # Check lock-delay == 0
    if [[ "$lock_delay" -eq 0 ]]; then
        echo -e "${GREEN}!! CHECK SUCCEEDED: lock-delay is 0 ${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}!! CHECK FAILED: lock-delay is not 0 (value: $lock_delay) ${NC}" | tee -a "$LOG_FILE"
    fi

    # Check idle-delay >= 900
    if [[ "$idle_delay" -ge 900 ]]; then
        echo -e "${GREEN}!! CHECK SUCCEEDED: idle-delay is $idle_delay (>= 900 seconds) ${NC}" | tee -a "$LOG_FILE"
    else
        echo -e "${RED}!! CHECK FAILED: idle-delay is $idle_delay (< 900 seconds) ${NC}" | tee -a "$LOG_FILE"
    fi
}


check_xfce_screensaver_lock

# Check for screensaver
#run_check "GNOME Screensaver Settings" "gsettings get org.gnome.desktop.screensaver lock-enabled; gsettings get org.gnome.desktop.screensaver lock-delay; gsettings get org.gnome.desktop.session idle-delay"
#run_check "UFW Status" "systemctl status ufw.service | grep -i 'active:'"

run_check "SSHD UsePAM Check" "sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'usepam'"
run_check "SSHD MACs Check" "sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print \$4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'macs'"
run_check "Auditd Service Status" "systemctl is-enabled auditd.service; systemctl is-active auditd.service"

run_check "Audit Binary Permissions" "stat -c \"%n %a\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules"
run_check "Audit Binary Ownership" "stat -c \"%n %U\" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules"

# Batch of auditctl pattern checks
patterns=(
"pam_faillock /var/log/auth.log" 
"-w /var/log/faillog -p wa -k logins" 
"-a always,exit -S all -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-priv_change" 
"-a always,exit -S all -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chfn" 
"-a always,exit -S all -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-mount" 
"-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh" 
"-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid&gt;=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid&gt;=1000 -F auid!=-1 -F key=perm_chng "
"-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid&gt;=1000 -F auid!=-1 -F key=perm_chng "
"-a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-ssh" 
"-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
"-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
"-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
"-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
"-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod"
"-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng"
"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access" 
"-a always,exit -F arch=b32 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access"
"-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access"
"-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access"
"-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd" 
"-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd" 
"-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd" 
"-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd"
"-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -S all -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng" 
"-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage"
"-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-usermod" 
"-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-pam_timestamp_check" 
"-a always,exit -F arch=b32 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng" 
"-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng"
"-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-crontab" 
"-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete" 
"-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -F key=delete"
"-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng"
"-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng"

)

for pattern in "${patterns[@]}"; do
    run_check "Audit: $pattern" "sudo auditctl -l | grep -e \"$pattern\""
done


run_check_null "GRUB Kernel Entries" "grep '^\\s*linux' /boot/grub/grub.cfg"
run_check_null "Shared Libs World Writable" "sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c \"%n %a\" '{}' \\;"
run_check_null "Libs Not Owned by Root" "sudo find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c \"%n %U\" '{}' \\;"
run_check_null "Libs Group Not Root" "sudo find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c \"%n %G\" '{}' \\;"
run_check_null "System Binaries World Writable" "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c \"%n %a\" '{}' \\;"
run_check_null "System Dirs World Writable" "find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c \"%n %a\" '{}' \\;"
run_check_null "Binaries Not Owned by Root" "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c \"%n %U\" '{}' \\;"
run_check_null "Dirs Not Owned by Root" "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c \"%n %U\" '{}' \\;"
run_check_null "Symlinked Binaries Group Not Root" "sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c \"%n %G\" '{}' \\;"
run_check_null "Dirs Group Not Root" "sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c \"%n %G\" '{}' \\;"

# Policy & config file checks
run_check "Check for NIS" "dpkg -l | grep nis"
run_check "Check for rsh-server" "dpkg -l | grep rsh-server"
run_check "OpenSC PKCS11 Package" "dpkg -l | grep opensc-pkcs11"
run_check_null "Check for telnetd" "dpkg -l | grep telnetd"


run_check_out "PAM: pam_faildelay" "grep pam_faildelay /etc/pam.d/common-auth" "auth     required     pam_faildelay.so     delay=4000000"
run_check_out "pwquality: dictcheck" "grep -i dictcheck /etc/security/pwquality.conf" "dictcheck = 1"
run_check "UMASK Setting" "grep -i '^\s*umask' /etc/login.defs" "UMASK 077"
run_check_null "Check SSH Protocol 1" "sudo cat /etc/ssh/sshd_config | grep -i 'Protocol 1'"
run_check "pwquality: ucredit" "grep -i ucredit /etc/security/pwquality.conf" "ucredit = -1"
run_check "pwquality: lcredit" "grep -i lcredit /etc/security/pwquality.conf" "ucredit = -1"
run_check "pwquality: dcredit" "grep -i dcredit /etc/security/pwquality.conf" "dcredit = -1"
run_check "pwquality: difok" "grep -i difok /etc/security/pwquality.conf" "dcredit = -1"
run_check "Encrypt Method" "grep -i '^\s*encrypt_method' /etc/login.defs" "ENCRYPT_METHOD SHA512"
run_check "Pass Min Days" "grep -i pass_min_days /etc/login.defs" "PASS_MIN_DAYS    1"
run_check "Minlen Setting" "grep -i minlen /etc/security/pwquality.conf" "minlen = 15" 
run_check "PKCS11 Module Block" "sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/'  '/etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca'" "cert_policy = ca,signature,ocsp_on;"
run_check "pwquality: ocredit" "grep -i ocredit /etc/security/pwquality.conf" "ocredit = -1"
run_check "PKCS11 use_mappers" "grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf" "use_mappers = pwent"
run_check_null "NOPASSWD / !authenticate in sudoers" "sudo grep -Ei '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*"

# SSHD Service
run_check "SSH Service Status" "sudo systemctl is-enabled ssh; sudo systemctl is-active ssh"

# FIPS Mode
run_check "FIPS Enabled" "grep -i 1 /proc/sys/crypto/fips_enabled"

# /var/log Checks
run_check "/var/log Group" "stat -c \"%n %G\" /var/log"
run_check "/var/log Owner" "stat -c \"%n %U\" /var/log"
run_check "/var/log Permissions" "stat -c \"%n %a\" /var/log"
run_check "/var/log/syslog Permissions" "stat -c \"%n %a\" /var/log/syslog"

# ASLR
run_check "ASLR sysctl" "sysctl kernel.randomize_va_space"
run_check "ASLR /proc" "cat /proc/sys/kernel/randomize_va_space"

echo -e "\nAudit completed at $(date). Results saved to $LOG_FILE"



summarize_failures() {
    echo "" | tee -a "$LOG_FILE"
    echo "========================" | tee -a "$LOG_FILE"
    echo "  STIG FAIL SUMMARY     " | tee -a "$LOG_FILE"
    echo "========================" | tee -a "$LOG_FILE"

    if [ ${#FAILED_CHECKS[@]} -eq 0 ]; then
        echo "All checks passed but you're still a failure in my eyes!" | tee -a "$LOG_FILE"
    else 
        echo "${#FAILED_CHECKS[@]} check(s) failed:" | tee -a "$LOG_FILE"
        for failure in "${FAILED_CHECKS[@]}"; do
            echo "$failure" | tee -a "$LOG_FILE"
        
        done
    fi
}
summarize_failures | tee -a "LOG_FILE"

#grep match output of faillock check
#greeter banner
#nftables instead of ufw
