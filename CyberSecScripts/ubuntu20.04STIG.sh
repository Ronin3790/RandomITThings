!#/bin/bash

sudo chage -E $(date -d "+3 days" +%F) system_account_name
sed -i 's/# banner-message-enable=true/banner-message-enable=false/g' greeter.dconf-defaults #### xcfe greeter config file
sudo gsettings set org.gnome.desktop.screensaver lock-enabled true #### xcfe
sudo apt-get install vlock
echo -n 'use_mappers=pwent' >> /etc/pam_pkcs11/pam_pkcs11.conf
echo -n 'PASS_MIN_DAYS 1' >> /etc/login.defs
echo -n 'PASS_MAX_DAYS 60' >> /etc/login.defs


grub-mkpasswd-pbkdf2 
Enter Password: 
Reenter Password: 
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG
sudo sed -i '$i set superusers=\"root\"\npassword_pbkdf2 root <hash>' /etc/grub.d/40_custom 
sudo update-grub

touch /etc/profile.d/99-terminal_tmout.sh; echo -n 'TMOUT=600' >> /etc/profile.d/99-terminal_tmout.sh
export TMOUT=600

sed -i '/NOPASSWD/d' sudoers
sed -i '/UMASK/d' login.defs; echo -n 'UMASK      077' >> login.defs

echo -n 'auth [success=2 default=ignore] pam_pkcs11.so' >>  /etc/pam.d/common-auth
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config

echo -n 'UsePAM yes' >> /etc/ssh/sshd_config
echo -n 'ClientAliveCountMax 1' >> /etc/ssh/sshd_config
echo -n 'ClientAliveInterval 600' >>  /etc/ssh/sshd_config
sudo systemctl restart sshd.service

sudo sed -i '/^Banner/d' /etc/ssh/sshd_config 
sudo sed -i '$aBanner /etc/issue.net' /etc/ssh/sshd_config 
sudo apt install ssh
sudo echo -n 'MACs hmac-sha2-512,hmac-sha2-256' >> /etc/ssh/sshd_config
sudo echo -n 'Ciphers aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config
sudo echo -n 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
sudo echo -n 'PermitUserEnvironment no' >> /etc/ssh/sshd_config
sudo echo -n 'X11Forwarding no' >> /etc/ssh/sshd_config
sudo echo -n 'X11UseLocalhost yes ' >> /etc/ssh/sshd_config
sudo echo -n 'ucredit=-1' >> /etc/security/pwquality.conf
sudo echo -n 'lcredit=-1' >> /etc/security/pwquality.conf
sudo echo -n 'dcredit=-1' >> /etc/security/pwquality.conf
sudo echo -n 'difok=8' >> /etc/security/pwquality.conf
sudo echo -n 'minlen=15' >> /etc/security/pwquality.conf
sudo echo -n 'ocredit=-1' >> /etc/security/pwquality.conf
sudo echo -n 'dictcheck=1' >> /etc/security/pwquality.conf
sudo echo -n 'difok=8' >> /etc/security/pwquality.conf
sudo echo -n 'minlen=15' >> /etc/security/pwquality.conf
sudo echo -n 'ocredit=-1' >> /etc/security/pwquality.conf
sudo echo -n 'dictcheck=1' >> /etc/security/pwquality.conf

sudo apt-get install libpam-pwquality -y
sudo echo -n 'enforcing = 1' >> /etc/security/pwquality.conf

sudo echo -n 'password requisite pam_pwquality.so retry=3' >> /etc/security/pwquality.conf

sudo apt-get install opensc-pkcs11
sudo apt install libpam-pkcs11
sudo echo -n 'cert_policy = ca,signature,ocsp_on;' >> /etc/pam_pkcs11/pam_pkcs11.conf
sudo echo -n 'cert_policy = ca,signature,ocsp_on, crl_auto;' >> /etc/pam/_pkcs11/pam_pkcs11.conf
sudo echo -n 'password [success=1 default=ignore] pam_unix.so obsecure sha512 shadow remember=5 rounds=5000' >> /etc/pam.d/common-password
sudo echo -n 'auth [default=die] pam_faillock.so authfail\nauth sufficient pam_faillock.so authsucc' >> /etc/pam.d/common-auth
sudo echo -n 'audit\nsilent\ndeny = 3\nfail_interval = 900\nunlock_time = 0 >> /etc/security/faillock.conf

cd /tmp; sudo apt download aide-common
dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | sudo tar -x ./usr/share/aide/config/cron.daily/aide -C / 
sudo cp -f /usr/share/aide/config/cron.daily/aide /etc/cron.daily/aide
sudo echo -n 'auth required pam_faildelay.so delay=4000000' >> /etc/pam.d/common-auth

touch /etc/audit/rules.d/stig.rules
sudo echo -n '-w /etc/passwd -p wa -k usergroup_modification' >> /etc/audit/rules.d/stig.rules
sudo echo -n '-w /etc/shadow -p wa -k usergroup_modification' >> /etc/audit/rules.d/stig.rules
sudo echo -n '-w /etc/gshadow -p wa -k usergroup_modification' >> /etc/audit/rules.d/stig.rules
sudo echo -n '-w /etc/security/opasswd -p wa -k usergroup_modification' >> /etc/audit/rules.d/stig.rules
sudo augenrules --load

sudo echo -n 'action_mail_acct = <administrator_account>' >> /etc/audit/auditd.conf
sudo systemctl restart auditd.service

sudo chmod 0600 /var/log/audit/*
sudo chown root /var/log/audit/*
sudo chmod -R g-w,o-rwx /var/log/audit
sudo chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
sudo chown root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
sudo chown :root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*

cat <<! >>/etc/audit/rules.d/stig.rules
-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change 
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chfn
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount 
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh 
-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr -F auid=0 -k perm_mod 
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng 
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access 
-a always,exit -F arch=b64 -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access 
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd 
-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng 
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng 
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng
-w /var/log/tallylog -p wa -k logins 
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged-passwd
-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod 
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-crontab
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check
-a always,exit -F arch=b64 -S init_module,finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng 
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv 
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -Fauid>=1000 -F auid!=4294967295 -k delete
-w /var/log/sudo.log -p wa -k maintenance
always,exit -F arch=b64 -S init_module-k modules
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins 
-w /sbin/modprobe -p x -k modules
-w /bin/kmod -p x -k modules
-w /bin/fdisk -p x -k fdisk
!

sudo apt-get install auditd 
sudo systemctl enable auditd.service
sudo augenrules --load

sudo sed -i '/GRUB_CMDLINE_LINUX="find_preseed=\/preseed.cfg auto noprompt priority=critical locale=en_US"/d' grub
sudo echo -n 'GRUB/_CMDLINE/_LINUX/=/\"find_preseed/=//preseed.cfg auto noprompt priority/=critical locale/=en_US audit=1\"'
sudo update-grub

sudo chmod 0755 auditctl
sudo chmod 0755 auditd
sudo chmod 0755 ausearch
sudo chmod 0755 aureport
sudo chmod 0755 autrace
sudo chmod 0755 audispd
sudo chmod 0755 augenrules

sudo chown :root auditctl
sudo chown :root auditd
sudo chown :root ausearch
sudo chown :root aureport
sudo chown :root autrace
sudo chown :root audispd
sudo chown :root augenrules

cat <<! > /etc/aide/aide.conf
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512 
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512 
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512 
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512 
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512 
/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512 
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
!

sudo sed -i -E 's@^(log_file\s*=\s*).*@\1 <log mountpoint>/audit.log@' /etc/audit/auditd.conf 


sudo apt-get install audispd-plugins -y 
sudo sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf
sudo sed -i -E 's/(remote_server\s*=).*/\1 <remote addr>/' /etc/audisp/audisp-remote.conf
sudo systemctl restart auditd.service

#If the "space_left_action" parameter is set to "email", set the "action_mail_acct" parameter to an email address for the SA and ISSO. 
#If the "space_left_action" parameter is set to "exec", ensure the command being executed notifies the SA and ISSO. 

sudo timedatectl set-timezone [ZONE]

#Create a script that offloads audit logs to external media and runs weekly. 

#The script must be located in the "/etc/cron.weekly" directory.

sudo echo -n '* hard maxlogins 10' >> /etc/security/limits.conf
sudo echo -n 'auth.*,authpriv.* /var/log/secure\ndaemon.notice /var/log/messages' >> /etc/rsyslog.d/50-default.conf

sudo systemctl restart rsyslog.service

sudo echo -n 'ENCRYPT_METHOD SHA512' >> /etc/login.defs

sudo apt-get remove telnetd
sudo apt-get remove rsh-server

sudo ufw allow <direction> <port/protocol/service>
sudo ufw deny <direction> <port/protocol/service>

sudo passwd -l root
sudo useradd -D -f 35 
sudo chage -E $(date -d "+3 days" +%F) account_name
sudo sysctl -w net.ipv4.tcp_syncookies=1

sudo echo -n 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf
sudo systemctl disable kdump.service 

sudo apt-get install mfetp
sudo find /var/log -perm /137 -type f -exec chmod 640 '{}' \;
sudo chgrp syslog /var/log
sudo chown root /var/log
sudo chmod 0750 /var/log
sudo chgrp adm /var/log/syslog
sudo chown syslog /var/log/syslog
sudo chmod 0640 /var/log/syslog
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \;
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' \;
sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;
sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' \;
sudo find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}' \;
sudo find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' \;
sudo find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' \;
sudo apt-get install rsyslog 
sudo systemctl enable --now rsyslog
sudo apt-get install ufw
sudo systemctl enable --now ufw.service

sudo echo -n 'server [source] iburst maxpoll = 16' >> /etc/chrony/chrony.conf
sudo systemctl restart chrony.service

echo -n 'makestep 1 -1' >> /etc/chrony/chrony.conf
sudo systemctl restart chrony.service

echo -n 'SILENTREPORTS no' >> /etc/default/aide

#APT::Get::AllowUnauthenticated "false"; \**not able to find this anywhere**\

sudo apt-get install apparmor
sudo systemctl enable apparmor.service
sudo systemctl start apparmor.service 

sudo chage -d 0 [UserName] 

#implement NIST FIPS-validated cryptography to protect classified information
#Configure the system to run in FIPS mode. Add "fips=1" to the kernel parameter during the Ubuntu operating systems install. 
#Enabling a FIPS mode on a pre-existing system involves a number of modifications to the Ubuntu operating system. Refer to the Ubuntu Server 18.04 FIPS 140-2 security policy document for instructions. 
#A subscription to the "Ubuntu Advantage" plan is required in order to obtain the FIPS Kernel cryptographic modules and enable FIPS.

sudo sed -i 's/^([^!#]+)/!\1/' /etc/ca-certificates.conf

#Add at least one DoD certificate authority to the "/usr/local/share/ca-certificates" directory in the PEM format. 
#Update the "/etc/ssl/certs" directory with the following command: 
sudo update-ca-certificates

#implement cryptographic mechanisms to prevent unauthorized modification of all information at rest.
To encrypt an entire partition, dedicate a partition for encryption in the partition layout. 

Note: Encrypting a partition in an already-installed system is more difficult because it will need to be resized and existing partitions changed.

# implement cryptographic mechanisms to prevent unauthorized disclosure of all information at rest.
#To encrypt an entire partition, dedicate a partition for encryption in the partition layout. 

#configure the uncomplicated firewall to rate-limit impacted network interfaces.
#Configure the application firewall to protect against or limit the effects of DoS attacks by ensuring the Ubuntu operating system is implementing rate-limiting measures on impacted network interfaces. 
sudo ss -l46ut 
For each service with a port listening to connections, run the following command, replacing "[service]" with the service that needs to be rate limited. 
$ sudo ufw limit [service] 
Rate-limiting can also be done on an interface. An example of adding a rate-limit on the eth0 interface follows: 
$ sudo ufw limit in on eth0

#implement non-executable data to protect its memory from unauthorized code execution.
Configure the Ubuntu operating system to enable NX. 

If "nx" is not showing up in "/proc/cpuinfo", and the system's BIOS setup configuration permits toggling the No Execution bit, set it to "enable".

sed -i '/^kernel.randomize_va_space/d' /etc/sysctl.conf
sudo sysctl --system

cat <<! > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Remove-Unused-Dependencies "true"; 
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

sudo apt-get install aide

sed -i '1s/^/session required pam_lastlog.so showfailed/' /etc/pam.d/login
sudo systemctl enable ufw.service 
sudo systemctl start ufw.service

#disable all wireless network adapters.
 List all the wireless interfaces with the following command: 

$ ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename 

For each interface, configure the system to disable wireless network interfaces with the following command: 

$ sudo ifdown <interface name> 

For each interface listed, find their respective module with the following command: 

$ basename $(readlink -f /sys/class/net/<interface name>/device/driver) 

where <interface name> must be substituted by the actual interface name. 

Create a file in the "/etc/modprobe.d" directory and for each module, add the following line: 

install <module name> /bin/true 

For each module from the system, execute the following command to remove it: 

$ sudo modprobe -r <module name>

sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec chown root '{}' \;
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec chgrp root '{}' \;

touch /etc/dconf/db/local.d/00-disable-CAD
sudo echo -n [org/gnome/settings-daemon/plugins/media-keys]\nlogout='' >> /etc/dconf/db/local.d/00-disable-CAD
dconf update

sudo systemctl mask ctrl-alt-del.target
sudo systemctl daemon-reload

Configure all accounts on the system to have a password or lock the account with the following commands:

Perform a password reset:
$ sudo passwd [username]

sed -i '/nullok/d' /etc/pam.d/common_password

touch /etc/modprobe.d
sudo su -c "echo install usb-storage /bin/true >> /etc/modprobe.d/DISASTIG.conf"
sudo su -c "echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf"
