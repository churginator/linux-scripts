#!/bin/bash
# The entire CIS hardening guide for ubuntu 24, in script form

set -uo pipefail

[[ $(id -u) != 0 ]] && echo "Run as root pls" && exit

GRUB_CMDLINE_LINUX=""

# -- :3 --
printf "\e[0;31m"
echo "\
!!!!!ATTENTION!!!!!
PLEASE VISUDO AND ADD THE FOLLOWING LINES:
Defaults use_pty
Defaults logfile=\"/var/log/sudo.log\"

ADDITIONALLY, REMOVE ANY LINES WITH THE FOLLOWING:
!authenticate
NOPASSWD
thanks :333, press enter when done"
printf "\e[0m"

read
unset REPLY

# --- Filesystem ---
echo "install cramfs /bin/false" > /etc/modprobe.d/cramfs.conf
modprobe -r cramfs 2>/dev/null

echo "install freevxfs /bin/false" > /etc/modprobe.d/freevxfs.conf
modprobe -r freevxfs 2>/dev/null

echo "install hfs /bin/false" > /etc/modprobe.d/hfs.conf
modprobe -r hfs 2>/dev/null

echo "install hfsplus /bin/false" > /etc/modprobe.d/hfsplus.conf
modprobe -r hfsplus 2>/dev/null

echo "install jffs2 /bin/false" > /etc/modprobe.d/jffs2.conf
modprobe -r jffs2 2>/dev/null

echo "install overlayfs /bin/false" > /etc/modprobe.d/overlayfs.conf
modprobe -r overlayfs 2>/dev/null

echo "install squashfs /bin/false" > /etc/modprobe.d/squashfs.conf
modprobe -r squashfs 2>/dev/null

echo "install udf /bin/false" > /etc/modprobe.d/udf.conf
modprobe -r udf 2>/dev/null

echo "install usb-storage /bin/false" > /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage 2>/dev/null

systemctl unmask tmp.mount 2>/dev/null
echo "\
tmpfs   /tmp    tmpfs  defaults,rw,nosuid,nodev,noexec,relatime    0 0" \
>> /etc/fstab

echo "\
tmpfs   /dev/shm    tmpfs   defaults,rw,nosuid,nodev,noexec,relatime    0 0" \
>> /etc/fstab

systemctl daemon-reload
mount -o remount /tmp
mount -o remount /dev/shm

# There should be a section here for putting user-writable directories on separate partitions,
# but that's not practical and i don't care enough to figure it out

# --- AppArmor ---
apt-get install apparmor apparmor-utils -y >/dev/null
GRUB_CMDLINE_LINUX=""$GRUB_CMDLINE_LINUX"apparmor=1 security=apparmor"
aa-enforce /etc/apparmor.d/*

# --- Bootloader ---
cat > /etc/grub.d/20-password.conf << EOF
exec tail -n +2 $0
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.600000.4D827E1BF6BA16BD7CD5FA9D14676F56564E0280564796B106AD003BBF5DCEA2C1CA590F0852F7814249FB8380E56E2271F61E855E7E291EF3A4C6FA06C48CD4.49A29600B3300EA57D2CCBF5D8E3CF508C7A0F218E390A9058D772CE449523D115089B747FCA31E20D1553288AC123415D47D7D214DC31F80E828CD23F2269FF
EOF

chown root:root /boot/grub/grub.cfg
chmod 0600 /boot/grub/grub.cfg

# --- Process hardening ---
cat >> /etc/systemd/coredump.conf << EOF
Storage=none
ProcessSizeMax=0
EOF

apt-get purge prelink -y >/dev/null

apt-get purge apport -y >/dev/null

# --- MOTD ---
rm /etc/motd
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net

chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)

chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)

# --- GDM ---
gsettings set org.gnome.login-screen banner-message-enable true 2>/dev/null
gsettings set org.gnome.login-screen banner-message-text 'Authorized users only. All activity may be monitored and reported' 2>/dev/null

gsettings set org.gnome.login-screen disable-user-list true 2>/dev/null

gsettings set org.gnome.desktop.screensaver lock-delay 5 2>/dev/null
gsettings set org.gnome.desktop.session idle-delay 900 2>/dev/null

cat > /etc/dconf/db/local.d/locks/00-screensaver << EOF
# Lock desktop screensaver settings
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-delay
EOF

gsettings set org.gnome.desktop.media-handling automount false 2>/dev/null
gsettings set org.gnome.desktop.media-handling automount-open false 2>/dev/null

cat > /etc/dconf/db/local.d/locks/00-media-automount << EOF
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
EOF

gsettings set org.gnome.desktop.media-handling autorun-never true

cat > /etc/dconf/db/local.d/locks/00-media-autorun << EOF
[org/gnome/desktop/media-handling]
autorun-never=true
EOF

rm /etc/gdm/custom.conf 2>/dev/null
rm /etc/gdm3/custom.conf 2>/dev/null

if [[ -d /etc/gdm ]]; then
    echo "\
[xdmcp]
Enable=false" \
    > /etc/gdm/custom.conf
elif [[ -d /etc/gdm3 ]]; then
    echo "\
[xdmcp]
Enable=false" \
    > /etc/gdm3/custom.conf
fi

# -- Services --
systemctl stop autofs.service 2>/dev/null
apt-get purge autofs -y >/dev/null

systemctl mask --now avahi-daemon.socket avahi-daemon.service 2>/dev/null

systemctl mask --now isc-dhcp-server.service isc-dhcp-server6.service 2>/dev/null

systemctl mask --now named.service 2>/dev/null

systemctl mask --now dnsmasq.service 2>/dev/null

systemctl mask --now vsftpd.service 2>/dev/null

systemctl mask --now slapd.service 2>/dev/null

systemctl mask --now dovecot.socket dovecot.service 2>/dev/null

systemctl mask --now nfs-server.service 2>/dev/null

systemctl mask --now ypserver.service 2>/dev/null

systemctl mask --now rpcbind.socket rpcbind.service 2>/dev/null

systemctl mask --now rsync.service 2>/dev/null

systemctl mask --now snmpd.service 2>/dev/null

systemctl mask --now tftpd-hpa.service 2>/dev/null

systemctl mask --now squid.service 2>/dev/null

systemctl mask --now xinetd.service 2>/dev/null

# -- Client Services --
apt-get purge nis -y >/dev/null
apt-get purge rsh-client -y >/dev/null
apt-get purge talk -y >/dev/null

# -- NTP --
apt-get purge chrony -y >/dev/null
apt-get install systemd-timesyncd -y >/dev/null

cat > /etc/systemd/timesyncd.conf << EOF
[Time]
NTP=time.nist.gov
FallbackNTP=time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov
EOF

systemctl enable --now systemd-timesyncd.service

# -- Cron --
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/

chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/

chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/

chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/

chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/

apt-get purge at >/dev/null

# -- Network --
systemctl mask --now bluetooth.service

# -- more kernel yippee --
echo "install dccp /bin/false" > /etc/modprobe.d/dccp.conf
echo "install tipc /bin/false" > /etc/modprobe.d/tipc.conf
echo "install rds /bin/false" > /etc/modprobe.d/rds.conf
echo "install sctp /bin/false" > /etc/modprobe.d/sctp.conf

# -- Firewall --
apt-get purge iptables-persistent >/dev/null

# -- ssh --
chmod 0600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config

chmod 0600 /etc/ssh/sshd_config.d/*
chown root:root /etc/ssh/sshd_config.d/*

chmod 0644 /etc/ssh/*.pub
chown root:root /etc/ssh/*.pub

chmod 0600 /etc/ssh/*key
chown root:root /etc/ssh/*key

sed -Ei '
1 i\Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com
DisableForwarding yes
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1;
MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com
s/^#?Banner.*/Banner \/etc\/issue/;
s/^#?ClientAliveInterval.*/ClientAliveInterval 15/;
s/^#?ClientAliveCountMax.*/ClientAliveCountMax 3/;
s/^#?GSSAPIAuthentication.*/GSSAPIAuthentication no/;
s/^#?HostbasedAuthentication.*/HostbasedAuthentication no/;
s/^#?IgnoreRhosts.*/IgnoreRhosts yes/;
s/^#?LoginGraceTime.*/LoginGraceTime 60/;
s/^#?LogLevel.*/LogLevel verbose/;
s/^#?MaxAuthTries.*/MaxAuthTries 4/;
s/^#?MaxSessions.*/MaxSessions 10/;
s/^#?MaxStartups.*/MaxStartups 10:30:60/;
s/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/;
s/^#?PermitRootLogin.*/PermitRootLogin no/;
s/^#?PermitUserEnvironment.*/PermitUserEnvironment no/;
s/^#?UsePAM.*/UsePAM yes/;' /etc/ssh/sshd_config 2>/dev/null

echo -n "su allowed line in pam: "
grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su || echo

# -- pam --
pam-auth-update --enable unix
pam-auth-update --enable faillock
pam-auth-update --enable faillock_notify

# -- root account --
sed -Ei '/umask/d' /root/.bashrc
sed -Ei '/umask/d' /root/.bash_profile
sed -Ei '/PATH/d' /root/.bashrc
sed -Ei '/PATH/d' /root/.bash_profile

for i in $(awk -F: '$3 < 1000 || $3 >= 60000 {print $1}' /etc/passwd | grep -vE "root|halt|sync|shutdown|nfsnobody" | tr '\n' ' ' | sed 's/.$//'); do
    usermod -s $(command -v nologin) $i
done

for i in $(grep nologin /etc/passwd | cut -d: -f1); do
    passwd -l $i
done

# -- user environment --
cat >> /etc/profile << EOF
TMOUT=900
readonly TMOUT
export TMOUT
EOF

sed -Ei 's/^UMASK.*/UMASK 027/' /etc/login.defs

# -- journaling --
systemctl unmask systemd-journald.service

cat > /etc/tmpfiles.d/systemd.conf << EOF
d /run/user 0755 root root -
F! /run/utmp 0664 root utmp -
d /run/systemd/ask-password 0755 root root -
d /run/systemd/seats 0755 root root -
d /run/systemd/sessions 0755 root root -
d /run/systemd/users 0755 root root -
d /run/systemd/machines 0755 root root -
d /run/systemd/shutdown 0755 root root -
d /run/log 0755 root root -
z /run/log/journal 2755 root systemd-journal - -
Z /run/log/journal/%m ~2750 root systemd-journal - -
a+ /run/log/journal    - - - - d:group::r-x,d:group:adm:r-x,group::r-x,group:adm:r-x
a+ /run/log/journal/%m - - - - d:group:adm:r-x,group:adm:r-x
a+ /run/log/journal/%m/*.journal* - - - - group:adm:r--
z /var/log/journal 2755 root systemd-journal - -
z /var/log/journal/%m 2755 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -
a+ /var/log/journal    - - - - d:group::r-x,d:group:adm:r-x,group::r-x,group:adm:r-x
a+ /var/log/journal/%m - - - - d:group:adm:r-x,group:adm:r-x
a+ /var/log/journal/%m/system.journal - - - - group:adm:r--
d /var/lib/systemd 0755 root root -
d /var/lib/systemd/coredump 0755 root root 2w
d /var/lib/systemd/ephemeral-trees 0755 root root 0
d /var/lib/private 0700 root root -
d /var/log/private 0700 root root -
d /var/cache/private 0700 root root -
C /run/systemd/tpm2-pcr-signature.json 0444 root root - /.extra/tpm2-pcr-signature.json
C /run/systemd/tpm2-pcr-public-key.pem 0444 root root - /.extra/tpm2-pcr-public-key.pem
EOF

mkdir -p /etc/systemd/journald.conf.d/
cat > /etc/systemd/journald.conf.d/99-journald.conf << EOF
[Journal]
SystemMaxUse=1G
SystemMaxFileSize=64M
SystemKeepFree=500M
RuntimeMaxUse=200M
RuntimeKeepFree=50M
MaxFileSec=1month
Compress=yes
Storage=persistent
EOF

systemctl mask --now rsyslog
systemctl enable --now systemd-journald.service

# -- auditing --
apt-get install auditd audispd-plugins -y
systemctl unmask auditd.service
systemctl enable --now auditd.service

GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1 audit_backlog_limit=8192"

sed -Ei '
s/^max_log_file.*/max_log_file = 16/;
s/^max_log_file_action.*/max_log_file_action = 16/;
s/^disk_full_action.*/disk_full_action = single/;
s/^disk_error_action.*/disk_error_action = single/;
s/^max_log_file.*/max_log_file 16/;
s/^space_left_action.*/space_left_action = single/;
s/^admin_space_left_action.*/admin_space_left_action = single/;
s/^space_left_action.*/space_left_action = single/;' /etc/audit/auditd.conf

printf "
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
" >> /etc/audit/rules.d/50-scope.rules

printf "
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
" >> /etc/audit/rules.d/50-user_emulation.rules

printf "
-w /var/log/sudo.log -p wa -k sudo_log_file
" >> /etc/audit/rules.d/50-sudo.rules

printf "
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
" >> /etc/audit/rules.d/50-time-change.rules

printf "
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale
" >> /etc/audit/rules.d/50-system_locale.rules

find / -xdev -perm /6000 -type f 2>/dev/null |\
awk -v UID_MIN=1000 '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>="UID_MIN" -F auid!=unset -k privileged" }' >\
/etc/audit/rules.d/50-privileged.rules

printf "
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
" >> /etc/audit/rules.d/50-access.rules

printf "
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
" >> /etc/audit/rules.d/50-identity.rules

printf "
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
" >> /etc/audit/rules.d/50-perm_mod.rules

printf "
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
" >> /etc/audit/rules.d/50-mounts.rules

printf "
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
" >> /etc/audit/rules.d/50-session.rules

printf "
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
" >> /etc/audit/rules.d/50-login.rules

printf "
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -F key=delete
" >> /etc/audit/rules.d/50-delete.rules

printf "
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
" >> /etc/audit/rules.d/50-MAC-policy.rules

printf "
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules

printf "
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules

printf "
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
" >> /etc/audit/rules.d/50-perm_chng.rules

printf "
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod
" >> /etc/audit/rules.d/50-usermod.rules

printf "
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules
" >> /etc/audit/rules.d/50-kernel_modules.rules

printf '\n%s\n' "-e 2" > /etc/audit/rules.d/99-finalize.rules

augenrules --load

# -- audit file permissions --
find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +

find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec chown root {} +

find $(dirname $(awk -F"=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)) -type f \( ! -group adm -a ! -group root \) -exec chgrp adm {} +

sed -ri 's/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = adm\1/' /etc/audit/auditd.conf

chmod g-w,o-rwx "$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +

find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +

chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

# -- AIDE --
DEBIAN_FRONTEND=noninteractive apt-get install aide aide-common -y >/dev/null
systemctl enable --now dailyaidecheck.timer

echo \
'@@ifndef TOPDIR
@@define TOPDIR /
@@endif

@@ifndef AIDEDIR
@@define AIDEDIR /etc/aide
@@endif

@@ifhost smbserv
@@define smbactive
@@endif

# The location of the database to be read.
database=file:@@{AIDEDIR}/aide.db

# The location of the database to be written.
database_out=file:aide.db.new

verbose=20
report_url=stdout

# Rule definition
All=R+a+sha1+rmd160
Norm=s+n+b+md5+sha1+rmd160

@@{TOPDIR} Norm
!@@{TOPDIR}etc/aide
!@@{TOPDIR}dev
!@@{TOPDIR}media
!@@{TOPDIR}mnt
!@@{TOPDIR}proc
!@@{TOPDIR}root
!@@{TOPDIR}sys
!@@{TOPDIR}tmp
!@@{TOPDIR}var/log
!@@{TOPDIR}var/run
!@@{TOPDIR}usr/portage
!@@{TOPDIR}var/db/repos/gentoo
@@ifdef smbactive
!@@{TOPDIR}etc/smb/private/secrets.tdb
@@endif
=@@{TOPDIR}home Norm' > /etc/aide.conf

printf '%s\n' "" "# Audit Tools" "$(readlink -f /sbin/auditctl)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/auditd)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/ausearch)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/aureport)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/autrace)
p+i+n+u+g+s+b+acl+xattrs+sha512" "$(readlink -f /sbin/augenrules)
p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf

# only slightly confusing line
echo "GRUB_CMDLINE_LINUX=\"$GRUB_CMDLINE_LINUX\"" >> /etc/default/grub
update-grub

# -- file permissions --
for i in /etc/passwd /etc/passwd- /etc/group /etc/group- /etc/shells; do
    chmod 0644 $i
    chown root:root $i
done

for i in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- /etc/security/opasswd; do
    chmod 0600 $i
    chown root:root $i
done

find / -xdev -not -type l -perm -o+w -type d -exec chmod a+t \{\} \+

printf "\e[0;31m"
echo -e "\nworld writable files:"
find / -xdev -type f -perm -o+w -not -type l 2>/dev/null

echo -e "\nfiles with no user or group:"
find / -xdev -nouser -o -nogroup 2>/dev/null

echo -e "\nSUID/GUID files:"
find / -xdev -perm /6000 2>/dev/null
printf "\e[0m"

# -- users --
pwconv

for stupid in $(awk -F: '($2 == "" ) { print $1 }' /etc/shadow); do
    passwd -l $stupid
done

sed -ri 's/(^shadow:[^:]*:[^:]*:)([^:]+$)/\1/' /etc/group
grpck