#!/bin/bash
# The entire CIS hardening guide for ubuntu 24, in script form

set -euo pipefail

[[ $(id -u) != 0 ]] && echo "Run as root pls"; exit

GRUB_CMDLINE_LINUX=""

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
mount -o remount /tmp

echo "\
tmpfs   /dev/shm    tmpfs   defaults,rw,nosuid,nodev,noexec,relatime    0 0" \
>> /etc/fstab
mount -o remount /dev/shm

# There should be a section here for putting user-writable directories on separate partitions,
# but that's not practical and i don't care enough to figure it out

# --- AppArmor ---
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

prelink -ua 2>/dev/null
apt-get purge prelink

apt-get purge apport

# --- MOTD ---
rm /etc/motd
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net

chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)

chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)

# --- GDM ---
gsettings set org.gnome.login-screen banner-message-enable true
gsettings set org.gnome.login-screen banner-message-text 'Authorized uses only. All activity may be monitored and reported'

gsettings set org.gnome.login-screen disable-user-list true

gsettings set org.gnome.desktop.screensaver lock-delay 5
gsettings set org.gnome.desktop.session idle-delay 900

cat > /etc/dconf/db/local.d/locks/00-screensaver << EOF
# Lock desktop screensaver settings
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/lock-delay
EOF

gsettings set org.gnome.desktop.media-handling automount false
gsettings set org.gnome.desktop.media-handling automount-open false

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
else
    echo "\
[xdmcp]
Enable=false" \
    > /etc/gdm3/custom.conf
fi

printf "\e[0;31m"
while IFS= read -r l_file; do
awk '/\[xdmcp\]/{ f = 1;next } /\[/{ f = 0 } f {if (/^\s*Enable\s*=\s*true/) print "\"'"$l_file"'\" includes: \"" $0 "\" in the \"[xdmcp]\" block"}' "$l_file" \
done < <(grep -Psil -- '^\h*\[xdmcp\]'
/etc/{gdm3,gdm}/{custom,daemon}.conf)
printf "\e[0m"

# -- Services --
systemctl stop autofs.service
apt-get purge autofs

systemctl mask --now avahi-daemon.socket avahi-daemon.service 2>dev/null

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
apt-get purge nis
apt-get purge rsh-client
apt-get purge talk

# -- NTP --
apt-get purge chrony 2>/dev/null
apt-get install systemd-timesyncd 2>/dev/null

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

apt-get purge at 2>/dev/null

# -- Network --
systemctl mask --now bluetooth.service

# -- more kernel yippee --
echo "install dccp /bin/false" > /etc/modprobe.d/dccp.conf
echo "install tipc /bin/false" > /etc/modprobe.d/tipc.conf
echo "install rds /bin/false" > /etc/modprobe.d/rds.conf
echo "install sctp /bin/false" > /etc/modprobe.d/sctp.conf

# -- Firewall --
apt-get purge iptables-persistent

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
grep -Pi '^\h*auth\h+(?:required|requisite)\h+pam_wheel\.so\h+(?:[^#\n\r]+\h+)?((?!\2)(use_uid\b|group=\H+\b))\h+(?:[^#\n\r]+\h+)?((?!\1)(use_uid\b|group=\H+\b))(\h+.*)?$' /etc/pam.d/su


# -- pam --
pam-auth-update --enable unix
pam-auth-update --enable faillock
pam-auth-update --enable faillock_notify


# .........


# -- user environment --
sed -Ei '/nologin/d' /etc/shells
cat >> /etc/profile << EOF
TMOUT=900
readonly TMOUT
export TMOUT
EOF

sed -Ei 's/^UMASK.*/UMASK 027/' /etc/login.defs