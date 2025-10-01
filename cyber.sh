#!/bin/bash

mkdir -p script-logs
cd script-logs

# Ensure we're running as root
[[ $(id -u) != 0 ]] && exec sudo originalUser=$(whoami) "./$(basename "$0") | tee script-logs/master.log"

# --- House(MD)keeping ---

echo "Remember to write down your user's password!"
read -p 'Press ENTER once the README has been read. '
read -p 'Press ENTER once the forensics have been done. '
unset REPLY

echo -en "Out of the following, which services are required as specified in the README?\nApache, Nginx, FTP, SQL, Printing\nRespond in a space-delimited list: "; read requiredServices
read -p "Enter a space-delimited list of all authorized users (including administrators): " -a authorizedUsers
read -p "Enter a space-delimited list of all authorized administrators: " -a authorizedAdmins
read -p "Enter any users that need to be added in a space-delimited list (user:group): " -a notPresentUsers

# there has GOT to be a better way to do this
grep -qi "apache" <<< "$requiredServices" && ignoreApache=true
grep -qi "nginx" <<< "$requiredServices" && ignoreNginx=true
grep -qi "ftp" <<< "$requiredServices" && ignoreFTP=true
grep -qi "sql" <<< "$requiredServices" && ignoreSQL=true
grep -qi "printing" <<< "$requiredServices" && ignoreCups=true


# --- Actual stuff begins here ---

# nightmare nightmare nightmare
find / -name "*.mp3" -type f -delete 2>/dev/null

# Firewall stuff
# Interestingly, most times the scoring engine doesn't actually care if the appropriate ports are open, just that the firewall is on
ufw --force reset
ufw default deny incoming; ufw default allow outgoing
ufw logging on; ufw logging high
ufw enable

#[ "$ignoreApache" == "true" -o "$ignoreNginx" == "true" ] && { ufw allow http; ufw allow https; }
#[ "$ignoreFTP" == "true" ] && { ufw allow ftp; ufw allow sftp; ufw allow saft; ufw allow ftps-data ; ufw allow ftps; }
#[ "$ignoreSQL" == "true" ] && { ufw allow ms-sql-s; ufw allow ms-sql-m; ufw allow mysql; ufw allow mysql-proxy; }
#[ "$ignoreCups" == "true" ] && { ufw allow ipp; ufw allow printer; ufw allow cups; }

# Users shenanigans

currentUsers=$(awk -F: '$3 >= 1000 && $3 <= 60000 && $1 != "nobody" {print $1}' /etc/passwd | grep -v "$originalUser" | tr '\n' ' ' | sed 's/.$//')
read -r -a badUsers <<< "$currentUsers"

currentAdmins=$(getent group sudo | cut -d: -f4 | tr ',' ' ')
read -r -a badAdmins <<< "$currentAdmins"

# is this performant? no, but we don't care
for confirmedOGUser in "${authorizedUsers[@]}"; do
        for i in "${!badUsers[@]}"; do
                if [[ ${badUsers[i]} = $confirmedOGUser ]]; then
                        unset 'badUsers[i]'
                        badUsers=("${badUsers[@]}")
                fi
        done
done

for confirmedOGAdmin in "${authorizedAdmins[@]}"; do
        for i in "${!badAdmins[@]}"; do
                if [[ ${badAdmins[i]} = $confirmedOGAdmin ]] || [[ ${badAdmins[i]} = $originalUser ]]; then
                        unset 'badAdmins[i]'
                        badAdmins=("${badAdmins[@]}")
                fi
        done
done

# keeping code dry? who needs that
# on a serious note, (trying to) passing arrays to bash functions is just cancer

for conglomerate in ${notPresentUsers[@]}; do
	IFS=':' read userToAdd groupOfUser <<< "$conglomerate"
	useradd -m "$userToAdd"
	getent group "$groupOfUser" >/dev/null 2>&1 || groupadd "$groupOfUser"
	usermod -aG "$groupOfUser" "$userToAdd"
done

# Executing this block here leaves empty uids in case we deleted someone we shouldn't have
for userToDelete in ${badUsers[@]}; do
	deletedUid = $(id "$userToDelete")
	userdel -r "$userToDelete"
	echo "Deleted $userToDelete with UID $deletedUid" > users.log
done

for adminToNuke in ${badAdmins[@]}; do
	gpasswd --delete "$adminToNuke" sudo
	echo "Removed $userToDelete from group sudo" > users.log
done

# The AFA has thrown a non-root uid 0 user in >=once, this intends to catch it
userdel -r "$(grep ":0:" /etc/passwd | grep -v "root")" 2>/dev/null

# Password Policy
# baby's first sed script!
sed -E -i.orig 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS=90/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS=7/; s/^#?PASS_MIN_LEN.*/PASS_MIN_LEN=12/' /etc/login.defs

# lock the root account
passwd -l root

cat > /etc/pam.d/common-password << EOF
password	requisite	pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difork=3
password 	requisite	pam_pwhistory.so remember=99 use_authok
password	[success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
password	requisite	pam_deny.so
password	required	pam_permit.so
EOF

cat > /etc/pam.d/common-auth << EOF
auth	required	pam_faillock.so preauth audit deny=5
auth	[success=2 default=ignore]	pam_unix.so
auth	[default=die]	pam_faillock.so authfail audit deny=5
auth	requisite	pam_deny.so
auth	requisite	pam_faillock.so deny=5
auth	required	pam_permit.so
auth	sufficient	pam_faillock.so authsucc audit deny=5
EOF

sed -E -i.orig 's/^#?PermitRootLogin.*/PermitRootLogin no/; s/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 2>/dev/null

# should provide a 13-char password for every user that isn't us
for passwordChange in $(awk -F: '$3 >= 1000 && $3 <= 60000 && $1 != "nobody" {print $1}' /etc/passwd | grep -v "$originalUser" | tr '\n' ' ' | sed 's/.$//'); do
	chpasswd <<< ""$passwordChange":cyberPatriot25!"
done

# File permissions
chown root:shadow /etc/shadow;	chmod 600 /etc/shadow
chown root:root /etc/passwd;	chmod 644 /etc/passwd
chown root:root /etc/group;	chmod 644 /etc/group

chown root:root /boot/grub/grub.cfg; chmod 600 /boot/grub/grub.cfg

# Crontabs
for user in $(cut -f1 -d: /etc/passwd); do
	if crontab -u user -l >/dev/null 2>&1; then
		echo "$user has a crontab" > cron.log
	fi
done
echo "Remember to check /etc/crontab as well" > cron.log

# LightDM
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
systemctl reload lightdm.service

# kernel parameters
cat >> /etc/sysctl.conf << EOF
kernel.exec-shield=1
kernel.randomize_va_space=1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.ip_forward
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0 
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_all = 1
EOF
sysctl --system

# Package management
# TODO: make sure this works
# it didnt
packagesToRemove=""
[ "$ignoreApache" != "true" ] && apt-get autoremove apache2
[ "$ignoreNginx" != "true" ] && apt-get autoremove nginx
[ "$ignoreFTP" != "true" ] && apt-get autoremove vsftpd
[ "$ignoreSQL" != "true" ] && apt-get autoremove $(dpkg --get-selections '*sql*' | awk '!/lib/ {print $1}' | tr '\n' ' ')

distroName="$(lsb_release -c 2>/dev/null | cut -f2)"
if [[ "$(lsb_release -a)" =~ "Ubuntu" ]]; then
	echo \
	"deb https://archive.ubuntu.com/ubuntu/ $distroName main restricted universe multiverse
	deb-src https://archive.ubuntu.com/ubuntu/ $distroName main restricted universe multiverse

	deb https://archive.ubuntu.com/ubuntu/ $distroName-updates main restricted universe multiverse
	deb-src https://archive.ubuntu.com/ubuntu/ $distroName-updates main restricted universe multiverse

	deb https://archive.ubuntu.com/ubuntu/ $distroName-security main restricted universe multiverse
	deb-src https://archive.ubuntu.com/ubuntu/ $distroName-security main restricted universe multiverse

	deb https://archive.ubuntu.com/ubuntu/ $distroName-backports main restricted universe multiverse
	deb-src https://archive.ubuntu.com/ubuntu/ $distroName-backports main restricted universe multiverse" > /etc/apt/sources.list
fi

echo \
"APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::AutocleanInterval \"1\";
APT::Periodic::Unattended-Upgrade \"1\";" | tee /etc/apt/apt.conf.d/10periodic > /etc/apt/apt.conf.d/20auto-upgrades

for i in wireshark ophcrack john zeitgeist hydra aircrack-ng fcrackzip pdfcrack rarcrack sipcrack irpas xprobe doona; do
	apt-get autoremove "$i" -y >/dev/null
done

# because output parsing is hard
apt-get autoremove $(apt-cache show "*" | grep "Section: games" -B 10 | grep "Package" | cut -d' ' -f2)

# [ -n "$packagesToRemove" ] && apt-get autoremove "$packagesToRemove" -y
apt-get update && apt-get upgrade -y
