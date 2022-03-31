echo "V-51391 A file integrity baseline must be created. (.db.gz)"
grep DBDIR /etc/aide.conf | awk '{print $3}' | xargs -i ls -l {$1}
echo
echo "V-51379 All device files must be monitored by the system Linux Security Module. (none)"
ls -lRZ /dev | grep unlabeled_t
echo
echo "V-38496 Default OS accounts, other than root, must be locked. (root & non-os account)"
echo "(show locked accounts) -----"
awk -F: '($4 < 1){print $1"-"$2}' /etc/shadow
echo "----- (show accounts not locked)"
grep -v ':!!/$' /etc/shadow | awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"&&$2!="x"){print $0}' | awk -F: '{print $1}'
echo
echo "V-38465 Library files must have mode 0755 or less permissive. (none)"
find -L /lib /lib64 /usr/lib /usr/lib64 /lib/modules -perm 022 -type f -ls
echo
echo "V-38466 Library files must be owned by a system account. (none or system account)"
find -L /lib /lib64 /usr/lib /usr/lib64 /lib/modules ! -user root -ls
echo
echo "V-38593 The DoD login banner must be displayed immediately prior to, or as part of, console login prompts."
head -50c /etc/issue
echo
echo
echo "V-38596 The system must implement virtual address space randomization. (2,2)"
sysctl kernel.randomize_va_space
grep kernel.randomize_va_space /etc/sysctl.conf
echo
echo "V-38597 The system must limit the ability of processes to have simultaneous write and execute access to memory. (1,1)"
sysctl kernel.exec-shield
grep kernel.exec-shield /etc/sysctl.conf
echo
echo "V-38549 The system must employ a local IPv6 firewall."
echo "V-38551 The OS must connect to external networks or info systems only through managed IPv6 interfaces..."
echo "V-38553 The OS must prevent public IPv6 access into an organizations internal networks..."
echo "(IPv6 enabled? network config) -----"
grep -i 'ipv6' /etc/sysconfig/network
echo "----- (interface addr)"
ip -f inet6 addr
echo "----- (If so, check IPv6 firewall)"
service ip6tables status
echo
echo "V-38560 The OS must connect to external networks or info systems only through managed IPv4 interfaces..."
echo "V-38513 The systems local IPv4 firewall must implement a deny-all policy for inbound packets. (DROP)"
service iptables status | grep -i input
echo
echo "V-38519 All rsyslog-generated log files must be group-owned by root. (none)"
ls -l /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/spooler /var/log/boot.log | awk '($4!="root"){print$0}'
echo
echo "V-38623 All rsyslog-generated log files must have mode 0600 or less permissive. (none)"
find -L /var/log/messages /var/log/secure /var/log/maillog /var/log/cron /var/log/spooler /var/log/boot.log -type f -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(l>6||m>0||n>0)print $0;}'
echo
echo "V-38624 System logs must be rotated daily."
echo "(logrotate cron) -----"
ls -l /etc/cron.daily/logrotate
echo "----- (logrotate log)"
grep logrotate /var/log/cron | tail -1
echo
echo "V-38628 The OS must produce audit records to establish the identity of any user associated with the event. (running)"
echo "V-38631 The OS must employ auto mechanisms to facilitate the monitoring and control of remote access methods."
echo "V-38632 The OS must produce audit records to establish what type of events occurred."
service auditd status
echo
echo "V-38634 The system must rotate audit log files that reach the maximum file size. (ROTATE)"
grep max_log_file_action /etc/audit/auditd.conf
echo
echo "V-38540 The audit system must be configured to audit modifications to the systems network configuration."
echo "(sethostname setdomainname /etc/issue /etc/issue.net /etc/hosts /etc/sysconfig/network) -----"
egrep '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules
echo
echo "V-38566 The audit system must be configured to audit failed attempts to access files and programs. (EACCES EPERM)"
egrep '(EACCES|EPERM)' /etc/audit/audit.rules
echo
echo "V-38567 The audit system must be configured to audit all use of setuid and setgid programs."
lvscan | awk -F\' '{print$2}' | awk -F/ '{print$4}' | \
xargs -i sh -c "mount | grep "{$1}" | grep on" | awk '{print$3}' | grep -v '^/$' | \
xargs -i find {$1} -xdev -type f -perm 6000 | xargs -i -t grep {$1} /etc/audit/audit.rules
echo
echo "V-38609 The TFTP service must not be running. (off or error)"
chkconfig --list tftp
echo
echo "V-38617 The SSH daemon must be configured to use only FIPS 140-2 approved ciphers. (aes ctr)"
grep -i 'cipher' /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-38652 Remote file systems must be mounted with the nodev option. (nodev)"
echo "V-38654 Remote file systems must be mounted with the nosuid option. (nosuid)"
mount | grep 'type nfs'
echo
echo "V-38655 The noexec option must be added to removable media partitions."
cat /etc/fstab
echo
echo "V-38657 The system must use SMB client signing for connecting to samba servers using mount.cifs."
echo "(installed?) -----"
yum list installed | egrep '(samba-client|samba4-client)'
echo "----- (if so, sec in fstab?)"
grep sec /etc/fstab
echo
echo "V-38663 RPM must verify permissions on all files and dirs associated with the audit package."
echo "V-38664 RPM must verify ownership on all files and dirs associated with the audit package."
echo "V-38665 RPM must verify group-ownership on all files and dirs associated with the audit package."
echo "V-38637 RPM must verify contents of all files associated with the audit package."
echo "(no M, no U, no G, no 5 w/o a 'c' column) -----"
rpm -V audit
echo
echo "V-38643 There must be no world-writable files on the system. (none)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/dev/ d' -e '/sys/ d' -e '/selinux/ d' | \
xargs -i find /{$1} -xdev -type f -perm -002 ! -fstype nfs -ls
echo
echo "V-38681 All GIDs referenced in /etc/passwd must be defined in /etc/group (none)"
pwck -r | grep 'no group'
echo
echo "V-38683 All accounts on the system must have unique user or account names (none)"
pwck -rq
echo
echo "V-38693 The system must require passwords to contain no more than three consecutive repeating characters. (maxrepeat=3)"
grep pam_cracklib /etc/pam.d/system-auth
echo
echo "V-38695 A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries."
echo "V-38696 The operating system must employ automated mechanisms, per organization defined frequency, to detect the addition of unauthorized components/devices into the operating system."
echo "V-38698 The operating system must employ automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency."
echo "V-38700 The operating system must provide a near real-time alert when any of the organization defined list of compromise or potential compromise indicators occurs."
echo "V-38670 The operating system must detect unauthorized changes to software and information."
echo "V-38673 The operating system must ensure unauthorized, security-relevant configuration changes detected are tracked."
echo "(report weekly, update monthly) -----"
ls -l /etc/cron* | egrep '(etc/cron|aide)'
echo
echo "V-38678 The audit system must provide a warning when allocated audit record storage volume reaches a documented percent..."
echo "(df audit) -----"
df -ah | egrep '(^File|audit)'
echo "----- (auditd.conf)"
grep '^space_left ' /etc/audit/auditd.conf
echo
echo "V-38682 The Bluetooth kernel module must be disabled. (/bin/true)"
grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d | grep -i '/bin/true' | grep -v '^#'
echo
echo "V-38686 The systems local firewall must implement a deny-all policy for forwarded packets. (DROP)"
iptables -nvL | grep -i forward
echo
echo "V-38689 The DoD login banner must be displayed immediately prior to graphical desktop environment login prompts."
echo "(yum) -----"
yum list installed | grep -i gconf2
echo "----- (gconf)"
gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--get /apps/gdm/simple-greeter/banner_message_text | head -50c
echo
echo
echo "V-38697 The sticky bit must be set on all public directories."
lvscan | awk -F\' '{print$2}' | awk -F/ '{print$4}' | \
xargs -i sh -c "mount | grep "{$1}" | grep on" | awk '{print$3}' | grep -v '^/$' | \
xargs -i -t find {$1} -xdev -type d -perm -002 ! -perm 1000
echo
echo "V-38699 All public directories must be owned by a system account."
lvscan | awk -F\' '{print$2}' | awk -F/ '{print$4}' | \
xargs -i sh -c "mount | grep "{$1}" | grep on" | awk '{print$3}' | grep -v '^/$' | \
xargs -i -t find {$1} -xdev -type d -perm -0002 -uid +499
echo
echo "V-38702 The FTP daemon must be configured for logging or verbose mode. (YES)"
grep '^xferlog_enable' /etc/vsftpd/vsftpd.conf
echo
echo "V-38660 The snmpd service must use only SNMP protocol version 3 or newer."
echo "V-38653 The snmpd service must not use a default password. (none, none)"
egrep '(v1|v2|com2sec)' /etc/snmp/snmpd.conf | grep -v '^#'
grep -i public /etc/snmp/snmpd.conf | grep -v '^#'
echo
echo "V-38619 There must be no .netrc files on the system. (none)"
find /root /export/home -xdev -name .netrc
echo
echo "V-38599 The FTPS/FTP service on the system must be configured with the DoD login banner. (/etc/issue)"
grep 'banner_file' /etc/vsftpd/vsftpd.conf
echo
echo "V-38493 Audit log directories must have mode 0755 or less permissive. (<755)"
grep '^log_file' /etc/audit/auditd.conf | awk '{print$3}' | xargs -i ls -l {$1}
echo
echo "V-38488 The OS must conduct backups of user-level info contained in the OS per defined frequency to conduct backups..."
echo "V-38486 The OS must conduct backups of system-level info contained in the IS per defined frequency to conduct backups..."
yum list lgtoclnt | grep lgtoclnt
echo
echo "V-38484 The OS must display to the user the date and time of the last logon or access via ssh. (yes)"
grep -i printlastlog /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-38474 The system must allow locking of graphical desktop sessions."
gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--get /apps/gnome_settings_daemon/keybindings/screensaver
echo
echo "V-38471 The system must forward audit records to the syslog service. (yes)"
grep active /etc/audisp/plugins.d/syslog.conf
echo
echo "V-38468 The audit system must take appropriate action when the audit storage volume is full."
echo "V-38464 The audit system must take appropriate action when there are disk errors on the audit storage volume."
echo "(full SYSLOG) -----"
grep 'disk_full_action' /etc/audit/auditd.conf
echo "----- (error SYSLOG)"
grep 'disk_error_action' /etc/audit/auditd.conf
echo
echo "V-38460 The NFS server must not have the all_squash option enabled. (none)"
grep 'all_squash' /etc/exports
echo
echo "V-38454 RPM must verify ownership on all files and directories associated with packages."
echo "V-38453 RPM must verify group-ownership on all files and directories associated with packages."
echo "V-38452 RPM must verify permissions on all files and directories associated with packages."
echo "V-38447 RPM must verify contents of all files associated with packages."
echo "(no U, no G, no M, no 5 w/o a 'c' column) -----"
rpm -Va 
echo
echo "V-38446 The mail system must forward all mail for root to one or more sys admins."
grep '^root' /etc/aliases
echo
echo "V-38445 Audit log files must be group-owned by root. (root)"
grep '^log_file' /etc/audit/auditd.conf | awk '{print$3}' | xargs -i ls -l {$1}
echo
echo "V-38444 The systems local IPv6 firewall must implement a deny-all policy for inbound packets. (none or 0, DROP)"
echo "(IPv6 available?) -----"
grep -i 'ipv6' /etc/sysconfig/network
echo "----- (if so, enabled in sysctl?)"
sysctl -a | grep ipv6
echo "----- ( ifso, ip6tables)"
grep 'DROP' /etc/sysconfig/ip6tables
echo
echo "V-43150 The login user list must be disabled. (true)"
gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--get /apps/gdm/simple-greeter/disable_user_list
echo
echo "V-57569 The noexec option must be added to the /tmp partition. (noexec)"
grep ' /tmp ' /etc/fstab | grep noexec
echo
echo "V-58901 The sudo command must require authentication. (none except keyed logins)"
egrep -i '(nopasswd|!auth)' /etc/sudoers
echo
