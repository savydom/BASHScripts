echo "V-whatever GNOME installed (multiple items are NA with no GNOME)"
yum list installed | grep -i gnome
echo
echo "V-71849 The file permissions, ownership, and group membership of system files and commands must match the vendor values."
echo "(Check that perms are vendor values or better i.e.STIG)-----"
rpm -Va | grep '^.M' | grep -v '.[c] /' | cut -c 13- | xargs ls -ld
echo
echo "V-71855 The cryptographic hash of system files and commands must match vendor values."
echo "(Check that list has no exes, if exe, it may be updated i.e.McAfee)-----"
rpm -Va | grep '^..5' | grep -v '.[c] /' | cut -c 13- | xargs ls -ld
echo
echo "V-71863 The OS must display the Standard Mandatory DoD Notice and Consent Banner before granting"
echo "local or remote access to the system via a command line user logon."
grep -i 'government' /etc/issue | head -c 50
echo
echo
echo "V-71897 The OS must have the screen package installed."
yum list installed | grep -i screen
echo
echo "V-73159 When passwords are changed or new passwords are established, pwquality must be used."
echo "(/etc/pam.d/passwd)----"
grep pwquality /etc/pam.d/passwd | grep -v '^#'
echo "-----(/etc/pam.d/password-auth-ac)"
grep pwquality /etc/pam.d/password-auth-ac | grep -v '^#'
echo "-----(/etc/pam.d/password-auth-local)"
grep pwquality /etc/pam.d/password-auth-local | grep -v '^#'
echo
echo "V-71903 When passwords are changed or new passwords are established,"
echo "the new password must contain at least one upper-case character. (-1)"
grep ucredit /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71905 When passwords are changed or new passwords are established,"
echo "the new password must contain at least one lower-case character. (-1)"
grep lcredit /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71907 When passwords are changed or new passwords are established,"
echo "the new password must contain at least one numeric character. (-1)"
grep dcredit /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71909 When passwords are changed or new passwords are established,"
echo "the new password must contain at least one special character. (-1)"
grep ocredit /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71911 When passwords are changed a minimum of eight of the total number of characters must be changed. (8)"
grep difok /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71913 When passwords are changed a minimum of four character classes must be changed. (4)"
grep minclass /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71915 When passwords are changed the number of repeating consecutive characters must not be more than four characters. (<=3)"
grep maxrepeat /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71917 When passwords are changed the number of repeating characters of the same character class"
echo "must not be more than four characters. (<=4)"
grep maxclassrepeat /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71919 The PAM system service must be configured to store only encrypted representations of passwords. (sha512)"
echo "(pam passwd)----"
grep password /etc/pam.d/passwd | grep -v '^#'
echo "-----(pam password-auth-ac)"
grep password /etc/pam.d/password-auth-ac | grep -v '^#'
echo "-----(pam password-auth-local)"
grep password /etc/pam.d/password-auth-local | grep -v '^#'
echo
echo "V-71921 The shadow file must be configured to store only encrypted representations of passwords. (SHA512)"
grep -i encrypt /etc/login.defs | grep -v '^#'
echo
echo "V-71923 User and group account admin utilities must be configured to store only encrypted"
echo "representations of passwords. (sha512)"
grep sha512 /etc/libuser.conf | grep -v '^#'
echo
echo "V-71925 Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime. (1)"
grep -i pass_min_days /etc/login.defs | grep -v '^#'
echo
echo "V-71927 Passwords must be restricted to a 24 hours/1 day minimum lifetime. (none)"
awk -F: '($4 < 1){print $1}' /etc/shadow
grep -v ':!!/$' /etc/shadow | awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"&&$2!="x"){print $0}' | awk -F: '($4 < 1){print $1}'
echo
echo "V-71929 Passwords for new users must be restricted to a 60-day maximum lifetime. (60)"
grep -i pass_max_days /etc/login.defs | grep -v '^#'
echo
echo "V-71931 Existing passwords must be restricted to a 60-day maximum lifetime. (service accounts ok-365)"
awk -F: '($4 < 1){print $1}' /etc/shadow
grep -v ':!!/$' /etc/shadow | awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"&&$2!="x"){print $0}' | awk -F: '($5 > 60){print $1}'
echo
echo "V-71933 Passwords must be prohibited from reuse for a minimum of five generations. (remember>=5)"
echo "(pam passwd)----"
grep remember /etc/pam.d/passwd | grep -v '^#'
echo "-----(pam password-auth-ac)"
grep remember /etc/pam.d/password-auth-ac | grep -v '^#'
echo "-----(pam password-auth-local)"
grep remember /etc/pam.d/password-auth-local | grep -v '^#'
echo
echo "V-71935 Passwords must be a minimum of 15 characters in length. (15)"
grep minlen /etc/security/pwquality.conf | grep -v '^#'
echo
echo "V-71937 The system must not have accounts configured with blank or null passwords. (none)"
echo "(pam passwd)----"
grep nullok /etc/pam.d/passwd | grep -v '^#'
echo "-----(pam password-auth-ac)"
grep nullok /etc/pam.d/password-auth-ac | grep -v '^#'
echo "-----(pam password-auth-local)"
grep nullok /etc/pam.d/password-auth-local | grep -v '^#'
echo
echo "V-71939 The SSH daemon must not allow authentication using an empty password. (none/no)"
grep -i PermitEmptyPass /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-71941 The OS must disable account identifiers (individuals, groups, roles, and devices) if the password expires. (0)"
grep -i inactive /etc/default/useradd | grep -v '^#'
echo
echo "V-71943 Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked"
echo "for the maximum configurable period. (3/900/604800)"
echo "(pam passwd)----"
grep pam_faillock.so /etc/pam.d/passwd | grep -v '^#'
echo "-----(pam password-auth-ac)"
grep pam_faillock.so /etc/pam.d/password-auth-ac | grep -v '^#'
echo "-----(pam password-auth-local)"
grep pam_faillock.so /etc/pam.d/password-auth-local | grep -v '^#'
echo
echo "V-71945 If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked. (even_deny_root)"
echo "(pam passwd)----"
grep -i even_deny_root /etc/pam.d/passwd | grep -v '^#'
echo "-----(pam password-auth-ac)"
grep -i even_deny_root /etc/pam.d/password-auth-ac | grep -v '^#'
echo "-----(pam password-auth-local)"
grep -i even_deny_root /etc/pam.d/password-auth-local | grep -v '^#'
echo
echo "V-71947 Users must provide a password for privilege escalation. (OK for usr/grp that login with keys)"
grep -i nopasswd /etc/sudoers /etc/sudoers.d/* | grep -v '^#'
echo
echo "V-71949 Users must re-authenticate for privilege escalation. (none)"
grep -i authenticate /etc/sudoers /etc/sudoers.d/* | grep -v '^#'
echo
echo "V-71951 The delay between logon prompts following a failed console logon attempt must be at least four seconds. (4)"
grep -i fail_delay /etc/login.defs | grep -v '^#'
echo
echo "V-71957 The OS must not allow users to override SSH environment variables. (no)"
grep -i PermitUserEnv /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-71959 The OS must not allow a non-certificate trusted host SSH logon to the system. (no)"
grep -i HostBasedAuth /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-71961 Systems with a BIOS must require authentication upon booting into"
echo "single-user and maintenance modes. (pbkdf2 root)"
grep -i password /boot/grub2/grub.cfg | grep -v '^#'
echo
echo "V-77823 The OS must require authentication upon booting into single-user and maintenance modes. (sulogin option)"
grep -i execstart /usr/lib/systemd/system/rescue.service
echo
echo "V-71965 The OS must uniquely identify and must authenticate organizational users"
echo "(or processes acting on behalf of organizational users) using multifactor authentication. (cannot enable, actions not blank)"
authconfig --test | grep -i smartcard
echo
echo "V-71967 The rsh-server package must not be installed. (none)"
yum list installed | grep -i rsh-server
echo
echo "V-71969 The ypserv package must not be installed. (none)"
yum list installed | grep -i ypserv
echo
echo "V-71971 The OS must prevent non-privileged users from executing privileged functions to include"
echo "disabling, circumventing, or altering implemented security safeguards/countermeasures."
echo "(admin accounts sysadm or staff)----"
semanage login -l | egrep '(sysadm|staff)'
echo "(non-admin accounts user)----"
semanage login -l | grep user
echo
echo "V-71973 A file integrity tool must verify the baseline OS configuration at least weekly."
grep -i aide /etc/cron*/* | grep -v '^#'
echo
echo "V-71975 Designated personnel must be notified if baseline configurations are changed in an unauthorized manner. (mail)"
grep -i aide /etc/cron*/* |  grep -v '^#' | grep mail
echo
echo "V-71977"
echo "V-71979"
echo "V-71981 The OS must prevent the installation of software, patches, service packs,"
echo "device drivers, or OS components from a repository without verification they have been digitally signed"
echo "using a cert that is issued by a CA that is recognized and approved by the organization. (1,1,0)"
grep gpgcheck /etc/yum.conf | grep -v '^#'
echo
echo "V-71983 USB mass storage must be disabled. (blacklist usb-storage)"
#grep -i usb-storage /etc/modprobe.d/*
grep -i usb-storage /etc/modprobe.d/blacklist.conf
echo
echo "V-77821 The DCCP Kernel module must be disabled unless required. (install dccp /bin/true)"
grep -i dccp /etc/modprobe.d/*
echo
echo "V-71985 File system automounter must be disabled unless required. (active for ldap/nfs)"
systemctl status autofs | grep -i active
echo
echo "V-71987 The OS must remove all software components after updated versions have been installed. (1)"
grep -i clean_require /etc/yum.conf
echo
echo "V-71989 The OS must enable SELinux. (Enforcing)"
getenforce
echo
echo "V-71991 The OS must enable the SELinux targeted policy. (targeted)"
sestatus | grep -i target
echo
echo "V-71993 The x86 Ctrl-Alt-Delete key sequence must be disabled."
systemctl status ctrl-alt-del.service
echo
echo "V-71995 The OS must define default permissions for all authenticated users in such a way"
echo "that the user can only read and modify their own files. (077)"
grep -i umask /etc/login.defs | grep -v '^#'
echo
echo "V-71997 The OS must be a vendor supported release."
echo "(current kernel) -----"
uname -r | awk '{print "kernel-"$0}'
echo "----- (avail kernels)"
rpm -qa -last | grep kernel | egrep -v '(debug|dev|head|tool)'
echo
echo "V-72001 The system must not have unnecessary accounts. (no games,news,gopher,or ftp)"
awk -F: '{print $1}' /etc/passwd
echo
echo "V-72003 All GIDs referenced in the /etc/passwd file must be defined in the /etc/group file."
echo "(pwck) -----"
pwck -r
echo "----- (accounts and groups)"
awk -F: '{print $1":"$4}' /etc/passwd | gawk -F: '{p=":"$2":";("grep "p" /etc/group" | getline u);close("grep "p" /etc/group"); \
if (u~p) n=split(u,o);printf("%20s %10s %20s\n", $1, $2, o[1]);p="";u="";}'
echo
echo "V-72005 The root account must be the only account having unrestricted access to the system. (root)"
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo
echo "V-72007 All files and dirs must have a valid owner. (none)"
find / -xdev -fstype xfs -nouser
echo
echo "V-72009 All files and dirs must have a valid group owner. (none)"
find / -xdev -fstype xfs -nogroup
echo
echo "V-72011 All local interactive users must have a home dir assigned in the /etc/passwd file."
echo "(pwck) -----"
pwck -r
echo "----- (home dirs)"
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i ls -ld /{$1}
echo
echo "V-72013 All local interactive user accounts, upon creation, must be assigned a home dir. (yes)"
grep -i create_home /etc/login.defs | grep -v '^#'
echo
echo "V-72015 All local interactive user home dirs defined in the /etc/passwd file must exist."
echo "V-72017 All local interactive user home dirs must have mode 0750 or less permissive. (<=750)"
echo "V-72019 All local interactive user home dirs must be owned by their respective users."
echo "V-72021 All local interactive user home dirs must be group-owned by the home directory owners primary group."
ls -ld $(egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)
echo
echo "V-72023 All files and dirs contained in local interactive user home dirs must be owned by the owner of the home dir."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i -t sh -c "ls -alr /{$1} | grep -v '^total'" 2>&1 | gawk '{if($3!~"root")print $0;}' |\
awk '{if($1=="sh")print $5;else if($1!="sh")print$0}'
echo
echo "V-72025 All files and dirs contained in local interactive user home dirs must be group-owned by a group of which the home dir owner is a member."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i -t sh -c "ls -alr /{$1} | grep -v '^total'" 2>&1 | awk '{if($3!~$4)print $0;}' |\
awk '{if($1=="sh")print $5;else if($1!="sh")print$0}'
echo
echo "V-72027 All files and dirs contained in local interactive user home dirs must have mode 0750 or less permissive. (<=750)"
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | grep -i home | xargs -i find -L /{$1} ! -fstype nfs -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>0)print $0;}'
echo
echo "V-72029 All local init files for interactive users must be owned by the home dir user or root."
echo "V-72031 Local init files for local interactive users must be group-owned by the users primary group or root."
echo "V-72033 All local initialization files must have mode 0740 or less permissive. (<=740)"
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "ls -l ~USER/.[a-zA-Z]* 2>/dev/null" | \
egrep -v '(^total|^$)' | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3){a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);\
if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}\
else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}if(m>4||n>0)print"--> "$0;else print$0;}' | sed 's/^--> \//\//'
echo
echo "V-72035 All local interactive user init files executable search paths must contain"
echo "only paths that resolve to the users home dir."
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "ls -p ~USER/.[a-zA-Z]* 2>/dev/null" | \
awk '{a=substr($1,1,1);b=substr($1,1,length($1)-1);c=substr($1,length($1),1); if (a=="/"&&c==":")print "cd "b; \
else if(a!=""&&c!="/")print "egrep -H (^PATH) "$1;}' | sed -e "s/(/'(/" -e "s/)/)'/" > /var/tmp/chkpath.sh
sh /var/tmp/chkpath.sh 2>/dev/null | egrep '(\./|::|=:|\$)' | grep -v '.bash_history'
echo
echo "V-72037 Local init files must not execute world-writable programs. (Makes WWList)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -perm -002 ! -fstype nfs -ls | \
awk '{if(substr($3,1,1)!="l")print $11;}' | egrep -v '(^$|^/var/tmp|^/tmp|^/dev/null)' > /var/tmp/wwflist.txt
echo "----- (Show startup scripts that have WW files referenced) (/dev/null, /var/tmp are false culprits)"
#ls -l /export/home/*/* | grep -v '^d' | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " " | xargs -i -t fgrep -f /var/tmp/wwflist.txt {$1} | grep -v '^#'
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "fgrep -f /var/tmp/wwflist.txt ~USER/.[a-zA-Z]* 2>/dev/null" | \
grep -v '.bash_history'
echo
echo "V-72039 All system device files must be correctly labeled to prevent unauthorized modification."
echo "(device_t - vmci vsock ok) -----"
find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"
echo "----- (unlabeled_t)"
find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"
echo
echo "V-72041 FS that contain user home dirs must be mounted to prevent files with the setuid and setgid bit set from being executed."
echo "(mtab nosuid & nodev) -----"
grep home /etc/mtab | egrep -i '(nosuid|nodev)'
echo "----- (fstab nosuid & nodev)"
grep home /etc/fstab | egrep -i '(nosuid|nodev)'
echo
echo "V-72043 FS that are used with removable media must be mounted to prevent files with the setuid and setgid bit set"
echo "from being executed. (fstab non nosuid+nodev entries - removable?)"
grep -vi xfs /etc/fstab | egrep -vi '(nosuid|nodev)' | grep -v '^#'
echo
echo "V-72045 FS that are being imported via NFS must be mounted to prevent files with the setuid and setgid bit set"
echo "from being executed. (fstab non nosuid+nodev entries - nfs?)"
grep -i nfs /etc/fstab | egrep -i '(nosuid|nodev)' | grep -v '^#'
echo
echo "V-73161 FS that are being imported via NFS must be mounted to prevent binary files from being executed."
echo "(fstab non nosuid+nodev entries - nfs?) -----"
grep -i nfs /etc/fstab | grep -i noexec | grep -v '^#'
echo
echo "V-72047 All world-writable directories must be group-owned by root, sys, bin, or an application group."
find / -xdev -perm -002 -type d -fstype xfs -exec ls -lLd {} \;
echo
echo "V-72049 The umask must be set to 077 for all local interactive user accounts."
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -i grep "^{$1}:" /etc/passwd | awk -F: '{print $6}' | grep '^/' | \
xargs -i sh -c "grep -i umask {$1}/.*" | grep -v '.bash_history'
echo
echo "V-72051 Cron logging must be implemented."
grep cron /etc/rsyslog.conf | grep -v '^#'
echo
echo "V-72053 If the cron.allow file exists it must be owned by root."
echo "V-72055 If the cron.allow file exists it must be group-owned by root."
ls -l /etc/cron.allow
echo
echo "V-72057 Kernel core dumps must be disabled unless needed. (inactive)"
systemctl status kdump.service | grep -i active
echo
echo "V-72059 A separate file system must be used for user home directories."
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | grep -v root | xargs -i grep "^{$1}:" /etc/passwd | awk -F: '{print $6}' | \
gawk -F/ '{for (i=1;i<NF;i++) {while("grep "$i" /etc/fstab" | getline ft) tf[j++]=ft; for (j in tf) if (tf[j]~$i) print tf[j];for (j in tf) tf[j]="";}\
;close("grep "$i" /etc/fstab");}' | egrep -v '(^$|^ )'
echo
echo "V-72061 The system must use a separate file system for /var."
echo "V-72063 The system must use a separate file system for the system audit data path."
echo "V-72065 The system must use a separate file system for /tmp. (enabled unless defined in fstab)"
echo "(var fstab) -----"
egrep '(var|tmp)' /etc/fstab | grep -v '^#'
echo "----- (tmp mount service)"
systemctl is-enabled tmp.mount
echo
echo "V-72067 The OS must implement NIST FIPS-validated cryptography for the following: to provision digital signatures,"
echo "to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable"
echo "federal laws, Executive Orders, directives, policies, regulations, and standards. (dracut,fips=1,1)"
echo "(FIPS) -----"
yum list installed | grep fips
echo "----- (grub)"
grep fips /boot/grub2/grub.cfg | sort | tail -n1
echo "----- (proc fips_enabled)"
cat /proc/sys/crypto/fips_enabled
echo
echo "V-72069 The file integrity tool must be configured to verify ACLs."
echo "V-72071 The file integrity tool must be configured to verify extended attributes."
echo "V-72073 The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and dirs."
echo "(acl) -----"
egrep -iB1 '(^# /|^/|^!/|^NORM|^LSSP|^PERM|^DIR|^LOG|^DATA)' /etc/aide.conf | egrep -v '(^--|^$|database)' | grep -i acl
echo "----- (xattr)"
egrep -iB1 '(^# /|^/|^!/|^NORM|^LSSP|^PERM|^DIR|^LOG|^DATA)' /etc/aide.conf | egrep -v '(^--|^$|database)' | grep -i xattrs
echo "----- (fips approved)"
egrep -iB1 '(^# /|^/|^!/|^NORM|^LSSP|^PERM|^DIR|^LOG|^DATA)' /etc/aide.conf | egrep -v '(^--|^$|database)' | grep -i sha512
echo
echo "V-72075 The system must not allow removable media to be used as the boot loader unless approved."
find / -name grub.cfg | xargs -i egrep '(^menuentry|set root)' {$1} | awk '{j++; print j, substr($0,1,29);}'
echo
echo "V-72077 The telnet-server package must not be installed. (none)"
yum list installed | grep -i telnet-server
echo
echo "V-72079 Auditing must be configured to produce records containing information to establish what type of events occurred,"
echo "where the events occurred, the source of the events, and the outcome of the events."
echo "These audit records must also identify individual identities of group account users. (active)"
systemctl is-active auditd.service
echo
echo "V-72081 The OS must shut down upon audit processing failure, unless availability is an overriding concern."
echo "If availability is a concern, the system must alert the designated staff in the event of an audit processing failure. (faulure 1 or 2)"
#grep '\-f [1-2]' /etc/audit/audit.rules
auditctl -s | grep -i fail
echo
echo "V-72083 The OS must off-load audit records onto a different system or media from the system being audited."
echo "(audisp config) -----"
grep -i remote_server /etc/audisp/audisp-remote.conf | grep -v '^#'
echo "----- (splunk config)"
grep -i targeturi /opt/splunkforwarder/etc/apps/nola_all_deploymentclient/local/deploymentclient.conf
echo
echo "V-72085 The OS must encrypt the transfer of audit records off-loaded onto a different system or media"
echo "from the system being audited. (yes)"
echo "(audisp config) -----"
grep -i enable_krb5 /etc/audisp/audisp-remote.conf | grep -v '^#'
echo
echo "V-72087 The audit system must take appropriate action when the audit storage volume is full. (syslog/single/halt)"
echo "V-73163 The audit system must take appropriate action when there is an error sending audit records"
echo "to a remote system. (syslog/single/halt)"
echo "(audisp config) -----"
egrep -i '(disk_full_action|network_failure_action)' /etc/audisp/audisp-remote.conf | grep -v '^#'
echo
echo "V-72089 The OS must immediately notify the SA and ISSO when allocated audit record storage volume reaches 75%"
echo "of the repository maximum audit record storage capacity."
grep '^log_file ' /etc/audit/auditd.conf | awk '{print $3}' | sed 's:\/[.0-9a-zA-Z]*$::' | xargs -i sh -c "df '"{$1}"' | grep '"{$1}"'" | \
awk '{("grep -i ''^space_left '' /etc/audit/auditd.conf" | getline sl);close("grep -i ''^space_left '' /etc/audit/auditd.conf");n=split(sl,p," "); \
s=p[3]*1024;t=$2*.25;print "audit.conf",sl,"x 1024 = Is ",s,"=>",t," ? (25% of",$2,"1K blocks) for",$6;}' 
echo
echo "V-72091 The OS must immediately notify the SA and ISSO via email when the threshold for the repository"
echo "maximum audit record storage capacity is reached. (email)"
grep -i '^space_left_action'  /etc/audit/auditd.conf
echo
echo "V-72093 The OS must immediately notify the SA and ISSO when the threshold for the repository"
echo "maximum audit record storage capacity is reached. (root)"
grep -i '^action_mail_acct' /etc/audit/auditd.conf
echo
echo "V-72095 All privileged function executions must be audited. (listed are not in audit - some are symlinks however)"
df -h | grep '^\/' | awk '{print$6;}' | xargs -i find {$1} -xdev -type f \( -perm -4000 -o -perm -2000 \) | \
xargs -i -t grep -c {$1} /etc/audit/audit.rules 2>&1 | \
awk '{j=1;i=1;ft="";FS="\n";tf[j]=$0;j++;while (getline){tf[j]=$0;j++}; for (i=1;i<j;i++){if (tf[i]==0) print tf[i-1]}}' | awk '{print $3}'
echo
echo "V-72097 All uses of the chown command must be audited."
echo "V-72099 All uses of the fchown command must be audited."
echo "V-72101 All uses of the lchown command must be audited."
echo "V-72103 All uses of the fchownat command must be audited."
grep -i 'chown' /etc/audit/audit.rules
echo
echo "V-72105 All uses of the chmod command must be audited."
echo "V-72107 All uses of the fchmod command must be audited."
echo "V-72109 All uses of the fchmodat command must be audited."
grep -i chmod /etc/audit/audit.rules
echo
echo "V-72111 All uses of the setxattr command must be audited."
echo "V-72113 All uses of the fsetxattr command must be audited."
echo "V-72115 All uses of the lsetxattr command must be audited."
grep -i setxattr /etc/audit/audit.rules
echo
echo "V-72117 All uses of the removexattr command must be audited."
echo "V-72119 All uses of the fremovexattr command must be audited."
echo "V-72121 All uses of the lremovexattr command must be audited."
grep -i removexattr /etc/audit/audit.rules
echo
echo "V-72123 All uses of the creat command must be audited."
grep -i creat /etc/audit/audit.rules
echo
echo "V-72125 All uses of the open command must be audited."
echo "V-72127 All uses of the openat command must be audited."
echo "V-72129 All uses of the open_by_handle_at command must be audited."
grep -i ' open' /etc/audit/audit.rules
echo
echo "V-72131 All uses of the truncate command must be audited."
echo "V-72133 All uses of the ftruncate command must be audited."
grep -i truncate /etc/audit/audit.rules
echo
echo "V-72135 All uses of the semanage command must be audited."
grep -i /usr/sbin/semanage /etc/audit/audit.rules
echo
echo "V-72137 All uses of the setsebool command must be audited."
grep -i /usr/sbin/setsebool /etc/audit/audit.rules
echo
echo "V-72139 All uses of the chcon command must be audited."
grep -i /usr/bin/chcon /etc/audit/audit.rules
echo
echo "V-72141 All uses of the restorecon command must be audited."
grep -i /usr/sbin/restorecon /etc/audit/audit.rules
echo
echo "V-72143 The OS must generate audit records for all successful/unsuccessful account access count events. (tallylog)"
grep -i /var/log/tallylog /etc/audit/audit.rules
echo
echo "V-72145 The OS must generate audit records for all unsuccessful account access events. (faillock)"
grep -i /var/run/faillock /etc/audit/audit.rules
echo
echo "V-72147 The OS must generate audit records for all successful account access events. (lastlog)"
grep -i /var/log/lastlog /etc/audit/audit.rules
echo
echo "V-72149 All uses of the passwd command must be audited."
grep -i /usr/bin/passwd /etc/audit/audit.rules
echo
echo "V-72151 All uses of the unix_chkpwd command must be audited."
grep -i /sbin/unix_chkpwd /etc/audit/audit.rules
echo
echo "V-72153 All uses of the gpasswd command must be audited."
grep -i /usr/bin/gpasswd /etc/audit/audit.rules
echo
echo "V-72155 All uses of the chage command must be audited."
grep -i /usr/bin/chage /etc/audit/audit.rules
echo
echo "V-72157 All uses of the userhelper command must be audited."
grep -i /usr/sbin/userhelper /etc/audit/audit.rules
echo
echo "V-72159 All uses of the su command must be audited."
grep -i '/bin/su ' /etc/audit/audit.rules
echo
echo "V-72161 All uses of the sudo command must be audited."
grep -i '/usr/bin/sudo ' /etc/audit/audit.rules
echo
echo "V-72163 All uses of the sudoers command must be audited. (sudoers,sudoers.d)"
grep /etc/sudoers /etc/audit/audit.rules
echo
echo "V-72165 All uses of the newgrp command must be audited."
grep -i /usr/bin/newgrp /etc/audit/audit.rules
echo
echo "V-72167 All uses of the chsh command must be audited."
grep -i /usr/bin/chsh /etc/audit/audit.rules
echo
echo "V-72169 All uses of the sudoedit command must be audited."
grep -i /usr/bin/sudoedit /etc/audit/audit.rules
echo
echo "V-72171 All uses of the mount command must be audited."
grep -i /bin/mount /etc/audit/audit.rules
echo
echo "V-72173 All uses of the umount command must be audited."
grep -i /bin/umount /etc/audit/audit.rules
echo
echo "V-72175 All uses of the postdrop command must be audited."
grep -i /usr/sbin/postdrop /etc/audit/audit.rules
echo
echo "V-72177 All uses of the postqueue command must be audited."
grep -i /usr/sbin/postqueue /etc/audit/audit.rules
echo
echo "V-72179 All uses of the ssh-keysign command must be audited."
grep -i /usr/libexec/openssh/ssh-keysign /etc/audit/audit.rules
echo
#echo "V-72181 All uses of the pt_chown command must be audited."
#grep -i /usr/libexec/pt_chown /etc/audit/audit.rules
#echo
echo "V-72183 All uses of the crontab command must be audited."
grep -i /usr/bin/crontab /etc/audit/audit.rules
echo
echo "V-72185 All uses of the pam_timestamp_check command must be audited."
grep -i /sbin/pam_timestamp_check /etc/audit/audit.rules
echo
echo "V-72187 All uses of the init_module command must be audited."
grep -i init_module /etc/audit/audit.rules
echo
echo "V-72189 All uses of the delete_module command must be audited."
grep -i delete_module /etc/audit/audit.rules
echo
echo "V-72191 All uses of the insmod command must be audited."
grep -i insmod /etc/audit/audit.rules
echo
echo "V-72193 All uses of the rmmod command must be audited."
grep -i rmmod /etc/audit/audit.rules
echo
echo "V-72195 All uses of the modprobe command must be audited."
grep -i modprobe /etc/audit/audit.rules
echo
echo "V-72197 The OS must generate audit records for all account creations, modifications, disabling,"
echo "and termination events that affect /etc/passwd."
grep /etc/passwd /etc/audit/audit.rules
echo
echo "V-73165 The OS must generate audit records for all account creations, modifications, disabling,"
echo "and termination events that affect /etc/group."
grep /etc/group /etc/audit/audit.rules
echo
echo "V-73167 The OS must generate audit records for all account creations, modifications, disabling,"
echo "and termination events that affect /etc/gshadow."
grep /etc/gshadow /etc/audit/audit.rules
echo
echo "V-73171 The OS must generate audit records for all account creations, modifications, disabling,"
echo "and termination events that affect /etc/shadow."
grep /etc/shadow /etc/audit/audit.rules
echo
echo "V-73173 The OS must generate audit records for all account creations, modifications, disabling,"
echo "and termination events that affect /etc/opasswd."
grep /etc/security/opasswd /etc/audit/audit.rules
echo
echo "V-72199 All uses of the rename command must be audited."
echo "V-72201 All uses of the renameat command must be audited."
grep -i rename /etc/audit/audit.rules
echo
echo "V-72203 All uses of the rmdir command must be audited."
grep -i rmdir /etc/audit/audit.rules
echo
echo "V-72205 All uses of the unlink command must be audited."
echo "V-72207 All uses of the unlinkat command must be audited."
grep -i unlink /etc/audit/audit.rules
echo
echo "V-72209 The system must send rsyslog output to a log aggregation server."
echo "(rsyslog config) -----"
grep @ /etc/rsyslog.conf | grep -v '^#'
echo "----- (splunk config)"
grep -i targeturi /opt/splunkforwarder/etc/apps/nola_all_deploymentclient/local/deploymentclient.conf
echo "----- (splunk items logged)"
egrep -i '(\[|able)' /opt/splunkforwarder/etc/apps/Splunk_TA_nix/local/inputs.conf | \
awk '{j=1;i=1;ft="";FS="\n";tf[j]=$0;j++;while (getline){tf[j]=$0;j++};for (i=1;i<j;i++){if (tf[i]~"0" || tf[i]~"false") print tf[i-1]}}' 
echo
echo "V-72211 The rsyslog daemon must not accept log messages from other servers unless the server"
echo "is being used for log aggregation. (none)"
grep imtcp /etc/rsyslog.conf | grep -v '^#'
echo
echo "V-72213 The system must use a DoD-approved virus scan program. (active)"
echo "(nails) -----"
systemctl status nails | grep -i active
echo
echo "V-72215 The system must update the DoD-approved virus scan program every seven days or more frequently."
ls -al /opt/NAI/LinuxShield/engine/dat/*.dat
echo
echo "V-72217 The OS must limit the number of concurrent sessions to 10 for all accounts and/or account types. (10)"
grep -i maxlogins /etc/security/limits.conf | grep -v '^#'
echo
echo "V-72219 The host must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services,"
echo "as defined in the PPSM CLSA and vulnerability assessments."
firewall-cmd --list-all
echo
echo "V-72221 A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications."
grep -i ciphers /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72223 All network connections associated with a communication session must be terminated at the end of the session"
echo "or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated"
echo "mission requirements. (600)"
echo "(bashrc) -----"
grep -i tmout /etc/bashrc | grep -v '^#'
echo "----- (profile)"
grep -i tmout /etc/profile | grep -v '^#'
echo
echo "V-72225 The Standard Mandatory DoD Notice and Consent Banner must be displayed immediately prior to, or as part of,"
echo "remote access logon prompts."
echo "(sshd) -----"
grep -i banner /etc/ssh/sshd_config | grep -v '^#'
echo "----- (issue)"
grep -i government /etc/issue | head -c 50
echo
echo "V-72227 The OS must implement cryptography to protect the integrity of LDAP authentication communications. (if yes,)"
echo "V-72229 The OS must implement cryptography to protect the integrity of LDAP communications. (must use tls, no start_tls->ldaps)"
echo "V-72231 The OS must implement cryptography to protect the integrity of LDAP communications. (ldap certs)"
echo "(authconfig) -----"
grep -i useldapauth /etc/sysconfig/authconfig | grep -v '^#'
echo "----- (pam_ldap)"
egrep -i '(ssl|cacertdir|cacertfile)' /etc/pam_ldap.conf | grep -i tls | grep -v '^#'
echo "----- (ldap.conf)"
grep -i tls /etc/openldap/ldap.conf | grep -v '^#'
echo
echo "V-77825 The OS must implement virtual address space randomization. (2)"
grep -i kernel.randomize /etc/sysctl.conf
echo
echo "V-72233 All networked systems must have SSH installed. (server and client)"
yum list installed  | grep -i ssh
echo
echo "V-72235 All networked systems must use SSH for confidentiality and integrity of transmitted and received information"
echo "as well as information during preparation for transmission. (active)"
systemctl status sshd | grep -i active
echo
echo "V-72237 All network connections associated with SSH traffic must terminate at the end of the session or after"
echo "10 minutes of inactivity, except to fulfill documented and validated mission requirements. (600)"
grep -i clientaliveinterval /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72239 The SSH daemon must not allow authentication using RSA rhosts authentication. (yes)"
grep -i rhostsrsaauthentication /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72241 All network connections associated with SSH traffic must terminate after a period of inactivity. (0)"
grep -i clientalivecount /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72243 The SSH daemon must not allow authentication using rhosts authentication. (yes)"
grep -i ignorerhosts /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72245 The system must display the date and time of the last successful account logon upon an SSH logon. (yes)"
grep -i printlastlog /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72247 The system must not permit direct logons to the root account using remote access via SSH. (no)"
grep -i permitrootlogin /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72249 The SSH daemon must not allow authentication using known hosts authentication. (yes)"
grep -i ignoreuserknownhosts /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72251 The SSH daemon must be configured to only use the SSHv2 protocol. (2)"
grep -i protocol /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72253 The SSH daemon must be configd to only use MACs employing FIPS 140-2 approved crypto hash algorithms. (sha2-256/512)"
grep -i macs /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72255 The SSH public host key files must have mode 0644 or less permissive. (none)"
#find /etc/ssh -name '*.pub' -exec ls -lL {} \;
ls -l /etc/ssh | \
grep .pub | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(l>6||m>4||n>4)print $0;}'
echo
echo "V-72257 The SSH private host key files must have mode 0600 or less permissive. (none)"
#find /etc/ssh -name '*ssh_host*key' -exec ls -lL {} \;
ls -l /etc/ssh | \
grep key | grep -v .pub | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(l>6||m>0||n>0)print $0;}'
echo
echo "V-72259 The SSH daemon must not permit GSSAPI authentication unless needed. (no)"
grep -i gssapiauth /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72261 The SSH daemon must not permit Kerberos authentication unless needed. (no)"
grep -i kerberosauth /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72263 The SSH daemon must perform strict mode checking of home directory configuration files. (yes)"
grep -i strictmodes /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72265 The SSH daemon must use privilege separation. (yes or sandbox)"
grep -i usepriv /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72267 The SSH daemon must not allow compression or must only allow compression after successful authentication. (no or delayed)"
grep -i compression /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72269 The OS must synchronize clocks with a server that is synchronized to one of the redundant USNO time servers,"
echo "a time server designated for NIPRNet/SIPRNet, and/or GPS. (active,maxpoll 10)"
echo "(ntpd) -----"
service ntpd status | grep -i active
echo "----- (crontab)"
crontab -l | grep ntpdate
echo "----- (ntp.conf)"
grep maxpoll /etc/ntp.conf
echo
echo "V-72271 The OS must protect against or limit the effects of DoS attacks by validating the OS"
echo "is implementing rate-limiting measures on impacted network interfaces."
echo "(generic) -----"
firewall-cmd --direct --get-rule ipv4 filter IN_public_allow
echo "----- (OOB)"
firewall-cmd --direct --get-rule ipv4 filter IN_internal_allow
echo "----- (10)"
firewall-cmd --direct --get-rule ipv4 filter IN_work_allow
echo "----- (205)"
firewall-cmd --direct --get-rule ipv4 filter IN_dmz_allow
echo
echo "V-72273 The OS must enable an application firewall, if available."
echo "(installed) -----"
yum list installed firewalld | grep -i firewalld
echo "----- (active)"
service firewalld status | grep -i active
echo "----- (state)"
firewall-cmd --state
echo
echo "V-72275 The system must display the date and time of the last successful account logon upon login."
echo "(pam lastlog no silent) -----"
grep pam_lastlog /etc/pam.d/postlogin*
echo "----- (or printlastlog in sshd)"
grep -i printlastlog /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72277 There must be no .shosts files on the system. (none)"
find / -xdev -name '*.shosts'
echo
echo "V-72279 There must be no shosts.equiv files on the system. (none)"
find / -xdev -name shosts.equiv
echo
echo "V-72281 For systems using DNS resolution, at least two name servers must be configured."
grep nameserver /etc/resolv.conf | grep -v '^#'
echo
echo "V-72283 The system must not forward IPv4 source-routed packets. (0)"
sysctl -a | grep net.ipv4.conf.all.accept_source_route
echo
echo "V-72285 The system must not forward IPv4 source-routed packets by default. (0)"
sysctl -a | grep net.ipv4.conf.default.accept_source_route
echo
echo "V-72287 The system must not respond to IPv4 ICMP echoes sent to a broadcast address. (1)"
sysctl -a | grep net.ipv4.icmp_echo_ignore_broadcasts
echo
echo "V-72289 The system must prevent IPv4 ICMP redirect messages from being accepted. (0)"
sysctl -a | grep net.ipv4.conf.default.accept_redirects
echo
echo "V-72291 The system must not allow interfaces to perform IPv4 ICMP redirects by default. (0)"
sysctl -a | grep net.ipv4.conf.default.send_redirects
echo
echo "V-72293 The system must not send IPv4 ICMP redirects. (0)"
sysctl -a | grep net.ipv4.conf.all.send_redirects
echo
echo "V-72295 Network interfaces must not be in promiscuous mode. (none)"
ip link | grep -i promisc
echo
echo "V-72297 The system must be configured to prevent unrestricted mail relaying. (permit_mynetworks & reject)"
postconf -n smtpd_client_restrictions
echo
echo "V-72299 A FTP server package must not be installed unless needed."
echo "V-72301 The TFTP server package must not be installed if not required for operational support. (none,none)"
yum list installed | egrep -i '(lftp|tftp)'
echo
echo "V-72303 Remote X connections for interactive users must be encrypted. (yes)"
grep -i x11forwarding /etc/ssh/sshd_config | grep -v '^#'
echo
echo "V-72305 If the TFTP server is required, the TFTP daemon must be configd to operate in secure mode. (if installed, -s & dir)"
echo "(installed) -----"
yum list installed | grep -i tftp
echo "----- (config)"
grep server_args /etc/xinetd.d/tftp | grep -v '^#'
echo
echo "V-72307 An X Windows display manager must not be installed unless approved."
yum group list installed "X Window System"
echo
echo "V-72309 The system must not be performing packet forwarding unless the system is a router. (0)"
sysctl -a | grep 'net.ipv4.ip_forward '
echo
echo "V-72311 NFS must be configured to use RPCSEC_GSS. (if nfs in fstab sec set to krb5)"
grep nfs /etc/fstab
echo
echo "V-72313 SNMP community strings must be changed from the default. (none)"
egrep -i '(public|private)' /etc/snmp/snmpd.conf | grep -v '^#'
echo
echo "V-72315 The system access control program must be configured to grant or deny system access to specific hosts and services."
echo "(firewalld active) -----"
systemctl status firewalld | grep -i active
echo "----- (default zone)"
firewall-cmd --get-default-zone | xargs -i firewall-cmd --list-all --zone={$1}
echo
echo "V-72317 The system must not have unauthorized IP tunnels configured. (libreswan not installed)"
yum list installed | grep -i libreswan
echo
echo "V-72319 The system must not forward IPv6 source-routed packets (none or 0)"
sysctl -a | grep net.ipv6.conf.all.accept_source_route
echo
echo "V-72417 The OS must have the required packages for multifactor authentication installed. (esc, pam_pkcs11, & authconfig-gtk)"
yum list installed | egrep -i '(^esc|pam_pkcs11|authconfig-gtk)'
echo
echo "V-72427 The OS must implement multifactor authentication for access to privileged accounts via PAM. (services includes pam)"
grep services /etc/sssd/sssd.conf
echo
echo "V-72433 The OS must implement certificate status checking for PKI authentication. (ocsp_on)"
grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf
echo
echo "V-72435 The OS must implement smart card logons for multifactor authentication for access to privileged accounts."
echo "(Duplicate of V-71965 - N/A)"
authconfig --test | grep -i smartcard
echo
echo "V-73177 Wireless network adapters must be disabled. (wifi disconnected)"
nmcli device
echo
