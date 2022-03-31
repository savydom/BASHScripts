echo "V-whatever EXT. ACL (list of files with ACL +)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -ls | grep "+ "
echo
echo "V-4339 The Linux NFS Server must not have the insecure file locking option. (none, none)"
echo "(NFS running?) -----"
ps -ef | grep nfsd | grep -v 'grep'
echo "----- (if NFS running, check insecure locks)"
exportfs -v | grep -i 'insecure_locks'
echo
echo "V-4346 The Linux PAM system must not grant sole access to admin privs to the first user who logs into the console. (none, none)"
echo "(pam console module) -----"
ls /etc/pam.d | xargs -i egrep -iH 'pam_console.so' /etc/pam.d/{$1}
echo "----- (console perms)"
ls -l /etc/security/console.perms
echo
echo "V-12038 The /etc/securetty file must be group-owned by root, sys, or bin. (root/sys/bin)"
ls -lL /etc/securetty 
echo
echo "V-783 System security patches and updates must be installed and up-to-date."
echo "(current kernel) -----"
uname -a | awk '{print "kernel-"$3}'
echo "----- (avail kernels)"
rpm -qa -last | grep kernel | egrep -v '(debug|dev|head)'
echo
echo "V-27250 A file integrity baseline including crypt hashes must be created. (files exist/good config)"
echo "V-27251 A file integrity baseline including crypt hashes must be maintained. (recently updated)"
echo "(files exist, updated recently) -----"
grep -i dbdir /etc/aide.conf | grep -i define | awk '{print $3}' | xargs -i -t ls -l {$1} | grep -iv '^total'
echo "----- (good config)"
egrep -iB1 '(^# /|^/|^!/|^NORM|^LSSP|^PERM|^DIR|^LOG|^DATA)' /etc/aide.conf | egrep -v '(^--|^$|database)'
echo
echo "V-11945 A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition"
echo "of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries."
grep -i aide /etc/cron*/*
echo
echo "V-4301 The system clock must be synchronized to an authoritative DoD time source. (running or scheduled)"
echo "V-22291 The system must use at least two time sources for clock synchronization."
echo "V-22292 The system must use time sources local to the enclave. (local time servers use multiple sources)"
echo "(NTP running) -----"
ps -ef | egrep -i '(xntpd|ntpd)' | grep -v egrep
echo "----- (ntp scheduled)"
grep -i 'ntpd' /etc/cron.*/*
echo "----- (ntp servers)"
egrep -i '(^server|^restrict)' /etc/ntp.conf
echo
echo "V-22295 The time synchronization configuration file must be group-owned by root, bin, or sys. (root/bin/sys)"
ls -lL /etc/ntp.conf
echo
echo "V-760 Direct logins must not be permitted to shared, default, application, or utility accounts."
grep -v ':!!/$' /etc/shadow | awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"&&$2!="x"){print $1}' | xargs -i -t sh -c "last {$1} | head -n 10"
echo
echo "V-4269 The system must not have unnecessary accounts."
echo "V-29376 The system must not have the unnecessary "games" account. (no games,news,gopher,ftp, or lp)"
awk -F: '{print $1}' /etc/passwd
echo
echo "V-761 All accounts on the system must have unique user or account names. (none)"
pwck -r
echo
echo "V-762 All accounts must be assigned unique UIDs. (none)"
cut -d: -f3 /etc/passwd | uniq -d
echo
echo "V-11946 UIDs reserved for system accounts must not be assigned to non-system accounts. (<500 belong to system)"
awk -F: '($3<500){print $1":"$3}' /etc/passwd
echo
echo "V-780 GIDs reserved for system accounts must not be assigned to non-system groups. (<500 belong to system)"
awk -F: '($4<500){print $1":"$4}' /etc/passwd
echo
echo "V-24331 The DoD login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts."
echo "(Some of the banner verbiage)"
grep -i 'government' /usr/share/gdm/themes/RHEL/RHEL.xml | head -n 50
echo
echo "V-765 Successful and unsuccessful logins and logouts must be logged."
echo "(successful logins) -----"
last -R | head -n 10
echo "----- (unsuccessful logins)"
lastb -R | head -n 10
echo
echo "V-22299 The system must display the date and time of the last successful account login upon login. (not silent in pam or yes in sshd_config, if neither prolly wtmpx)"
echo "(pam.d/sshd pam_lastlog not silent) -----"
grep pam_lastlog /etc/pam.d/sshd
echo "----- (sshd_config printlastlog)"
grep -i printlastlog /etc/ssh/sshd_config
echo
echo "V-768 The delay between login prompts following a failed login attempt must be at least 4 seconds. (>=4, exists&=4000000)"
echo "(login.defs) -----"
grep -i fail_delay /etc/login.defs
echo "----- (pam faildelay)"
grep -i pam_faildelay /etc/pam.d/system-auth
echo
echo "V-22301 The system must display a publicly-viewable pattern during a graphical desktop environment session lock. (mode entry & stringvalue as blank-only)"
egrep -i '(mode|string)' /etc/gconf/gconf.xml.mandatory/apps/gnome-screensaver/%gconf.xml
echo
echo "V-27285 Global settings defined in system-auth must be applied in the pam.d definition files. (not pointing to system-auth-ac, config uses system-auth-ac)"
echo "(pointer) -----"
ls -l /etc/pam.d/system-auth
echo "----- (system-auth file)"
grep -i system-auth-ac /etc/pam.d/system-auth
echo
echo "V-11977 All non-interactive/automated processing account passwords must be changed at least once per year or be locked."
egrep '(sync|cfms|srccode)' /etc/shadow | awk -F: '{lk=substr($2,1,2);print $1":"lk":"$3":"$5;}'
echo
echo "V-918 Accounts must be locked upon 35 days of inactivity."
echo "[DaysSince][Date][PasswordUsed-LockedNotShown][Account]"
cut -d: -f1 /etc/passwd | xargs -i passwd -S {$1} | grep -vi locked | awk '{print $3,$8,$9,$10,$11,$12,$1}' | awk '{yr=0;mo=0;dy=0;lp=0;pd=$1;\
split("0_31_59_90_120_151_181_212_243_273_304_334",mary,"_");("date +%s"|getline td);yr=strtonum(substr(pd,1,4));\
mo=strtonum(substr(pd,6,2));dy=strtonum(substr(pd,9,2));for(cy=1970;cy<=yr;cy++){if(((cy%4==0)&&!(cy%100==0))||(cy%400==0))lp++;};\
yday=(yr-1970)*365;mday=mary[mo];dsec=(yday+mday+dy+lp-1)*86400;dif=(td-dsec)/86400;print dif,$0;}'
echo
echo "V-4298 Remote consoles must be disabled or protected from unauthorized access. (exists, 1)"
echo "(file exists) -----"
ls -lL /etc/securetty
echo "----- (1 tty or console)"
egrep -ic '(^tty|^console)' /etc/securetty
echo
echo "V-11979 The root account must not be used for direct log in. (none?)"
last root | grep -v reboot
echo
echo "V-11980 The system must log successful and unsuccessful access to the root account. (Can check if current with 'su -' & check for entries)"
echo "(authpriv) -----"
grep -i authpriv /etc/syslog.conf | grep -v '^#'
echo
echo "V-1046 Root passwords must never be passed over a network in clear text form."
echo "(if root logged in console)-----"
last | grep '^root' | egrep -v '(reboot|console)'
echo "----- (if root logged in, check if its with sshd) (sshd should be running)"
ps -ef | grep -i sshd | egrep -iv '(grep|lzimm|mjohn|tgrot|jivy|eshep)'
echo
echo "V-784 System files and dirs must not have uneven access permissions. (check for higher group/world perms than owner/group)"
find -L /etc /bin /usr/bin /usr/lbin /usr/usb /sbin /usr/sbin -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(n>m||m>l||n>l)print $0;}'
echo
echo "V-785 All files and dirs must have a valid owner."
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -nouser -ls
echo
echo "V-22312 All files and dirs must have a valid group-owner."
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -nogroup -ls
echo
echo "V-786 All network services daemon files must have mode 0755 or less permissive. (<=755 none if correct)"
ls -laL /usr/bin /usr/sbin /usr/lib /usr/bin/ssh | \
egrep '(finger|ftp|terminal|host|http|mail|net|news|scp|smb|ssh|telnet|vnc)' | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>5)print $0;}'
echo
echo "V-792 Manual page files must have mode 0644 or less permissive. (<=644 & dirs don't count)"
find -L /usr/share/man /usr/share/info /usr/share/infopage -type f -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(l>6||m>4||n>4)print $0;}'
echo
echo "V-790 NIS/NIS+/yp files must be group-owned by root, sys, or bin. (root/sys/bin)"
ls -la /var/yp/*
echo
echo "V-22320 The /etc/resolv.conf file must be group-owned by root, bin, or sys. (root/sys/bin)"
ls -lL /etc/resolv.conf
echo
echo "V-22324 The /etc/hosts file must be group-owned by root, bin, or sys. (root/sys/bin)"
ls -lL /etc/hosts
echo
echo "V-22331 For systems using DNS resolution, at least two name servers must be configd. (nameservers in resolv.conf)"
grep -i nameserver /etc/resolv.conf
echo
echo "V-902 All interactive user home dirs must be owned by their respective users."
echo "V-903 All interactive user home dirs must be group-owned by the home dir owners primary group."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i ls -ld /{$1}
echo
echo "V-914 All files and dirs contained in interactive user home dirs must be owned by the home dirs owner."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i -t sh -c "ls -alr /{$1} | grep -v '^total'" 2>&1 | gawk '{if($3!~/[root]/)print $0;}' |\
awk '{if($1=="sh")print $5;else if($1!="sh")print$0}'
echo
echo "V-22351 All files and dirs contained in user home dirs must be group-owned by a group of which the home dirs owner is a member."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i -t sh -c "ls -alr /{$1} | grep -v '^total'" 2>&1 | awk '{if($3!~$4)print $0;}' |\
awk '{if($1=="sh")print $5;else if($1!="sh")print$0}'
echo
echo "V-915 All files and dirs contained in user home dirs must have mode 0750 or less permissive. (<=750 none if correct)"
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | grep -i home | xargs -i find -L /{$1} ! -fstype nfs -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>0)print $0;}'
echo
echo "V-907 Run control scripts executable search paths must contain only absolute paths. (No ./, .., etc.)"
find -L /etc/rc* /etc/init.d -type f -print | xargs egrep 'PATH=' | grep -v LIBRARY | egrep '(\./|::|=:|\$)'
echo
echo "V-22354 Run control scripts library search paths must contain only absolute paths."
find -L /etc/rc* /etc/init.d -type f -print | xargs egrep LD_LIBRARY_PATH | egrep '(\./|::|=:|\$)'
echo
echo "V-910 Run control scripts must not execute world-writable programs or scripts. (Makes WWList)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -perm -002 ! -fstype nfs -ls | \
awk '{if(substr($3,1,1)!="l")print $11;}' | egrep -v '(^$|^/var/tmp|^/tmp|^/dev/null)' > /var/tmp/wwflist.txt
echo "----- (Show startup scripts that have WW files referenced) (/dev/null, /var/tmp are false culprits)"
ls -l /etc/init.d/* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " " | xargs -i -t fgrep -f /var/tmp/wwflist.txt {$1} | grep -v '^#'
echo
echo "V-4091 System start-up files must only execute programs owned by a privileged UID or an application. (owner:file)"
for FILE in `egrep -r "/" /etc/rc.* /etc/init.d | awk '/^.*[^\/][0-9A-Za-z_\/]*/{print $2}' | egrep "^/"| sort | uniq`; \
do if [ -e $FILE ]; then stat -L -c '%U:%n' $FILE; fi; done
echo
echo "V-22359 Global init files library search paths must contain only absolute paths."
echo "V-22360 Global init files lists of preloaded libs must contain only absolute paths. (No ./, .., etc.)"
egrep '(LD_LIBRARY_PATH|LD_PRELOAD)' /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout \
/etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/*
echo
echo "V-904 All local initialization files must be owned by the home dirs user or root."
echo "V-22361 Local initialization files must be group-owned by the users primary group or root."
echo "V-905 All local initialization files must have mode 0740 or less permissive. (<=740)"
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "ls -l ~USER/.[a-zA-Z]* 2>/dev/null" | \
egrep -v '(^total|^$)' | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3){a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);\
if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}\
else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}if(m>4||n>0)print"--> "$0;else print$0;}' | sed 's/^--> \//\//'
echo
echo "V-22363 Local initialization files library search paths must contain only absolute paths."
echo "V-22364 Local initialization files lists of preloaded libraries must contain only absolute paths. (files listed which have)"
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "ls -p ~USER/.[a-zA-Z]* 2>/dev/null" | \
awk '{a=substr($1,1,1);b=substr($1,1,length($1)-1);c=substr($1,length($1),1); if (a=="/"&&c==":")print "cd "b; \
else if(a!=""&&c!="/")print "egrep -H (^PATH|LD_LIBRARY_PATH|LD_PRELOAD) "$1;}' | sed -e "s/(/'(/" -e "s/)/)'/" > /var/tmp/chkpath.sh
sh /var/tmp/chkpath.sh 2>/dev/null | egrep '(\./|::|=:|\$)' | grep -v '.bash_history'
echo
echo "V-4087 User start-up files must not execute world-writable programs. (/devices/*, /dev/null are false culprits, /usr/mail/* are dirs)"
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "fgrep -f /var/tmp/wwflist.txt ~USER/.[a-zA-Z]* 2>/dev/null" | grep -v '.bash_history'
echo
echo "V-11987 The .rhosts, .shosts, hosts.equiv, shosts.equiv, /etc/passwd, /etc/shadow, and/or /etc/group files must not contain a plus (+) without defining entries for NIS+ netgroups."
echo "V-4427 All .rhosts, .shosts, or host.equiv files must only contain trusted host-user pairs. (none, none or host-user pairs)"
echo "(.rhosts, .shosts, hosts.equiv, shosts.equiv)-----"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | \
xargs -i find /{$1} \( -name .rhosts -o -name .shosts -o  -name hosts.equiv -o -name shosts.equiv \) -exec grep '+' {} \; -ls
echo "----- (/etc/passwd, shadow, group)"
grep '+' /etc/passwd /etc/shadow /etc/group
echo "----- (.rhosts, .shosts, or host.equiv)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | \
xargs -i find /{$1} \( -name .rhosts -o -name .shosts -o  -name hosts.equiv -o -name shosts.equiv \) -exec egrep '(^$|^#)' {} \; -ls
echo
echo "V-917 All shells referenced in /etc/passwd must be listed in the /etc/shells file, except any shells specified for the purpose of preventing logins. (0 entry is fail)"
cut -d: -f 1,7 /etc/passwd | sed -e 's/:/|/' | xargs -i sh -c "echo \"{$1}\"; egrep -cx '({$1})' /etc/shells"
echo
echo "V-925 Device files used for backup must only be readable and/or writable by root or the backup user. (root)"
cat /var/tmp/wwflist.txt | xargs -i find {$1} \( -type b -o -type c \) -ls | awk '{if($5!="root") print" "$5" "$6" "$0;}'
echo
echo "V-801 The owner, group-owner, mode, ACL, and location of files with the setuid bit set must be documented using site-defined procedures. (list of files to be documented)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -perm 4000 -ls
echo
echo "V-805 Removable media, remote file systems, and any file system not containing approved setuid files must be mounted with the nosuid option."
echo "V-22368 Removable media, remote file systems, and any file system not containing approved device files must be mounted with the nodev option. (nosuid & nodev for nfs,proc,swap)"
echo "(mtab nosuid & nodev) -----"
egrep -i '(nosuid|nodev)' /etc/mtab
echo "----- (fstab nosuid & nodev)"
egrep -i '(nosuid|nodev)' /etc/fstab
echo
echo "V-802 The owner, group-owner, mode, ACL and location of files with the setgid bit set must be documented using site-defined procedures. (list of files to be documented)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -perm 2000 -ls
echo
echo "V-1010 Public dirs must be the only world-writable dirs and world-writable files must be located only in public dirs."
echo "V-806 The sticky bit must be set on all public dirs."
echo "V-807 All public dirs must be owned by root or an application account."
echo "V-11990 All public dirs must be group-owned by root, sys, bin, or an application group."
echo "(no ww except tmp null etc. & ww files only in dirs with sticky bit, sticky bit set on ww dirs, root, root/sys/bin/application group)"
echo "(ww dirs and files)-----"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -perm -2 -a \( -type d -a -type f \) -ls
echo "----- (no sticky bit)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -type d -perm -002 -a ! -perm -1000 -ls
echo
echo "V-810 Default system accounts must be disabled or removed. (root & emerg ok?)"
awk -F: '($3<100){print $1}' /etc/passwd | xargs -i grep -w {$1} /etc/shadow | egrep -v '(\*|LK|NP|\!)' | cut -d: -f 1
echo
echo "V-4357 Audit logs must be rotated daily."
ls /etc/cron.*/* | grep -i logrotate
echo
echo "V-976 Cron must not execute group-writable or world-writable programs. (/dev/null, /var/tmp are false culprits)"
cat /var/tmp/wwflist.txt | xargs -i grep {$1} /var/spool/cron /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
echo
echo "V-977 Cron must not execute programs in, or subordinate to, world-writable dirs. (/dev/null, /var/tmp are false culprits)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -perm -002 -a -type d | \
xargs -i grep {$1} /var/spool/cron /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
echo
echo "V-11994 Crontabs must be owned by root or the crontab creator."
ls -lL /var/spool/cron /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
echo
echo "V-4360 Cron programs must not set the umask to a value less restrictive than 077. (>=077)"
ls /etc/cron.d | xargs -i -t cat /etc/cron.d/{$1} | egrep -v '(^#|^$)' | sed -e 's/^\*\/[0-9 *]*//' -e 's/^[0-9 *]*//' -e 's/^[a-zA-Z0-9 ]*//' -e 's/^[^\/].*[^\/a-zA-Z0-9]\///' \
-e 's/^.*\/![_a-zA-Z0-9].*//' -e 's/[^\/._a-zA-Z0-9].*//' | xargs -i -t grep umask {$1}
ls /etc/cron.hourly | xargs -i -t grep umask /etc/cron.hourly/{$1}
ls /etc/cron.daily | xargs -i -t grep umask /etc/cron.daily/{$1}
ls /etc/cron.weekly | xargs -i -t grep umask /etc/cron.weekly/{$1}
ls /etc/cron.monthly | xargs -i -t grep umask /etc/cron.monthly/{$1}
echo
echo "V-988 The at daemon must not execute group-writable or world-writable programs. (none)"
cat /var/tmp/wwflist.txt | xargs -i grep -s {$1} /var/spool/at/*
echo
echo "V-989 The at daemon must not execute programs in, or subordinate to, world-writable dirs. (none)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} -perm -002 -a -type d | xargs -i grep -s {$1} /var/spool/at/*
echo
echo "V-4365 The at dir must be owned by root, bin, sys, daemon, or cron."
ls -ld /var/spool/at
echo
echo "V-4366 At jobs must not set the umask to a value less restrictive than 077. (>=077)"
ls -L /var/spool/at | xargs -i cat /var/spool/at/{$1} | grep -v "^#" | sed -e 's/^\*\/[0-9 *]*//' -e 's/^[0-9 *]*//' -e 's/^[a-zA-Z0-9 ]*//' -e 's/^[^\/].*[^\/a-zA-Z0-9]\///' \
-e 's/^.*\/![_a-zA-Z0-9].*//' -e 's/[^\/._a-zA-Z0-9].*//' | xargs -i -t grep umask /{$1}
echo
echo "V-22409 The system must not process Internet Control Message Protocol (ICMP) timestamp requests. (reply/request both drop)"
grep -i timestamp /etc/sysconfig/iptables | grep -i drop
echo
echo "V-4304 The root file system must employ journaling or another mechanism ensuring file system consistency. (none)"
mount | egrep -iv '(JFS|VXFS|HFS|XFS|reiserfs|EXT3|EXT4|ZFS)' | grep ' \/ '
echo
echo "V-24386 The telnet daemon must not be running. (none)"
echo "(ps) -----"
ps -ef | grep -i telnet | grep -v grep
echo "----- (chkconfig)"
chkconfig --list | grep -i telnet
echo
echo "V-4701 The system must not have the finger service active. (yes)"
echo "(finger installed? -----"
rpm -q finger
echo "----- (finger disabled?)"
grep -i disable /etc/xinetd.d/finger
echo
echo "V-12049 Network analysis tools must not be installed. (none)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/home/ d' -e '/fmis/ d' | xargs -i find /{$1} \( -name ethereal -o -name wireshark -o -name tshark -o -name nc \
-o -name tcpdump -o -name snoop \) -ls
echo
echo "V-827 The hosts.lpd file (or equivalent) must not contain a + character. (not *:port nor allow from all)"
egrep -i '(listen|allow from)' /etc/cups/cupsd.conf | grep -v '^#'
echo
echo "V-4382 Administrative accounts must not run a web browser, except as needed for local service administration. (none)"
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | grep root | xargs -i ls -la /{$1} | egrep '(.netscape|.mozilla)'
echo
echo "V-833 Files executed through a mail aliases file must be owned by root and must reside within a dir owned and writable only by root."
echo "V-22440 Files executed through a mail aliases file must be group-owned by root/bin/sys/system, and must reside within a dir group-owned by root/bin/sys/system."
echo "(root, root/bin/sys/system)"
echo "(/etc/mail/sendmail.cf) -----"
grep '\/' /etc/mail/sendmail.cf | grep -v '#' | sed -e 's/^[a-zA-Z0-9 _:=;.]*//' -e 's/^.*\/![a-zA-Z0-9_.].*//' -e 's/[^\/a-zA-Z0-9_.].*//' | xargs -i ls -lL {$1}
echo "----- (/etc/aliases)"
grep '\/' /etc/aliases | grep -v '#' | sed -e 's/^[a-zA-Z0-9 _:=;.]*//' -e 's/^.*\/![a-zA-Z0-9_.].*//' -e 's/[^\/a-zA-Z0-9_.].*//' | xargs -i ls -lL {$1}
echo
echo "V-836 The system syslog service must log informational and more severe SMTP service messages. (mail.* or mail.crit)"
egrep '(mail\.\*|mail\.crit)' /etc/syslog.conf
echo
echo "V-4690 The sendmail server must have the debug feature disabled. (version >=8.13.8)"
rpm -q sendmail
echo
echo "V-4691 The SMTP service must not have a uudecode alias active. (none)"
echo "(/etc/mail/sendmail.cf) -----"
grep -i decode /etc/mail/sendmail.cf | grep -v '^#'
echo "----- (/etc/aliases)"
grep -i decode /etc/aliases | grep -v '^#'
echo
echo "V-4694 The sendmail service must not have the wizard backdoor active. (goaway/noexpn, novrfy, no 'wiz')"
egrep -i '(goaway|expn|vrfy|wiz)' /etc/mail/sendmail.cf | grep -v '^#'
echo
echo "V-12010 Unencrypted FTP must not be used on the system."
echo "V-846 Anonymous FTP must not be active on the system unless authorized."
echo "V-4702 If the system is an anonymous FTP server, it must be isolated to the DMZ network. (off or not exist)"
chkconfig --list gssftp
chkconfig --list vsftpd
echo
echo "V-841 The ftpusers file must contain account names not allowed to use FTP. (0 entry is fail)"
cut -d: -f 1 /etc/passwd | xargs -i -t grep -iwcs {$1} /etc/ftpusers /etc/vsftpd.ftpusers /etc/vfsftpd/ftpusers 2>&1 | awk '{print $1,$2,$3;}'
echo
echo "V-845 The FTP daemon must be configd for logging or verbose mode. (yes if found, yes if found, none)"
echo "(vsftpd config file used for xinetd) -----"
grep -Hi vsftpd /etc/xinetd.d/* | grep -v '#' | awk -F: '{print $1}' | xargs -i grep -i 'server_args*' {$1} |awk -F= '{print $2}' | xargs -i -t grep -i 'xferlog_enable*' {$1}
echo "----- (vsftpd default config)"
grep -i xferlog_enable /etc/vsftpd/vsftpd.conf
echo "----- (gssftp)"
grep -i server_args /etc/xinetd.d/gssftp | grep -v '\-l'
echo
echo "V-849 The TFTP daemon must be configd to vendor specs, including a dedicated TFTP user account, a non-login shell such as /bin/false, and a home dir owned by the TFTP user."
echo "V-4695 Any active TFTP daemon must be authorized and approved in the system accreditation pkg."
echo "(not exist or yes||no w/tftp user, none)"
echo "(tftp in xinetd) -----"
egrep -i '(disable|user)' /etc/xinetd.d/tftp
echo "----- (tftp active)"
chkconfig --list | grep -i tftp
echo
echo "V-850 Any X Windows host must write .Xauthority files."
echo "V-12014 All .Xauthority files must have mode 0600 or less permissive. (n/a if none/.Xauth exists, <=600)"
echo "(X being used) -----"
egrep "^x:5.*X11" /etc/inittab
echo "----- (xauth in users dirs)"
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -i sh -c "find ~{$1}/ \( -name .Xauthority -o -name .xauth* \) -ls"
echo
echo "V-4697 X displays must not be exported to the world. (access control enabled)"
xhost
echo
echo "V-12016 .Xauthority or X*.hosts (or equivalent) file(s) must be used to restrict access to the X server. (is X running? for files see 12017)"
ps -ef | egrep X | egrep -iv '(java|grep)'
echo 
echo "V-12017 The .Xauthority utility must only permit access to authorized hosts. (authorized hosts)"
awk -F: '($2!="!!"&&$2!="!*"&&$2!="*"){print $1}' /etc/shadow | xargs -i sh -c "find ~{$1}/ \( -name .Xauthority -o -name .xauth* \) -ls" | awk '{print $11}' | \
xargs -i -t xauth -f {$1} list | awk '{print $1}'
echo
echo "V-12018 X Window System connections not required must be disabled. (is Xorg running?)"
ps -ef | egrep Xorg | egrep -iv '(java|grep)'
echo
echo "V-993 SNMP communities, users, and passphrases must be changed from the default."
egrep -i '(default|public|private|snmp-trap|password)' /var/net-snmp/snmpd.conf /etc/snmp/snmpd.conf | grep -v '#'
echo
echo "V-22448 The SNMP service must require the use of a FIPS 140-2 approved crypt hash algorithm as part of its authentication and integrity methods."
echo "V-22449 The SNMP service must require the use of a FIPS 140-2 approved encryption algorithm for protecting the privacy of SNMP messages. (none, none)"
grep -v '^#' /var/net-snmp/snmpd.conf /etc/snmp/snmpd.conf | grep -i createuser | egrep -vi '(SHA|AES)'
echo
echo "V-4395 The system must only use remote syslog servers (log hosts) that is justified and documented using site-defined procedures. (@loc.al.ser.ver)"
grep '@' /etc/syslog.conf | grep -v '^#'
echo
echo "V-12021 The syslog daemon must not accept remote messages unless it is a syslog server documented using site-defined procedures. (none)"
ps -ef | grep -i syslogd | grep '\-r'
echo
echo "V-22457 The SSH daemon must only listen on management network addresses unless authorized for uses other than management."
egrep -i listen /etc/ssh/sshd_config
echo
echo "V-22459 The SSH daemon must be configd to not use Cipher-Block Chaining (CBC) ciphers. (ctr not cbc)"
egrep -i ciphers /etc/ssh/sshd_config
echo
echo "V-12022 The SSH daemon must be configd for IP filtering."
grep sshd /etc/hosts.deny /etc/hosts.allow
echo
echo "V-4397 The system must be configd with a default gateway for IPv4 if the system uses IPv4. (ip4 default set)"
ip -4 route list | grep default
echo
echo "V-22490 The system must be configd with a default gateway for IPv6 if the system uses IPv6. (ip4 default returned)"
ip -6 route list | grep default
echo
echo "V-1026 The Samba Web Administration Tool (SWAT) must be restricted to the local host or require SSL. (n/a if not installed)"
echo "(swat installed?) ----"
rpm -qa | grep swat
echo "----- (if so, then restricted?)"
grep -H "bin/swat" /etc/xinetd.d/* | cut -d: -f1 | xargs grep 'only_from'
echo
echo "V-1030 The smb.conf file must use the hosts option to restrict access to Samba. (hosts list)"
grep -i host /etc/samba/smb.conf | grep -v '^#'
echo
echo "V-4273 The /etc/news/incoming.conf (or equivalent) must have mode 0600 or less permissive. (<=600 - n/a if not installed)"
ls -lL /etc/news/incoming.conf
echo
echo "V-4274 The /etc/news/infeed.conf (or equivalent) must have mode 0600 or less permissive. (<=600 - n/a if not installed)"
ls -lL /etc/news/infeed.conf
echo
echo "V-4277 Files in /etc/news must be owned by root or news. (root/news - n/a if not installed)"
ls -al /etc/news
echo
echo "V-4399 The system must not use UDP for NIS/NIS+. (n/a if no NIS)"
rpcinfo -p | grep -i yp | grep -i udp
echo
echo "V-12026 NIS maps must be protected through hard-to-guess domain names. (n/a if no NIS)"
domainname
echo
echo "V-22506 The system pkg management tool must be used to verify system software periodically. (rpm)"
grep -i 'rpm -q' /etc/cron.*/*
echo
echo "V-12765 The system must use and update a DoD-approved virus scan program. (mcafee/dat <7 days old)"
echo "(nails status) -----"
/etc/init.d/nails status
echo "(dat files) -----"
ls -lL /opt/NAI/LinuxShield/engine/dat
echo
echo "V-38692 Accounts must be locked upon 35 days of inactivity. (35)"
grep -i inactive /etc/default/useradd
echo
echo "V-22545 The system must not have 6to4 enabled. (none)"
ip tun list | grep 'remote any' | grep "ipv6/ip"
echo
echo "V-22547 The system must not have IP tunnels configd. (none)"
ip tun list
ip -6 tun list
echo
echo "V-22548 The DHCP client must be disabled if not needed. (none)"
grep -i 'bootproto=dhcp' /etc/sysconfig/network-scripts/ifcfg-*
echo
echo "V-22553 The system must not forward IPv6 source-routed packets. (0 and not commented out)"
egrep "net.ipv6.conf.*forwarding" /etc/sysctl.conf
echo
echo "V-23972 The system must not respond to ICMPv6 echo requests sent to a broadcast address. (INPUT icmpv6 DROP)"
grep -i input /etc/sysconfig/ip6tables | grep -i icmpv6 | grep -i drop
echo
echo "V-22555 If the system is using LDAP for authentication or account info, the system must use a TLS connection using FIPS 140-2 approved crypt algorithms."
echo "V-22556 If the system is using LDAP for authentication or account info, certs used to authenticate to the LDAP server must be provided from DoD PKI"
echo "or a DoD-approved external PKI."
echo "(n/a if 0/none ldap entries / TLS start & ciphers, TLS cert - if exists manual openssl check)"
echo "(nssldap)-----"
grep -iv '^#' /etc/nsswitch.conf | grep -ic ldap
echo "----- (TLS)"
egrep -i '(ssl start_tls|tls_ciphers|tls_cert)' /etc/ldap.conf
echo
echo "V-22578 The system must have USB disabled unless needed. (none)"
grep -i kernel /boot/grub/grub.conf | egrep -iv '(nousb|#)'
echo
echo "V-22583 The system's local firewall must implement a deny-all, allow-by-exception policy."
echo "(rules in place)-----"
iptables --list | grep -v '^$'
echo
echo "V-22588 The system pkg management tool must cryptally verify the authenticity of software pkgs during installation. (none / none/not 0)"
echo "(rpm) -----"
grep -is nosignature /etc/rpmrc /usr/lib/rpm/rpmrc /usr/lib/rpm/redhat/rpmrc ~root/.rpmrc
echo "----- (yum)"
grep -i gpgcheck /etc/yum.conf /etc/yum.repos.d/* | grep -v '=1'
echo
echo "V-22589 The system pkg management tool must not auto obtain updates. (none)"
service yum-updatesd status | grep -v stop
echo
