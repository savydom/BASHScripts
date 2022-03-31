echo "v-whatever EXT. ACL (list of files with ACL +)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find /{$1} -ls | grep "+ "
echo
echo "v-4353 The /etc/security/audit_user file must not define a different auditing level for specific users. (only root)"
grep -v '^#' /etc/security/audit_user
echo
echo "v-4313 The ASET master files must be located in the /usr/aset/masters dir. Is ASET used in crontab?"
echo "(crontab) -----"
crontab -l | grep -i aset
echo "----- (If so, are ASET files in /usr/aset/masters)"
ls -l /usr/aset/masters
echo
echo "v-4312 The /usr/aset/masters/uid_aliases must be empty. (none)"
grep -v '^#' /usr/aset/masters/uid_aliases
echo
echo "v-4309 If the system is a firewall, ASET must be used on the system, and the firewall parameters must be set in /usr/aset/asetenv. (TASKS=..., n/a?)"
grep TASKS /usr/aset/asetenv | grep -i firewall
echo
echo "v-953 (ASET) configurable parameters in the asetenv file must be correct. (no changes to the first part of the file)"
echo "(asetenv) -----"
head -n 25 /usr/aset/asetenv
echo "----- (And no commented out entries after)"
grep "^#" /usr/aset/asetenv
echo
echo "v-954 YPCHECK variable must be set to true when NIS+ is configured. (true if NIS enabled)"
grep -i ypcheck /usr/aset/asetenv
echo
echo "v-12032 Hidden extended file attributes must not exist on the system. (none)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find -L /{$1} -xattr -print -exec runat {} ls -la \;
echo
echo "v-22606 The /etc/zones directory, and its contents, must not have an extended ACL. (n/a if not a zone, no +)"
ls -ldR /etc/zones | grep '+ '
echo
echo "v-756 The system must require authentication upon booting into single-user and maintenance modes. (yes or file doesn't exist)"
grep -i passreq /etc/default/sulogin
echo
echo "v-11940 The operating system must be a supported release. (Solaris)"
uname -a
echo
echo "v-4301 The system clock must be synchronized to an authoritative DoD time source. (cron job exists)"
echo "v-22291 The system must use at least two time sources for clock synchronization. (each time server references two external timeservers)"
echo "v-22292 The system must use time sources local to the enclave. (local timeserver)"
crontab -l | grep -i ntp
echo
echo "v-760 Direct logins must not be permitted to shared, default, application, or utility accounts."
awk -F: '($2!~/NP/&&$2!~/LK/){print $1}' /etc/shadow | xargs -i -t sh -c "last {$1} | head -n 10"
echo
echo "v-4269 The system must not have unnecessary accounts. (no games,news,gopher,ftp, or lp)"
awk -F: '{print $1}' /etc/passwd
echo
echo "v-761 All accounts on the system must have unique user or account names. (none)"
logins -u | sort | uniq -c | awk '$1>1 {print $2}'
echo
echo "v-762 All accounts must be assigned unique UIDs. (none)"
logins -d
echo
echo "v-11946 UIDs reserved for system accounts must not be assigned to non-system accounts. (<100 belong to system)"
awk -F: '$3<100 {print $1":"$3}' /etc/passwd
echo
echo "v-780 GIDs reserved for system accounts must not be assigned to non-system groups. (<100 belong to system)"
awk -F: '$4<100 {print $1":"$4}' /etc/passwd
echo
echo "v-765 Successful and unsuccessful logins and logouts must be logged."
echo "(successful logins) -----"
last | head -n 10
echo "----- (unsuccessful logins)"
cat /var/adm/loginlog
echo "----- (auth logging info/debug configured)"
egrep "auth\.(info|debug)" /etc/syslog.conf
echo
echo "v-22299 The system must display the date and time of the last successful account login upon login."
grep -i printlastlog /etc/ssh/sshd_config
echo
echo "v-1032 Users must not be able to change passwords more than once every 24 hours. (displays if <1)"
echo "(shadow) -----"
awk -F: '($4<1&&$2!~/NP/&&$2!~/LK/) {print $1}' /etc/shadow
echo "----- (Check to see if minweeks is set - just informational)"
grep -i minweeks /etc/default/passwd
echo
echo "v-770 The system must not have accounts configured with blank or null passwords. (NP system accounts)"
logins -p
echo
echo "v-11947 The system must require passwords contain a minimum of 14 characters. (>=14)"
grep -i passlength /etc/default/passwd
echo
echo "v-22302 The system must enforce compliance of the entire password during authentication. _, *, or $ (none, NP for nonlogin account)"
nawk -F: '{if($2!~/[*]/ && $2!~/[$]/ && $2!~/[_]/) print $1":"$2}' /etc/shadow
#cut -d':' -f2 /etc/shadow | egrep -v '^[*!$_]'
echo
echo "v-22303 The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes."
echo "(ALLOW 5,6 - Cannot use ALLOW if DEPRICATE is set.)"
grep "^CRYPT_" /etc/security/policy.conf
echo
echo "v-11948 The system must require passwords to contain at least one uppercase alphabetic character. (>=1)"
grep -i minupper /etc/default/passwd
echo
echo "v-11972 The system must require passwords to contain at least one numeric character. (>=1)"
grep -i mindigit /etc/default/passwd
echo
echo "v-11973 The system must require passwords to contain at least one special character. (>=1)"
grep -i minspecial /etc/default/passwd
echo
echo "v-11975 The system must require passwords to contain no more than three consecutive repeating characters. (>=3)"
grep -i maxrepeats /etc/default/passwd
echo
echo "v-11976 User passwords must be changed at least every 60 days. (60)"
echo "[Account][St][LastChanged][MinPW][MaxPW][Warn][DaysSincePWChange]"
cut -d: -f1 /etc/passwd | xargs -i passwd -s {$1} | egrep -vi '(LK|NL)' | nawk '{yr=0;mo=0;dy=0;pd=$3;\
split("0_31_59_90_120_151_181_212_243_273_304_334",mary,"_");("date +%m/%d/%y"|getline td);\
yr=substr(pd,7,2);yr=yr+2000;mo=substr(pd,1,2)+0;dy=substr(pd,4,2)+0;lp=0;for(cy=1970;cy<=yr;cy++){if(((cy%4==0)&&!(cy%100==0))||(cy%400==0))lp++;};\
yday=(yr-1970)*365;mday=mary[mo];pday=yday+mday+dy+lp-1;\
yr=substr(td,7,2);yr=yr+2000;mo=substr(td,1,2)+0;dy=substr(td,4,2)+0;lp=0;for(cy=1970;cy<=yr;cy++){if(((cy%4==0)&&!(cy%100==0))||(cy%400==0))lp++;};\
yday=(yr-1970)*365;mday=mary[mo];tday=yday+mday+dy+lp-1;\
dif=(tday-pday);print $0,"     ",dif;}'
echo
echo "v-918 Accounts must be locked upon 35 days of inactivity."
echo "(last 5 logins) -----"
cat /etc/passwd | cut -d":" -f1 | xargs -i -t last -n 5 {$1}
echo
echo "v-22307 The system must prevent the use of dictionary words for passwords."
grep "^DICTION" /etc/default/passwd
echo
echo "v-22308 The system must restrict the ability to switch to the root user to members of a defined group. (type=role)"
egrep '^root:' /etc/user_attr | grep -i role
echo
echo "v-777 The root account must not have world-writable (ww) dirs in its executable search path. (lists dir in PATH, check for ww)"
echo $PATH | sed -e 's/ /\\ /g' -e 's/:/\
/g' | xargs ls -ld
echo
echo "v-4298 Remote consoles must be disabled or protected from unauthorized access. (none)"
consadm -p
echo
echo "v-11979 The root account must not be used for direct logins. (none?)"
last root | grep -v reboot
echo
echo "v-11980 The system must log successful and unsuccessful access to the root account. (Can check if current with su -)"
tail /var/adm/sulog
echo
echo "v-1062 The root shell must be located in the / file system."
echo "(usr in vfstab)-----"
grep /usr /etc/vfstab
echo "---- (if /usr partitioned, check location of root shell - shell shouldnt be in partitioned /usr)"
awk -F: '$1 == "root" {print $7}' /etc/passwd
echo
echo "v-1046 Root passwords must never be passed over a network in clear text form."
echo "(if root logged in console)-----"
last | grep "^root" | egrep -v "reboot|console"
echo "----- (if root logged in, check if its with sshd) (sshd should be running)"
ps -ef | grep -i sshd
echo
echo "v-784 System files and dirs must not have uneven access permissions. (check for higher group/world perms than owner/group)"
find -L /etc /bin /usr/bin /usr/ucb /sbin /usr/sbin -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(n>m||m>l||n>l)print $0;}'
echo
echo "v-785 All files and dirs must have a valid owner."
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find -L /{$1} -nouser -ls
echo
echo "v-22312 All files and dirs must have a valid group-owner."
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find -L /{$1} -nogroup -ls
echo
echo "v-786 All network services daemon files must have mode 0755 or less permissive. (<=755)"
ls -laL /usr/bin /usr/sbin /usr/lib /usr/lib/ssh | \
egrep '(finger|ftp|terminal|host|http|mail|net|news|scp|smb|ssh|telnet|vnc)' | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>5)print $0;}'
echo
echo "v-794 All system command files must have mode 0755 or less permissive. (<=755)"
find -L /etc /bin /usr/bin /usr/ucb /sbin /usr/sbin -type f -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>5)print $0;}'
echo
echo "v-795 All system files, programs, and dirs must be owned by a system account."
find -L /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin ! \( -group root -o -group bin \
-o -group sys -o -group other -o -group mail -o -group uucp -o -group lp -o -group daemon \) -ls
echo
echo "v-792 Manual page files must have mode 0644 or less permissive. (<=644 dirs don't count)"
find -L /usr/share/man /usr/sfw/man /usr/sfw/share/man -type f -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(l>6||m>4||n>4)print $0;}'
echo
echo "v-901 All users home dirs must have mode 0750 or less permissive. (<=750)"
echo "v-902 All interactive users home dirs must be owned by their respective users."
echo "v-903 All interactive users home dirs must be group-owned by the home dir owners primary group."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i ls -ld /{$1} | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>0)print"--> "$0;else print$0;}'
echo
echo "v-914 All files and dirs contained in interactive users home dirs must be owned by the home dirs owner."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i -t ls -alr /{$1} | \
grep -v '^total' | nawk '{q=$0;r=$3;if(r!~/[root]/)print q;}'
echo
echo "v-22351 All files and dirs contained in user home dirs must be group-owned by a group of which the home dirs owner is a member."
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | xargs -i -t ls -alr /{$1} | \
grep -v '^total' | nawk '{q=$0;r=$3;s=$4;("groups "$3 | getline t);close("groups "$3);if(t!~s)print q;}'
echo
echo "v-915 All files and dirs contained in users home dirs must have mode 0750 or less permissive. (<=750)"
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | grep -i home | xargs -i find -L /{$1} ! -fstype nfs -ls | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>0)print $0;}'
echo
echo "v-906 All run control scripts must have mode 0755 or less permissive. (<=755 dirs and links dont count)"
find -L /etc/rc* /etc/init.d /lib/svc/method -ls | awk '{if(substr($3,1,1)~/[-]/)print$0;}' | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>5)print $0;}'
echo
echo "v-22354 Run control scripts library search paths must contain only absolute paths."
echo "v-22355 Run control scripts lists of preloaded libs must contain only absolute paths. (No ./, .., etc.)"
find -L /etc/rc* /etc/init.d -type f -print | xargs egrep '(LD_LIBRARY_PATH|LD_PRELOAD)'
echo
echo "v-910 Run control scripts must not execute world-writable (ww) programs or scripts. (Makes WWList)"
ls -L / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' | xargs -i find /{$1} -perm -002 ! -fstype nfs -ls | \
awk '{if(substr($3,1,1)!="l")print $11;}' | egrep -v '(^/var/tmp|^/tmp|^/dev/null)'> /var/tmp/wwflist.txt
echo "----- (Show startup scripts that have WW files referenced) (/dev/null, /var/tmp are false culprits)"
ls -l /etc/init.d/* | tr '\011' ' ' | tr -s ' ' | cut -f 9,9 -d " " | \
xargs -i -t fgrep -f /var/tmp/wwflist.txt {$1}
echo
echo "v-4091 System start-up files must only execute programs owned by privileged UID or application. (List non-root owned exe)"
ls /etc/init.d/* | grep -vi readme | xargs -i cat {$1} | grep '^.\/[a-zA-Z0-9]' | \
grep -v  '^#' | awk '{print $1}' | xargs -i ls -l {$1} | awk '($3!="root"){print$0}'
echo
echo "v-11981 All global initialization files must have mode 0644 or less permissive."
echo "v-11982 All global init files must be owned by root."
echo "v-11983 All global init files must be group-owned by root, sys, or bin. (<=644, root, root/sys/bin)"
ls -l /etc/.login /etc/profile /etc/bashrc /etc/environment /etc/security/environ /etc/csh.login /etc/csh.cshrc | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(l>6||m>4||n>4)print"--> "$0;else print$0;}'
echo
echo "v-22359 Global init files library search paths must contain only absolute paths."
echo "v-22360 Global init files lists of preloaded libs must contain only absolute paths. (No ./, .., etc.)"
egrep '(LD_LIBRARY_PATH|LD_PRELOAD)' /etc/.login /etc/profile /etc/bashrc \
/etc/environment /etc/security/environ /etc/csh.login /etc/csh.cshrc
echo
echo "v-904 All local init files must be owned by the user or root."
echo "v-22361 Local init files must be group-owned by the users primary group or root."
echo "v-905 All local init files must have mode 0740 or less permissive. (<=740)"
#awk -F: '($2!="NP"&&$2!="*LK*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "ls -l ~USER/.[a-zA-Z]*" | \
awk -F: '($2!~/NP/&&$2!~/LK/){print $1}' /etc/shadow | xargs -i grep "^{$1}:" /etc/passwd | awk -F: '{print $6}' | grep '^/' | \
xargs -i sh -c "ls -l {$1}/.[a-zA-Z]*" |\
egrep -v '(^total|^$)' | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3){a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);\
if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}\
else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}if(m>4||n>0)print"--> "$0;else print$0;}' | sed 's/^--> \//\//'
echo
echo "v-11986 All local init files executable search paths must contain only absolute paths."
echo "v-22363 Local init files library search paths must contain only absolute paths."
echo "v-22364 Local init files lists of preloaded libs must contain only absolute paths. (files listed which have)"
#awk -F: '($2!="NP"&&$2!="*LK*"){print $1}' /etc/shadow | xargs -n1 -iUSER sh -c "ls -p ~USER/.[a-zA-Z]*" | \
awk -F: '($2!~/NP/&&$2!~/LK/){print $1}' /etc/shadow | xargs -i grep "^{$1}:" /etc/passwd | awk -F: '{print $6}' | grep '^/' | \
xargs -i sh -c "ls -p {$1}/.[a-zA-Z]*" |\
awk '{a=substr($1,1,1);b=substr($1,1,length($1)-1);c=substr($1,length($1),1); if (a=="/"&&c==":")print "cd "b; \
else if(a!=""&&c!="/")print "egrep -il (^PATH|LD_LIBRARY_PATH|LD_PRELOAD) "$1;}' | sed -e "s/(/'(/" -e "s/)/)'/" > /var/tmp/chkpath.sh
sh /var/tmp/chkpath.sh
echo
echo "v-4087 User start-up files must not execute ww programs. (/devices/*, /dev/null are false culprits, /usr/mail/* are dirs)"
awk -F: '($2!~/NP/&&$2!~/LK/){print $1}' /etc/shadow | xargs -i grep "^{$1}:" /etc/passwd | awk -F: '{print $6}' | grep '^/' | \
xargs -i sh -c "fgrep -f /var/tmp/wwflist.txt {$1}/.[a-zA-Z]*"
echo
echo "v-11987 The following files must not contain a plus (+) without defining entries for NIS+ netgroups."
echo "v-913 There must be no .netrc files on the system. (none)"
echo "v-4427 All .rhosts, .shosts, or host.equiv files must only contain trusted host-user pairs. (if they exist, manually check)"
echo "v-4428 All .rhosts, .shosts, .netrc, or hosts.equiv files must be accessible by only root or the owner."
echo "(.rhosts)-----"
find /bin /etc /sbin /usr -name .rhosts -exec grep '+' {} \; -ls
echo "----- (.shosts)"
find /bin /etc /sbin /usr -name .shosts -exec grep '+' {} \; -ls
echo "----- (hosts.equiv)"
find /bin /etc /sbin /usr -name hosts.equiv -exec grep '+' {} \; -ls
echo "----- (shosts.equiv)"
find /bin /etc /sbin /usr -name shosts.equiv -exec grep '+' {} \; -ls
echo "----- (/etc/passwd, shadow, group)"
grep '+' /etc/passwd /etc/shadow /etc/group
echo "----- (.netrc)"
find /bin /etc /sbin /usr -name .netrc
echo "----- (.rhosts, .shosts, or host.equiv)"
find /bin /etc /sbin /usr -name .rhosts -o -name .shosts -o -name host.equiv
echo
echo "v-917 All shells in /etc/passwd must be listed in the /etc/shells file, except shells specified for preventing logins. (0 entry is fail)"
cut -d: -f 7 /etc/passwd | xargs -i -t grep -c -w {$1} /etc/shells
echo
echo "v-921 All shell files must be owned by root or bin."
echo "v-22365 All shell files must be group-owned by root, bin, or sys."
echo "v-922 All shell files must have mode 0755 or less permissive. (root/bin,root/bin/sys,<=755)"
cat /etc/shells | xargs -i ls -lL {$1} | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>5)print"--> "$0;else print$0;}'
echo
echo "v-924 Device files and dirs must only be writable by users with a system account or as configured by the vendor."
echo "v-925 Device files used for backup must only be readable and/or writable by root or the backup user. (none, root)"
#cat /var/tmp/wwflist.txt | xargs -i find {$1} \( -type b -o -type c \) -ls | awk '{if($5!="root"||($6!="root"&&$6!="sys"&&$6!="bin")) print" "$5" "$6" "$0;}'
find / -type b -o -type c -ls | grep -i dev | \
awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3){a=substr($3,p+1,1);b=substr($3,p+2,1);c=substr($3,p+3,1);\
if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}\
else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(n>5)print$0;}'
echo
echo "v-1048 Audio devices must have mode 0660 or less permissive. (<=660)"
ls -l /dev/audio
echo
echo "v-805 Removable media, remote FS, and any FS that does not contain setuid files must be mounted with the nosuid option. (none and zfs list)"
echo "(vfstab nosuid)-----"
cat /etc/vfstab | grep -i nosuid
echo "----- (zfs get setuid)"
zfs get setuid
echo
echo "v-1010 Public dirs must be the only ww dirs and ww files must be located only in public dirs."
echo "v-806 The sticky bit must be set on all public dirs."
echo "v-807 All public dirs must be owned by root or an application account."
echo "v-11990 All public dirs must be group-owned by root or an application group."
echo "(ww dirs)-----"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find /{$1} -perm -002 -a -type d -ls
echo "----- (no sticky bit)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find /{$1} -perm -002 -a -type d ! -perm -1000 -ls
echo
echo "v-808 The system and user default umask must be 077. (>=077, some other umasks are in backup files)"
echo "(system)-----"
find /etc -type f | xargs grep -i '^umask'
echo "----- (users)"
awk -F: '($2!~/NP/&&$2!~/LK/){print $1}' /etc/shadow | xargs -i grep "^{$1}:" /etc/passwd | awk -F: '{print $6}' | grep '^/' | \
xargs -i sh -c "grep -i umask {$1}/.*"
echo
echo "v-810 Default system accounts must be disabled or removed. (root & emerg ok?)"
awk -F: '$3<100 {print $1}' /etc/passwd | xargs -i grep -w {$1} /etc/shadow | egrep -v '(\*|LK|NP|\!)' | cut -d: -f 1
echo
echo "v-22374 The audit system must alert the SA in the event of an audit processing failure. (audit_warn entry)"
echo "v-22375 The audit system must alert the SA when the audit storage volume approaches its capacity. (minfree entry)"
echo "v-22376 The audit system must be configured to audit account creation."
echo "v-22377 The audit system must be configured to audit account modification."
echo "v-22378 The audit system must be configured to audit account disabling."
echo "v-22382 The audit system must be configured to audit account termination. (ua in flag and naflag)"
echo "(audit_warn?)-----"
grep -i audit_warn /etc/mail/aliases
echo "-----(minfree)"
egrep '^minfree:' /etc/security/audit_control
echo "-----(ua)"
grep -i ua /etc/security/audit_control
echo
echo "v-24357 The system must be configured to send audit records to a remote audit server. (audit_syslog plugin in use and audit.notice '@loc.al.ser.ver')"
grep -i plugin /etc/security/audit_control
echo "-----"
grep '@' /etc/syslog.conf | grep -v '^#'
echo
echo "v-976 Cron must not execute group-writable or ww programs. (/dev/null, /var/tmp are false culprits)"
cat /var/tmp/wwflist.txt | xargs -i grep {$1} /var/spool/cron/crontabs/*
echo
echo "v-977 Cron must not execute programs in, or subordinate to, ww dirs. (/dev/null, /var/tmp are false culprits)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | \
xargs -i find /{$1} -perm -002 -a -type d | xargs -i grep {$1} /var/spool/cron/crontabs/*
echo
echo "v-11994 Crontabs must be owned by root or the crontab creator."
echo "v-22385 Crontab files must be group-owned by root, sys, or the crontab creator's primary group."
ls -lL /var/spool/cron/crontabs
echo
echo "v-11995 Default system accounts (except root) must not be in the cron.allow file or must be in the cron.deny file, if cron.allow does not exist."
echo "(allow)-----"
cat /etc/cron.d/cron.allow
echo "----- (deny)"
cat /etc/cron.d/cron.deny
echo
echo "v-982 Cron logging must be implemented. (cron/log exist? and cronlog=yes)"
ls -lL /var/cron/log
echo "-----"
cat /etc/default/cron
echo
echo "v-4360 Cron programs must not set the umask to a value less restrictive than 077. (>=077)"
ls /var/spool/cron/crontabs | egrep -v '(.au|.new)' | xargs -i -t cat /var/spool/cron/crontabs/{$1} | grep -v "^#" | \
sed -e 's/^[0-9 *]*//' -e 's/^[a-zA-Z0-9 ]*//' -e 's/^[^\/].*[^\/a-zA-Z0-9]\///' -e 's/\///' -e 's/[^\/._a-zA-Z0-9].*//' | \
xargs -i -t grep umask /{$1} | grep -v '^#'
echo
echo "v-986 Default system accounts (except root) must not be in the at.allow file or must be in the at.deny file, if at.allow file does not exist."
cat /etc/cron.d/at.allow
echo
echo "v-988 The at daemon must not execute group-writable or ww programs. (none)"
cat /var/tmp/wwflist.txt | xargs -i grep -s {$1} /var/spool/cron/atjobs/*
echo
echo "v-989 The "at" daemon must not execute programs in, or subordinate to, ww dirs. (none)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | \
xargs -i find /{$1} -perm -002 -a -type d | xargs -i grep -s {$1} /var/spool/cron/atjobs/*
echo
echo "v-4364 The at dir must have mode 0755 or less permissive."
echo "v-4365 The at  dir must be owned by root, bin, or sys."
echo "v-22396 The at dir must be group-owned by root, bin, or sys. (<=755, root/owner, owner group)"
ls -ld /var/spool/cron/atjobs | awk '{l=0;m=0;n=0;for(p=1;p<=7;p+=3)\
{a=substr($1,p+1,1);b=substr($1,p+2,1);c=substr($1,p+3,1);if(p==1){if(a!~/[-]/)l+=4;if(b!~/[-]/)l+=2;if(c!~/[-]/)l+=1;}\
else if(p==4){if(a!~/[-]/)m+=4;if(b!~/[-]/)m+=2;if(c!~/[-]/)m+=1;}else if(p==7){if(a!~/[-]/)n+=4;if(b!~/[-]/)n+=2;if(c!~/[-]/)n+=1;}}\
if(m>5||n>5)print"--> "$0;else print$0;}'
echo
echo "v-4366 At jobs must not set the umask to a value less restrictive than 077. (>=077)"
ls /var/spool/cron/atjobs | egrep -v '(.au|.new)' | xargs -i cat /var/spool/cron/atjobs/{$1} | grep -v "^#" | \
sed -e 's/^[0-9 *]*//' -e 's/^[a-zA-Z0-9 ]*//' -e 's/^[^\/].*[^\/a-zA-Z0-9]\///' -e 's/\///' -e 's/[^\/._a-zA-Z0-9].*//' | \
xargs -i -t grep umask /{$1} | grep -v '^#'
echo
echo "v-11996 Process core dumps must be disabled unless needed. (none, not 1)"
echo "(enabled?) -----"
egrep "COREADM_.*_ENABLED" /etc/coreadm.conf | grep -i yes
echo "----- (dumpsize)"
grep -i coredumpsize /etc/system
echo
echo "v-22399 The system must be configured to store any process core dumps in a specific, centralized directory."
echo "v-22400 The centralized process core dump data directory must be owned by root."
echo "v-22401 The centralized process core dump data directory must be group-owned by root, bin, or sys."
echo "v-22402 The centralized process core dump data directory must have mode 0700 or less permissive."
echo "(absolute path) -----"
grep COREADM_GLOB_PATTERN /etc/coreadm.conf
echo "----- (root, root, <=700)"
grep COREADM_GLOB_PATTERN /etc/coreadm.conf | cut -d= -f 2 | sed 's/\/[A-Za-z0-9_]*\_.*//' | xargs -i ls -ld {$1}
echo
echo "v-22404 Kernel core dumps must be disabled unless needed. (none)"
grep DUMPADM_ENABLE /etc/dumpadm.conf | grep -i yes
echo
echo "v-22405 The kernel core dump data directory must be group-owned by root."
echo "v-22406 The kernel core dump data directory must have mode 0700 or less permissive. (root, <=700)"
grep DUMPADM_SAVDIR /etc/dumpadm.conf | cut -d= -f 2 | sed 's/\/[A-Za-z0-9_]*\_.*//' | xargs -i ls -ld {$1}
echo
echo "v-12002 The system must not forward IPv4 source-routed packets. (0)"
ndd /dev/ip ip_forward_src_routed
echo
echo "v-23741 TCP backlog queue sizes must be set appropriately. (>1280,=1024)"
echo "(tcp_conn_req_max_q0) -----"
ndd /dev/tcp tcp_conn_req_max_q0
echo "----- (tcp_conn_req_max_q)"
ndd /dev/tcp tcp_conn_req_max_q
echo
echo "v-22409 The system must not process ICMP timestamp requests. (0)"
ndd /dev/ip ip_respond_to_timestamp
echo
echo "v-22410 The system must not respond to ICMPv4 echoes sent to a broadcast address. (0)"
echo "(From STIG: echo broadcast) -----"
ndd /dev/ip ip_respond_to_echo_broadcast
echo
echo "v-22411 The system must not respond to ICMP timestamp requests sent to a broadcast address. (0,0)"
echo "(From STIG: echo broadcast) -----"
ndd /dev/ip ip_respond_to_echo_broadcast
echo "----- (I think this is what it's supposed to be: timestamp broadcast)"
ndd /dev/ip ip_respond_to_timestamp_broadcast
echo
echo "v-22412 The system must not apply reversed source routing to TCP responses. (0)"
ndd /dev/tcp tcp_rev_src_routes
echo
echo "v-22415 Proxy ARP must not be enabled on the system. (none)"
arp -a | grep P
echo
echo "v-22416 The system must ignore IPv4 ICMP redirect messages. (1)"
ndd -get /dev/ip ip_ignore_redirect
echo
echo "v-22417 The system must not send IPv4 ICMP redirects. (0)"
ndd /dev/ip ip_send_redirects
echo
echo "v-22418 The system must log martian packets. (LOL)"
echo "(rules in place)-----"
ipfstat -i
echo "----- (ipf.conf)"
egrep -v '(^#|^$)' /etc/ipf/ipf.conf
echo
echo "v-23738 The system must use a separate file system for the system audit data path. (filesystem)"
grep -i dir /etc/security/audit_control | cut -d: -f 2 | xargs -i grep {$1} /etc/vfstab
echo
echo "v-22422 All local file systems must employ journaling or another mechanism ensuring file system consistency. (none)"
mount | grep '^/dev/' | grep -v '(logging|vxfs|zfs)' | grep -v /dev/fd
echo
echo "v-12004 The system must log authentication informational data. (locations for auth entries defined)"
grep -v '^#' /etc/syslog.conf | grep 'auth.*'
echo
echo "v-12005 Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled."
echo "(inetd)-----"
svcs -a | grep inetd
echo "----- (inet services enabled)"
inetadm | grep -v disabled
echo
echo "v-821 The inetd.conf file must be owned by root or bin."
echo "v-22423 The inetd.conf file must be group-owned by root, bin, or sys. (root/bin, root/bin/sys)"
ls -lL /etc/inet/inetd.conf
echo
echo "v-1011 Inetd or xinetd logging/tracing must be enabled. (tcp_trace=true)"
echo "(inet service trace)-----"
inetadm -p | grep tcp_trace
echo "----- (managed process trace)"
inetadm | grep enabled | awk '{print $NF}' | xargs inetadm -l | egrep -i '(exec|tcp_trace)'
echo
echo "v-22430 The portmap or rpcbind service must not be installed unless needed. (rpcbind needed so non-000)"
ls -lL /usr/sbin/rpcbind
echo
echo "v-12049 Network analysis tools must not be installed. (none)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find -L /{$1} \( -name ethereal -o -name wireshark -o -name tshark \
-o -name netcat -o -name tcpdump -o -name snoop \) -ls
echo
echo "v-827 The hosts.lpd file (or equivalent) must not contain a + character. (none)"
echo "(listen parameter)-----"
grep -i listen /etc/apache/httpd-standalone-ipp.conf | grep -v '^#'
echo "-----"
grep -i 'allow from' /etc/apache/httpd-standalone-ipp.conf | grep -v '^#'
echo
echo "v-828 The hosts.lpd (or equivalent) file must be owned by root."
echo "v-22435 The hosts.lpd (or equivalent) file must be group-owned by root, bin, or sys."
echo "v-829 The hosts.lpd (or equivalent) must have mode 0644 or less permissive. (root, root/bin/sys, <=644)"
ls -lL /etc/apache/httpd-standalone-ipp.conf /etc/printers.conf /etc/samba/smb.conf
echo
echo "v-4371 The traceroute file must have mode 0700 or less permissive. (<=700)"
ls -lL /usr/sbin/traceroute
echo
echo "v-4382 Administrative accounts must not run a web browser, except as needed for local service administration. (none)"
cut -d: -f 6 /etc/passwd | sed -e 's/\///' -e '/^$/ d' | grep root | xargs -i ls -la /{$1} | egrep '(.netscape|.mozilla)'
echo
echo "v-22438 The aliases file must be group-owned by root, sys, smmsp, or bin."
echo "v-832 The alias file must have mode 0644 or less permissive. (root/sys/smmsp/bin, <=644)"
egrep '^O(A | AliasFile)' /etc/mail/sendmail.cf | cut -d= -f 2 | xargs -i ls -lL {$1}
echo "-----"
egrep '^O(A | AliasFile)' /etc/mail/sendmail.cf | cut -d= -f 2 | xargs -i ls -lL {$1}.db
echo
echo "v-22440 Files executed through a mail aliases file must be group-owned by root, bin, or sys, and must be in a dir group-owned by root, bin, or sys. (root/bin/sys)"
egrep '^O(A | AliasFile)' /etc/mail/sendmail.cf | cut -d= -f 2 | xargs -i cat {$1} | egrep -v '(^#|^$)'
echo
echo "v-837 The SMTP service log file must be owned by root."
echo "v-838 The SMTP service log file must have mode 0644 or less permissive."
grep -v '^#' /etc/syslog.conf | grep mail | sed 's/^.*[^a-zA-Z0-9]\///' | xargs -i ls -lL /{$1}
echo
echo "v-12006 The SMTP service HELP command must not be enabled. (none)"
grep -i helpfile /etc/mail/sendmail.cf | cut -d= -f 2 | xargs -i cat {$1}
echo
echo "v-4384 The SMTP services SMTP greeting must not provide version information. (no \$v/no \$Z)"
grep -i smtpgreetingmessage /etc/mail/sendmail.cf
echo
echo "v-4385 The system must not use .forward files. (none)"
ls / | sed -e '/proc/ d' -e '/net/ d' -e '/system/ d' -e '/home/ d' -e '/ace/ d' | xargs -i find -L /{$1} -name .forward -ls
echo
echo "v-4689 The SMTP service must be an up-to-date version."
echo "v-4690 The Sendmail server must have the debug feature disabled. (151074 is 8.14.7 Feb 2014, version >8.6)"
showrev -p | egrep "Patch: 151074" | cut -d" " -f 2
/usr/lib/sendmail -d0 -bt < /dev/null | grep -i version
echo
echo "v-4691 The SMTP service must not have a uudecode alias active. (none)"
egrep '^O(A | AliasFile)' /etc/mail/sendmail.cf | cut -d= -f 2 | xargs -i grep -i decode {$1} | grep -v '^#'
echo
echo "v-4692 The SMTP service must not have the EXPN feature active."
echo "v-4693 The SMTP service must not have the VRFY feature active."
echo "v-4694 The Sendmail service must not have the wizard backdoor active. (goaway/noexpn, novrfy, no 'wiz')"
egrep -i '(goaway|expn|vrfy|wiz)' /etc/mail/sendmail.cf | grep -v '^#'
echo
echo "v-23952 Mail relaying must be restricted."
echo "(loopback address?)-----"
grep -i daemonportoptions /etc/mail/sendmail.cf | grep -v '^#'
echo "----- (no, then check for no promiscuity)"
grep -i promis /etc/mail/cf/cf/sendmail.mc
echo
echo "v-12010 Unencrypted FTP must not be used on the system."
echo "v-846 Anonymous FTP must not be active on the system unless authorized."
echo "v-4702 If the system is an anonymous FTP server, it must be isolated to the DMZ network.(none)"
svcs -a | grep "\/ftp" | egrep -i -v disabled
echo
echo "v-841 The ftpusers file must contain account names not allowed to use FTP. (0 entry is fail)"
cut -d: -f 1 /etc/passwd | xargs -i -t grep -i -w -c {$1} /etc/ftpd/ftpusers
echo
echo "v-845 The FTP daemon must be configured for logging or verbose mode. (none)"
inetadm -l ftp | grep in.ftpd | grep -v "\-l"
echo
echo "v-848 The TFTP daemon must have mode 0755 or less permissive. (<=755)"
ls -lL /usr/sbin/in.tftpd
echo
echo "v-849 The TFTP daemon must be configured, including a TFTP user, a non-login shell, such as /bin/false, and a home dir owned by the TFTP user."
echo "v-4695 Any active TFTP daemon must be authorized and approved in the system accreditation package. (none)"
svcs -a | grep tftp | egrep -i -v disabled
echo
echo "v-850 Any X Windows host must write .Xauthority files."
awk -F: '($2!~/NP/&&$2!~/LK/){print $1}' /etc/shadow | xargs -i grep "^{$1}:" /etc/passwd | awk -F: '{print $6}' | grep '^/' | \
xargs -i sh -c "find {$1}/ -name .Xauthority -ls"
echo
echo "v-12016 .Xauthority or X*.hosts file(s) must be used to restrict access to X. (is X running? check above if so)"
ps -ef | grep X
echo
echo "v-4696 The system must not have the UUCP service active. (none)"
svcs -a | grep uucp | egrep -i -v disabled
echo
echo "v-993 SNMP communities, users, and passphrases must be changed from the default. (none)"
egrep -i '(default|public|private|snmp-trap|password)' /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf \
/etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf | grep -v '#'
echo
echo "v-22447 The SNMP service must use only SNMPv3 or its successors. (v1/v2c/community/com2sec denotes v1/v2c, access/rouser denotes v3)"
egrep '(v1|v2c|community|com2sec|access|rouser)' /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf \
/etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf | grep -v '#'
echo
echo "v-994 The snmpd.conf file must have mode 0600 or less permissive. (<=600)"
ls -lL /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf
echo
echo "v-995 Management Information Base (MIB) files must have mode 0640 or less permissive."
echo "(mib)-----"
find /etc/sma/snmp /var/sma_snmp /etc/snmp/conf /usr/sfw/lib/sma_snmp -type f -ls | grep -i '\.mib' | egrep -v '\.conf$'
echo
echo "v-12019 The snmpd.conf files must be owned by root."
echo "v-22451 The snmpd.conf file must be group-owned by root, sys, or bin. (none)"
echo "----- (root owned)"
find /etc/sma/snmp /var/sma_snmp /etc/snmp/conf /usr/sfw/lib/sma_snmp -type f ! \( -user root \) -ls
echo "----- (group owned)"
find /etc/sma/snmp /var/sma_snmp /etc/snmp/conf /usr/sfw/lib/sma_snmp -type f ! \( -group root -o -group sys -o -group bin \) -ls
echo
echo "v-22455 The system must use a remote syslog server (log host)."
echo "v-4395 The system must only use remote syslog servers (log hosts) justified and documented. (@loc.al.ser.ver)"
grep '@' /etc/syslog.conf | grep -v '^#'
echo
echo "v-12021 The syslog daemon must not accept remote messages unless it is a syslog server. (false)"
svcprop system-log | grep log_from_remote
echo
echo "v-22457 The SSH daemon must only listen on management network addresses."
egrep -i listen /etc/ssh/sshd_config | grep -v '^#'
echo
echo "v-22458 The SSH daemon must be configured to only use FIPS 140-2 approved ciphers. (ctr)"
egrep -i ciphers /etc/ssh/sshd_config | grep -v '^#'
echo
echo "v-22460 The SSH daemon must be configured to only use (MACs) employing FIPS 140-2. (hmac-sha1)"
egrep -i macs /etc/ssh/sshd_config | grep -v '^#'
echo
echo "v-22461 The SSH client must be configured to only use FIPS 140-2 approved ciphers. (ctr)"
egrep -i ciphers /etc/ssh/ssh_config | grep -v '^#'
echo
echo "v-22463 The SSH client must be configured to only use (MACs) employing FIPS 140-2. (hmac-sha1)"
egrep -i macs /etc/ssh/ssh_config | grep -v '^#'
echo
echo "v-22470 The SSH daemon must restrict login ability to specific users and/or groups."
egrep -i '(allowgroups|allowusers)' /etc/ssh/sshd_config | grep -v '^#'
echo
echo "v-22485 The SSH daemon must perform strict mode checking of home directory configuration files. (yes)"
egrep -i strict /etc/ssh/sshd_config | grep -v '^#'
echo
echo "v-22487 The SSH daemon must not allow rhosts RSA authentication. (no)"
egrep -i rhostsrsa /etc/ssh/sshd_config | grep -v '^#'
echo
echo "v-4397 The system must be configured with a default gateway for IPv4 if the system uses IPv4."
netstat -r | grep default
echo
echo "v-22665 The system must not be running any routing protocol daemons. (none)"
ps -ef | egrep -i '(ospf|route|bgp|zebra|quagga)' | grep -v egrep
echo
echo "v-12023 IP forwarding for IPv4 must not be enabled. (none)"
svcs -a | grep -i ipv4-for | grep -v disabled
echo
echo "v-22491 The system must not have IP forwarding for IPv6 enabled. (none)"
ndd /dev/ip6 ip6_forwarding | grep -v 0
echo
echo "v-931 All NFS-exported system files and system directories must be owned by root."
echo "v-22496 All NFS exported system files and system directories must be group-owned by root, bin, or sys."
echo "v-932 The NFS anonymous UID and GID must be configured to values that have no permissions."
echo "v-933 The NFS server must be configured to restrict file system access to local hosts."
echo "v-935 The NFS server must not allow remote root access. (root, root/sys/bin, anon=, rw/ro, root=)"
cat /etc/dfs/sharetab
echo
echo "v-934 The system's NFS export config not have sec option set to none; default authentication not to be set to none. (no 0 in second column)"
grep "^default" /etc/nfssec.conf
echo
echo "v-936 The nosuid option must be enabled on all NFS client mounts. (none)"
grep nfs /etc/mnttab | grep -v nosuid | grep -v :vold
echo
echo "v-1026 The Samba Web Administration Tool (SWAT) must be restricted to the local host or require SSL. (disabled)"
svcs swat
echo
echo "v-1030 The smb.conf file must use the hosts option to restrict access to Samba. (enabled)"
grep -i host /etc/samba/smb.conf
echo
echo "v-22500 Samba must be configured to use encrypted passwords."
grep -i 'encrypt password' /etc/samba/smb.conf
echo
echo "v-4399 The system must not use UDP for NIS/NIS+. (none)"
rpcinfo -p | grep -i yp | grep -i udp
echo
echo "v-12026 NIS maps must be protected through hard-to-guess domain names."
domainname
echo
echo "v-926 Any NIS+ server must be operating at security level 2."
niscat cred.org_dir
echo
echo "v-782 The system must have a host-based intrusion detection tool installed. (McAfee hips)"
echo "(what McAfee is running)-----"
ps -ef | grep -i mca
echo "----- (McAfee dir)"
ls -l /opt/McAfee
echo
echo "v-22506 The system package management tool must be used to verify system software periodically. (pkgchk)"
crontab -l | egrep -i pkgchk
echo
echo "v-940 The system must use an access control program. (true)"
svcprop -p defaults inetd | grep tcp_wrappers
echo
echo "v-941 The system's access control program must log each system access attempt."
grep -v "^#" /etc/syslog.conf | egrep -i '(mail|auth)'
echo
echo "v-12765 The system must use and update a DoD-approved virus scan program. (uvscan)"
echo "(uvscan run)-----"
grep uvscan /var/spool/cron/crontabs/*
echo "----- (.dat files up to date)"
ls -l /home/nso/uvscan/avv*.dat
echo
echo "v-22530 The Reliable Datagram Sockets (RDS) protocol must be disabled or not installed unless required. (SUNWrds not installed)"
echo "(package) -----"
pkginfo | grep SUNWrds
echo "----- (exclude if installed)"
grep -i rds /etc/system
echo
echo "v-22533 The Transparent Inter-Process Communication (TIPC) protocol must be disabled or not installed. (SUNWtipc not installed)"
echo "(package) -----"
pkginfo | grep SUNWtipc
echo "----- (exclude if installed)"
grep -i tipc /etc/system
echo
echo "v-22545 The system must not have 6to4 enabled. (none)"
ifconfig -a | grep -i ipv6
echo
echo "v-22547 The system must not have IP tunnels configured. (none)"
ifconfig -a | grep -i 'ip.*tun'
echo
echo "v-22550 The system must ignore IPv6 ICMP redirect messages. (1)"
ndd /dev/ip6 ip6_ignore_redirect
echo
echo "v-22551 The system must not send IPv6 ICMP redirects. (0)"
ndd /dev/ip6 ip6_send_redirects
echo
echo "v-22553 The system must not forward IPv6 source-routed packets."
echo "v-22554 The system must not accept source-routed IPv6 packets. (0)"
ndd /dev/ip6 ip6_forward_src_routed
echo
echo "v-23972 The system must not respond to ICMPv6 echo requests sent to a broadcast address. (0)"
ndd -get /dev/ip6 ip6_respond_to_echo_multicast
echo
echo "v-22555 LDAP for authentication, the system must use a TLS connection using FIPS 140-2. (ldap entries/AUTH=method/SERVICE_ATH= tls:xxx/server algorithm)"
echo "(nssldap, n/a if 0/none)-----"
grep -v '^#' /etc/nsswitch.conf | grep -i -c ldap
echo "----- (Auth methods start with tls:)"
grep -i "NS_LDAP_AUTH" /var/ldap/ldap_client_file
echo "----- (Not sure if Service Auth methods count)"
grep -i "NS_LDAP_SERVICE_AUTH" /var/ldap/ldap_client_file
echo "----- (LDAP servers use FIPS certs)"
grep -i "NS_LDAP_SERVERS" /var/ldap/ldap_client_file | cut -d= -f 2 | sed 's/,/\
/' | xargs -i -t certutil -L -n {$1} -d /var/ldap | grep -i algorithm
echo
echo "v-22563 LDAP for authentication, the TLS cert auth file and/or directory must be owned by root."
echo "v-22564 LDAP for authentication, the TLS cert auth file and/or directory must be group-owned by root, bin, or sys."
echo "v-22565 LDAP for authentication, the TLS cert auth file and/or directory must have mode 0644. (root, root/sys/bin, <=644)"
ls -laL /var/ldap/*.db
echo
echo "v-22579 The system must have USB Mass Storage disabled unless needed."
echo "v-22580 The system must have IEEE 1394 (Firewire) disabled unless needed. (none, excluded, excluded)"
modinfo | egrep -i '(usb|hid)'
echo "----- (exclude dynamic loading)"
egrep -i '(usb|hid|1394)' /etc/system
echo
echo "v-22583 The system's local firewall must implement a deny-all, allow-by-exception policy."
echo "(rules in place)-----"
ipfstat -i
echo "----- (ipf.conf)"
egrep -v '(^#|^$)' /etc/ipf/ipf.conf
echo
echo "v-22589 The system package management tool must not automatically obtain updates. (none)"
crontab -l | egrep -i smpatch
echo "-----"
grep smpatch /var/spool/cron/crontabs/* /var/spool/cron/atjobs/*
echo
