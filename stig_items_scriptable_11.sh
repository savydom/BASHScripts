echo "V-47805 The audit system must be configured to audit file deletions."
echo "V-47807 The audit system must be configured to audit account creation"
echo "V-47809 The audit system must be configured to audit account modification."
echo "V-47811 The OS must automatically audit account disabling actions."
echo "V-47813 The OS must automatically audit account termination."
echo "V-47815 The OS must ensure unauthorized, security-relevant configuration changes detected are tracked."
echo "V-47817 The audit system must be configured to audit all administrative, privileged, and security actions."
echo "V-47819 The audit system must be configured to audit login, logout, and session initiation."
echo "V-47821 The audit system must be configured to audit all discretionary access control permission modifications."
echo "V-47823 The audit system must be configured to audit the loading and unloading of dynamic kernel modules."
echo "V-47825 The audit system must be configured to audit failed attempts to access files and programs."
echo "(flags fd,ps,as,lo,fm,fa) -----"
auditconfig -getflags | grep active |sed s/'active user default audit flags ='//
echo "----- (naflags fd,ps,as,lo,fm,fa)"
auditconfig -getnaflags | grep active | sed s/'active user default audit flags ='//
echo "----- (argv)"
auditconfig -getpolicy | grep active | grep argv
echo
echo "V-47827 The OS must be configured to send audit records to a remote audit server."
echo "(If inactive, its probably managed by Splunk) -----"
auditconfig -getplugin | grep audit_syslog | grep -i inactive
echo "----- (If active, audit.notice should be set)"
grep audit.notice /etc/syslog.conf
echo
echo "V-47831 The auditing system must not define a different auditing level for specific users. (none)"
echo "(root shows up because it is a role) -----"
cut -d: -f 1 /etc/passwd | xargs -i -t userattr audit_flags {$1}
echo
echo "V-47837 The audit system must maintain a central audit trail for all zones. (none)"
auditconfig -getpolicy | grep active | grep perzone
echo
echo "V-47839 The audit system must identify in which zone an event occurred. (none)"
auditconfig -getpolicy | grep active | grep zonename
echo
echo "V-47841 The systems physical devices must not be assigned to non-global zones. (none)"
zoneadm list -vi | egrep -v '(global|BRAND)' | awk '{print $2}' | xargs -i zonecfg -z {$1} info | grep dev
echo
echo "V-47857 The OS must allocate audit record storage capacity. (2,/var/audit,on,5G,5G)"
auditconfig -getplugin audit_binfile | awk -F\; '{for(i=1;i<=NF;i++){print $i;}}' | grep p_minfree
auditconfig -getplugin audit_binfile | awk -F\; '{for(i=1;i<=NF;i++){print $i;}}' | grep p_dir
zfs get compression,quota,reservation | grep audit
echo
echo "V-49621 The OS must configure auditing to reduce the likelihood of storage capacity being exceeded."
auditconfig -getplugin | grep p_fsize
echo
echo "V-47863 The OS must shut down by default upon audit failure. (ahlt)"
auditconfig -getpolicy | grep ahlt
echo
echo "V-47869 The OS must protect audit information from unauthorized read access."
echo "V-47875 The OS must protect audit information from unauthorized modification."
echo "V-47879 The OS must protect audit information from unauthorized deletion."
echo "(640,root,root) -----"
auditconfig -getplugin audit_binfile | awk -F\; '{for(i=1;i<=NF;i++){print $i;}}' | grep p_dir | awk -F\= '{print$2}' \
| xargs -i ls -lLd {$1}
echo
echo "V-47881 The System packages must be up to date with the most recent vendor updates and security fixes."
pkg publisher
echo
echo "V-47883 The system must verify that package updates are digitally signed. (verify)"
pkg property | grep signature-policy
echo
echo "V-47885 The OS must protect audit tools from unauthorized access."
echo "V-47887 The OS must protect audit tools from unauthorized modification."
echo "V-47889 The OS must protect audit tools from unauthorized deletion."
echo "V-47891 System packages must be configured with the vendor-provided files, permissions, and ownerships."
echo "(filtered list shows mostly explainable changes) -----"
pkg verify | egrep -v '(man|Mode|pkg)'
echo
echo "V-47899 The OS must manage excess capacity, bandwidth, or other redundancy to limit the effects of DOS attacks."
echo "V-47903 The OS must identify potentially security-relevant error conditions."
echo "V-47907 The OS must verify the correct operation of security functions..."
echo "(none) -----"
echo
echo "V-47919 The rpcbind service must be configured for local only services."
echo "(Cannot be set to true for NFS /home directories) -----"
svcprop -p config/local_only network/rpc/bind
echo
echo "V-47923 The OS must employ automated mechanisms to detect the addition of unauthorized components & devices into the OS. (none)"
echo "(List files installed by packagemanager, are they authorized?) -----"
pkg history -o finish,user,operation,command | grep install | grep packagemanager
echo
echo "V-47925 The OS must be configured to provide essential capabilities."
echo "V-47927 The OS must employ automated mechanisms to prevent program execution"
echo "(Are there any unauthorized packages?) -----"
pkg list
echo
echo "V-47929 If graphical login access for the console is required, the service must be in local-only mode. (false)"
svcprop -p options/tcp_listen svc:/app/x11/x11-server
echo
echo "V-47931 Generic Security Services (GSS) must be disabled. (not enabled)"
svcs -Ho state svc:/network/rpc/gss
echo
echo "V-47933 Systems services that are not required must be disabled."
echo "(Are there any unauthorized services?) -----"
svcs -Ha | grep online
echo
echo "V-47935 TCP Wrappers must be enabled and configured per site policy to only allow access by approved hosts and services. (true,allow/deny entries)"
inetadm -p | grep tcp_wrappers
grep -v '^#' /etc/hosts.allow /etc/hosts.deny
echo
echo "V-47937 All manual editing of system-relevant files shall be done using the pfedit command. (vi is bad mmmkay?)"
echo
echo "V-47941 The OS must back up audit records at least every seven days. (splunk)"
echo
echo "V-47943 User passwords must be changed at least every 56 days."
echo "(none - system accounts are exempt) -----"
cut -d: -f1 /etc/passwd | xargs -i logins -ox -l {$1} | awk -F: '{if( $1!="root" && $8!="LK" && $8!="NL" && $11!="56"){print $0}}'
echo "----- (maxweeks=8)"
grep -i maxweeks /etc/default/passwd
echo 
echo "V-47945 The OS must employ automated mechanisms to alert security personnel of any activities with security implications."
echo "V-47947 The OS must protect information obtained from intrusion-monitoring tools."
echo "(HIPS is installed) -----"
echo
echo "V-47949 The OS must automatically terminate temporary accounts within 72 hours."
echo "(Temp accounts not used) -----"
echo
echo "V-47951 Intrusion detection and prevention capabilities must be implemented to prevent non-privileged users from circumventing such protections."
echo "(HIPS is installed) -----"
echo
echo "V-47953 The OS must enforce minimum password lifetime restrictions."
echo "(none) -----"
cut -d: -f1 /etc/passwd | xargs -i logins -ox -l {$1} | awk -F: '{if( $1!="root" && $8!="LK" && $8!="NL" && $10<1){print $0}}'
echo "----- (minweeks=1)"
grep -i minweeks /etc/default/passwd
echo
echo "V-47955 The OS must have malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code..."
echo "V-47959 The OS must employ malicious code protection mechanisms at workstations, servers, or mobile computing devices..."
echo "V-47963 The OS must prevent non-privileged users from circumventing malicious code protection capabilities."
echo "V-47965 The OS must employ automated mechanisms to determine the state of system components following frequency: HBSS 30 days."
echo "(HIPS is installed) -----"
echo
echo "V-47969 The OS must prevent the execution of prohibited mobile code."
echo "(Firefox is usually not installed - N/A) -----"
pkg list firefox
echo
echo "V-47973 The OS must conduct backups of OS documentation..."
echo "V-47975 The OS must conduct backups of system-level information..."
echo "V-47977 The OS must conduct backups of user-level information..."
echo "(EMC Networker) -----"
echo
echo "V-47979 The system must not have any unnecessary accounts. (no games,news,gopher,ftp,lp)"
echo "(If you want to remove lp, change user/grp to root on files in /etc & /var/spool) -----"
echo "----- (You may just want to ignore it for cups sake)"
cut -d: -f1 /etc/passwd | xargs -i getent passwd {$1}
echo
echo "V-47983 Direct logins must not be permitted to shared, default, app, or utility accounts."
echo "(Check system/app accounts for logins) -----"
cut -d: -f1 /etc/passwd | xargs -i auditreduce -c lo -u {$1} | praudit -l | grep -v '^file'
echo
echo "V-47985 The OS must synchronize internal clocks with a server that is synchronized to one of the USNO time servers."
echo "(NTP service) -----"
svcs -H ntp
echo "----- (ntp.conf servers - 104.149/14.150/nola/sd/119.5)"
grep server /etc/inet/ntp.conf
echo "----- (maxpoll - none)"
grep maxpoll /etc/inet/ntp.conf
echo "----- (ntpq -    none)"
ntpq -p | awk '($6 ~ /[0-9]+/ && $6 > 86400){print $1,$6}'
echo
echo "V-47987 A file integrity baseline must be created, maintained, and reviewed on at least weekly..."
echo "(bart log exists and date) -----"
ls -l /var/adm/log/bartlogs | grep bart
echo "----- (cron)"
crontab -l | grep bart
echo
echo "V-47995 SNMP communities, users, and passphrases must be changed from the default. (none)"
egrep '(public|private|trap|password)' /etc/net-snmp/snmp/snmpd.conf /var/net-snmp/snmpd.conf | grep '^#'
echo
echo "V-48003 The system must require passwords to change the boot device settings."
echo "(Cannot be set) -----"
eeprom security-mode
echo
echo "V-48007 The kernel core dump data dir must have mode 0700 or less permissive."
echo "V-48009 The kernel core dump data dir must be group-owned by root."
echo "V-48011 The kernel core dump data dir must be owned by root. (700,root,root)"
ls -ld /var/crash /var/share/crash
echo
echo "V-48013 Kernel core dumps must be disabled unless needed. (none)"
dumpadm -p 2>/dev/null | grep -i enabled | grep -vi no
echo
echo "V-48015 The centralized process core dump data dir must have mode 0700 or less permissive."
echo "V-48017 The centralized process core dump data dir must be group-owned by root, bin, or sys."
echo "V-48019 The centralized process core dump data dir must be owned by root. (700,root,root)"
ls -ld /var/core /var/core/* /var/cores /var/share/cores
echo
echo "V-48021 Process core dumps must be disabled unless needed. (none)"
coreadm | grep -i enabled | grep -vi logging
echo
echo "V-48023 Address Space Layout Randomization (ASLR) must be enabled."
echo "V-48025 The system must implement non-executable program stacks."
echo "('enabled') -----"
sxadm info -p | grep aslr | grep enabled
echo "----- (Sol11.3 'enabled (all)')"
sxadm status -p nxstack | grep enabled
echo "----- (Sol11.2 '1')"
grep noexec_user_stack /etc/system
echo
echo "V-48029 The operator must document all file system objects that have non-standard access control list settings. (none)"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
-o -fstype objfs -o -fstype proc \) -prune -o -acl -ls
echo
echo "V-48031 The OS must protect the audit records resulting from non-local accesses to privileged accounts... (640)"
ls -Al /var/audit /var/share/audit/*
echo
echo "V-48037 The OS must have no files with extended attributes. (none)"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
-o -fstype objfs -o -fstype proc \) -prune -o -xattr -ls
echo
echo "V-48039 The OS must have no unowned files. (none)"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
-o -fstype objfs -o -fstype proc \) -prune \( -nouser -o -nogroup \) -ls
echo
echo "V-48059 All valid SUID/SGID files must be documented. (none)"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs \
-o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -4000 -o -perm -2000 -print | sort > /var/tmp/sufi.tmp
pkg contents -Ha mode=4??? -a mode=2??? -t file -o path | sort | xargs -i sh -c "echo /{$1}" > /var/tmp/supa.tmp
cat /var/tmp/sufi.tmp | xargs -i -t grep -c {$1} /var/tmp/supa.tmp 2>&1 | \
xargs -i nawk '{j=1;i=1;ft="";FS="\n";tf[j]=$0;j++;while (getline){tf[j]=$0;j++};for (i=1;i<j;i++){if (tf[i]~"0" || tf[i]~"false") print tf[i-1]}}' | \
awk '{print$3}'
echo
echo "V-48063 World-writable files must not exist. (none)"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -0002 -print
echo
echo "V-48069 Duplicate group names must not exist. (none)"
getent group | awk -F: '{print$1}' | uniq -d
echo
echo "V-48073 Duplicate user names must not exist. (none)"
getent passwd | awk -F: '{print$1}' | uniq -d
echo
echo "V-48075 The value mesg n must be configured as the default setting for all users. (mesg n)"
grep '^mesg' /etc/.login /etc/profile
echo
echo "V-48079 User accounts must be locked after 35 days of inactivity."
echo "(useradd inactive=35)"
useradd -D | grep inactive
echo "----- (users not at 35)"
cut -f1 -d: /etc/passwd | xargs -i logins -axo -l {$1} | awk -F: '($13!=-1 && $13!=35){print$1}'
echo
echo "V-48081 Duplicate Group IDs (GIDs) must not exist for multiple groups. (none)"
getent group | awk -F: '{print$3}' | uniq -d
echo
echo "V-48083 The OS must manage information system identifiers by disabling the user identifier after 35 days..."
echo "V-48085 Emergency accounts must be locked after 35 days of inactivity."
echo "(useradd inactive=35)"
useradd -D | grep inactive
echo "----- (users not at 35)"
cut -f1 -d: /etc/passwd | xargs -i logins -axo -l {$1} | awk -F: '($13!=-1 && $13!=35){print$1}'
echo
echo "V-48091 Duplicate UIDs must not exist for multiple non-organizational users."
echo "V-48095 Duplicate User IDs (UIDs) must not exist for users within the organization. (none)"
logins -d
echo
echo "V-48097 All home directories must be owned by the respective user assigned to it in /etc/passwd."
echo "V-48105 All user accounts must be configured to use a home dir that exists."
echo "(home dir owned by user,home dir actually exists) -----"
cut -f1 -d: /etc/passwd | xargs -i logins -axo -l {$1} | awk -F: '($8!="LK" && $8!="NL"){print$1":"$6}' | \
nawk  -F: '($2!="\/"){("ls -ld "$2 | getline q);close("ls -ld "$2);printf("%15s %25s %35s\n",$1,$2,q)}'
echo
echo "V-48125 Unauthorized use of the at or cron capabilities must not be permitted."
echo "(no cron.deny) -----"
ls -ld /etc/cron.d/cron.deny 2>/dev/null
echo "----- (no at.deny)"
ls -ld /etc/cron.d/at.deny 2>/dev/null
echo "----- (cron.allow root)"
cat /etc/cron.d/cron.allow
echo "----- (no at.allow)"
cat /etc/cron.d/at.allow 2>/dev/null
echo
echo "V-48129 Permissions on user . files must be 750 or less permissive. (none)"
cut -f1 -d: /etc/passwd | xargs -i logins -axo -l {$1} | awk -F: '($8!="LK" && $8!="NL"){print$6}' | \
xargs -i sh -c "find {$1}/.[A-Za-z0-9]* ! -type l \( -perm -20 -o -perm -02 \) -ls"
echo
echo "V-48135 The OS must provide the capability for users to directly initiate session lock mechanisms."
echo "(Gnome GUI is not used) -----"
echo
echo "V-48137 The sticky bit must be set on all world writable directories. (none)"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) \
-prune -o -type d \( -perm -0002 -a ! -perm -1000 \) -ls
echo
echo "V-48141 The OS must protect the integrity of transmitted information."
echo "(ipsec enabled) -----"
svcs -H svc:/network/ipsec/policy:default
echo
echo "V-48145 The OS must use cryptographic mechanisms to protect the integrity of audit information."
echo "(N/A not required by datacenter) -----"
echo
echo "V-48147 The OS must prevent remote devices that have established a non-remote connection..."
echo "(name=Restrict...desc=Restrict Out...limit=zone,!net) -----"
profiles -p RestrictOutbound info
echo
echo "V-48149 The OS must employ cryptographic mechanisms to prevent unauthorized disclosure of information at rest..."
echo "V-48151 The OS must limit the number of concurrent sessions for each account to an organization-defined number of sessions."
echo "V-48153 The OS must protect the confidentiality and integrity of information at rest."
echo "V-48155 The OS must employ cryptographic mechanisms to protect information in storage."
echo "(N/A not required by datacenter) -----"
echo
echo "V-48157 The OS must use cryptographic mechanisms to protect and restrict access to information on portable digital media. (none found)"
rmformat
echo
echo "V-48159 The OS must use cryptography to protect the confidentiality of remote access sessions."
echo "V-48161 The OS must maintain the confidentiality of information...in preparation for transmission."
echo "V-48163 The OS must employ cryptographic mechanisms to prevent unauthorized disclosure of information during transmission"
echo "(All sessions use SSH) -----"
echo
echo "V-48165 The system must disable directed broadcast packet forwarding. (0)"
ipadm show-prop -p _forward_directed_broadcasts -co current ip
echo
echo "V-48167 The OS must protect the confidentiality of transmitted information."
echo "(All sessions use SSH) -----"
echo
echo "V-48169 The system must not respond to ICMP timestamp requests. (0)"
ipadm show-prop -p _respond_to_timestamp -co current ip
echo
echo "V-48171 The OS must maintain the integrity of information...in preparation for transmission."
echo "(All sessions use SSH) -----"
echo
echo "V-48173 The system must not respond to ICMP broadcast timestamp requests. (0)"
ipadm show-prop -p _respond_to_timestamp_broadcast -co current ip
echo
echo "V-48175 The OS must employ cryptographic mechanisms to recognize changes to information during transmission..."
echo "(All sessions use SSH) -----"
echo
echo "V-48177 The system must not respond to ICMP broadcast netmask requests. (0)"
ipadm show-prop -p _respond_to_address_mask_broadcast -co current ip
echo
echo "V-48179 The OS must protect the integrity of transmitted information."
echo "(All sessions use SSH) -----"
echo
echo "V-48181 The system must not respond to broadcast ICMP echo requests. (0)"
ipadm show-prop -p _respond_to_echo_broadcast -co current ip
echo
echo "V-48183 The OS must employ FIPS-validate or NSA-approved cryptography to implement digital signatures. (all enabled)"
cryptoadm list fips-140
echo
echo "V-48185 The system must not respond to multicast echo requests. (0,0)"
ipadm show-prop -p _respond_to_echo_multicast -co current ipv4
ipadm show-prop -p _respond_to_echo_multicast -co current ipv6
echo
echo "V-48187 The OS must use mechanisms for authentication to a cryptographic module... (all enabled)"
cryptoadm list fips-140
echo
echo "V-48189 The system must ignore ICMP redirect messages. (1,1)"
ipadm show-prop -p _ignore_redirect -co current ipv4
ipadm show-prop -p _ignore_redirect -co current ipv6
echo
echo "V-48191 The OS must prevent internal users from sending out packets which attempt to manipulate or spoof invalid IP addresses."
echo "(Interfaces forwarding enabled?) -----"
dladm show-link -Z | grep -i phys | awk '{print$1}' | xargs -i ipadm show-ifprop {$1} -o ifname,property,proto,current | grep forwarding
echo "----- (Interfaces using Ether or Infini? vfxxx indicates Virtual Function/SR-IOV)"
dladm show-link -Z | grep -i phys | awk '{print$1}' | xargs -i dladm show-phys {$1}  -o link,media,device | egrep -i '(ether|infin|vf)'
echo "----- (Infiniband   ? Requires             restricted,ip-nospoof,dhcp-nospoof)"
echo "----- (Forwarding   ? Requires mac-nospoof,restricted,           dhcp-nospoof)"
echo "----- (VF/SR-IOV    ? Requires mac-nospoof,restricted,           dhcp-nospoof)"
echo "----- (Eth + No Fwd ? Requires mac-nospoof,restricted,ip-nospoof,dhcp-nospoof)"
dladm show-linkprop -p protection -o link,property,value | grep protection
echo
echo "V-48193 The system must set strict multihoming. (1,1)"
ipadm show-prop -p _strict_dst_multihoming -co current ipv4
ipadm show-prop -p _strict_dst_multihoming -co current ipv6
echo
echo "V-48197 The system must disable ICMP redirect messages. (off,off)"
ipadm show-prop -p send_redirects -co current ipv4
ipadm show-prop -p send_redirects -co current ipv6
echo
echo "V-48201 The system must disable TCP reverse IP source routing. (0)"
ipadm show-prop -p _rev_src_routes -co current tcp
echo
echo "V-48207 The system must set maximum number of half-open TCP connections to 4096. (4096)"
ipadm show-prop -p _conn_req_max_q0 -co current tcp
echo
echo "V-48211 The system must set maximum number of incoming connections to 1024. (>=1024)"
ipadm show-prop -p _conn_req_max_q -co current tcp
echo
echo "V-48213 The system must prevent local apps from generating source-routed packets."
echo "(block out log quick from any to any with opt lsrr/ssrr) -----"
echo "----- (ipfstat)"
ipfstat -o
echo "----- (ipf.conf)"
grep -v '^#' /etc/ipf/ipf.conf
echo
echo "V-48215 The OS must enforce requirements for remote connections to the information system."
echo "(block in/out is set for datacenter, fragspass, etc. are not) -----"
svcs -H ipfilter
ipfstat -io
echo
echo "V-48217 The system must disable network routing unless required. (none)"
routeadm -p | egrep '(routing|forwarding)' | grep enabled
echo
echo "V-48219 The OS must block both inbound and outbound traffic between instant messaging clients..."
echo "(block in/out is set for datacenter, fragspass, etc. are not) -----"
svcs -H ipfilter
ipfstat -io
echo
echo "V-48221 The system must implement TCP Wrappers."
echo "(tcp_wrappers TRUE) -----"
inetadm -p | grep tcp_wrappers
echo "----- (services)"
inetadm | grep -v FMRI | awk '{print$3}' | xargs -i -t inetadm -l {$1} | grep -i wrapper
echo
echo "V-48223 The OS must use cryptography to protect the integrity of remote access sessions."
echo "V-48225 The OS must configure the information system to specifically prohibit...functions, ports, protocols, and/or services."
echo "V-48227 The OS must disable the use of organization-defined networking protocols within the OS deemed to be nonsecure..."
echo "V-48229 The OS must implement host-based boundary protection mechanisms for servers..."
echo "V-48231 The OS must use organization-defined replay-resistant authentication mechanisms for network access to privileged accounts."
echo "V-48233 The firewall must be configured to only allow encrypted protocols to ensure that passwords are transmitted via encryption."
echo "V-48235 The firewall must be configured to deny network traffic by default and must allow network traffic by exception."
echo "V-48237 The OS must use organization-defined replay-resistant authentication mechanisms for network access to non-privileged accounts."
echo "V-48239 The OS must employ strong identification and authentication techniques in...non-local maintenance and diagnostic sessions."
echo "V-48241 The OS must employ cryptographic mechanisms to protect the integrity...of non-local maintenance and diagnostic..."
echo "(block in/out is set for datacenter, fragspass, etc. are not) -----"
svcs -H ipfilter
ipfstat -io
echo
echo "V-49621 The OS must configure auditing to reduce the likelihood of storage capacity being exceeded. (4M)"
auditconfig -getplugin | grep fsize
echo
echo "V-49625 The OS must employ PKI solutions at...servers...to create, manage, distribute, use, store, and revoke digital certs."
echo "(Not implemented on VMs) -----"
echo
echo "V-59829 All run control scripts must have no extended ACLs. (none)"
ls -lL /etc/init.d /etc/rc*.d | grep '+'
echo
echo "V-59833 Run control scripts library search paths must contain only authorized paths."
echo "(Appending or Prepending env vars typically ok, i.e.: \${PATH}, \${CMAMESH}, \${ORAHOME}, etc.)"
find /etc/rc* /etc/init.d -type f -print | xargs grep LD_LIBRARY_PATH
echo
echo "V-59835 Run control scripts lists of preloaded libraries must contain only authorized paths."
echo "(Appending or Prepending env vars typically ok, i.e.: \${PATH}, \${CMAMESH}, \${ORAHOME}, etc.)"
find /etc/rc* /etc/init.d -type f -print | xargs grep LD_PRELOAD
echo
echo "V-59837 Run control scripts must not execute world writable programs or scripts. (none)"
find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) \
-prune -o -type f -perm -002 -print | xargs -i grep \'{$1}\' /etc/init.d/* /etc/rc*.d/*
echo
echo "V-59843 System start-up files must only execute programs owned by a privileged UID or an app. (none or appuser owner)"
ls -lL /etc/init.d/* /etc/rc*.d/* | awk '($3!="root"){print$0}'
echo
echo "V-61003 Any X Windows host must write .Xauthority files."
echo "V-61023 The .Xauthority files must not have extended ACLs."
echo "V-61025 X displays must not be exported to the world."
echo "V-61027 .Xauthority or X*.hosts (or equivalent) file(s) must be used to restrict access to the X server."
echo "V-61029 The .Xauthority utility must only permit access to authorized hosts."
echo "(N/A X Windows is not used) -----"
echo
echo "V-61031 X Window System connections that are not required must be disabled. (none)"
ps -ef |grep X | grep -v grep
echo
echo "V-71495 Access to a domain console via telnet must be restricted to the local host."
echo "V-71497 Access to a logical domain console must be restricted to authorized users."
echo "(N/A if false) -----"
virtinfo get all | grep control-role
echo "----- (N/A if disabled)"
echo
echo "V-72827 Wireless network adapters must be disabled. (N/A)"
echo
