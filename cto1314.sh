echo group ========= grep sysadmin /etc/group
grep sysadmin /etc/group
echo passwd ======== grep 14 /etc/passwd
grep 14 /etc/passwd
echo shadow ======== grep -i '\$' /etc/shadow
grep -i '\$' /etc/shadow
echo sudoers ======= grep -i adm /etc/sudoers
echo sudoers ======= grep -i oper /etc/sudoers
echo sudoers ======= grep -i '\%' /etc/sudoers
grep -i adm /etc/sudoers
grep -i oper /etc/sudoers
grep -i '\%' /etc/sudoers
echo policy.conf === grep -i allow /etc/security/policy.conf
grep -i allow /etc/security/policy.conf
