#!/bin/bash


/usr/bin/ldapmodify -h %ldap_server% -p 636 -P /var/ldap/cert8.db \
	-D cn=Manager,dc=DC,dc=DCC -w - <<!
dn: gid=$1,ou=group,dc=DC,dc=DCC
changetype: modify
add: memberuid
memberuid: $1
-
!
echo "tommy added to group: $1"



