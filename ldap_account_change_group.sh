#!/bin/bash


/usr/bin/ldapmodify -h sscmgt2.sscnola.oob -p 636 -P /var/ldap/cert8.db \
	-D cn=Manager,dc=sscnola,dc=oob -w - <<!
dn: gid=$1,ou=group,dc=sscnola,dc=oob
changetype: modify
add: memberuid
memberuid: $1
-
!
echo "tnguyen added to group: $1"



