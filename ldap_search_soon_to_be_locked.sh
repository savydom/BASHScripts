/usr/bin/ldapsearch -D "cn=Manager,dc=sscnola,dc=oob"  -b "ou=people,dc=sscnola,dc=oob" -h sscmgt2.sscnola.oob -p 636 -P /var/ldap/cert8.db  -s sub "(pwdChangedTime=*)"

/usr/bin/ldapsearch -LLL -h sscmgt2.sscnola.oob -p 636 -P /var/ldap/cert8.db -X -s base -b "ou=people,dc=sscnola,dc=oob" -h sscmgt2.sscnola.oob -p 636 -P /var/ldap/cert8.db  -s sub "(pwdChangedTime=*)"






