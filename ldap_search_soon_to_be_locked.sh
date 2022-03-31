/usr/bin/ldapsearch -D "cn=Manager,dc=DC,dc=DCC"  -b "ou=people,dc=DC,dc=DCC" -h mgt2.DC.DCC -p 636 -P /var/ldap/cert8.db  -s sub "(pwdChangedTime=*)"

/usr/bin/ldapsearch -LLL -h mgt2.DC.DCC -p 636 -P /var/ldap/cert8.db -X -s base -b "ou=people,dc=DC,dc=DCC" -h mgt2.DC.DCC -p 636 -P /var/ldap/cert8.db  -s sub "(pwdChangedTime=*)"






