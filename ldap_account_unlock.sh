#!/bin/bash

if [ `hostname` != "mgt1" ] && [ `hostname` != "mgt2" ]
then
        echo "Must run from mgt1 or mgt2"
        exit
fi


/usr/bin/ldapmodify -H ldapi:/// \
	-D cn=Manager,dc=DC,dc=DCC -W  <<!
dn: uid=$1,ou=people,dc=DC,dc=DCC
changetype: modify
delete: pwdAccountLockedTime
-
!
echo "Account: $1 unlocked"



