#!/bin/bash

if [ `hostname` != "sscmgt1" ] && [ `hostname` != "sscmgt2" ]
then
        echo "Must run from sscmgt1 or sscmgt2"
        exit
fi


/usr/bin/ldapmodify -H ldapi:/// \
	-D cn=Manager,dc=sscnola,dc=oob -W  <<!
dn: uid=$1,ou=people,dc=sscnola,dc=oob
changetype: modify
delete: pwdAccountLockedTime
-
!
echo "Account: $1 unlocked"



