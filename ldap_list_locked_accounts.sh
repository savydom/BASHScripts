#!/bin/bash

#ldapsearch -h sscmgt1 -D cn=admin,cn=Administrators,cn=dscc -w - -b "ou=people,dc=sscnola,dc=oob" -s sub "(pwdAccountLockedTime=*)" 1.1

if [ `hostname` != "sscmgt1" ] && [ `hostname` != "sscmgt2" ]
then
	echo "Must run from sscmgt1 or sscmgt2"
	exit
fi

#/usr/bin/ldapsearch -x -b "ou=people,dc=sscnola,dc=oob" \
#                -H ldaps://sscmgt2.sscnola.oob  \
#                  -s sub "(pwdAccountLockedTime=*)" 1.1 |grep dn

/usr/bin/ldapsearch -LLL -Y external -H ldapi:///  \
                  -s sub "(pwdAccountLockedTime=*)" 1.1 |grep dn


