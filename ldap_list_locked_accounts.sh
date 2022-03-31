#!/bin/bash

#ldapsearch -h mgt1 -D cn=admin,cn=Administrators,cn=dscc -w - -b "ou=people,dc=DC,dc=dcc" -s sub "(pwdAccountLockedTime=*)" 1.1

if [ `hostname` != "sscmgt1" ] && [ `hostname` != "sscmgt2" ]
then
	echo "Must run from mgt1 or mgt2"
	exit
fi

#/usr/bin/ldapsearch -x -b "ou=people,dc=DC,dc=DCC" \
#                -H ldaps://mgt2.DC.DCC  \
#                  -s sub "(pwdAccountLockedTime=*)" 1.1 |grep dn

/usr/bin/ldapsearch -LLL -Y external -H ldapi:///  \
                  -s sub "(pwdAccountLockedTime=*)" 1.1 |grep dn


