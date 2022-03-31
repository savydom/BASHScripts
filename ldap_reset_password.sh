#!/bin/bash

if [ $# -gt 0 ]
then
	if [ `hostname` != "mgt1" ] && [ `hostname` != "mgt2" ]
	then
        	echo "Must run from mgt1 or mgt2"
        	exit
	fi

else
	echo "Error, Usage: ./ldap_reset_password.sh user"
	echo "Please try again and specify a user."
	exit
fi

/usr/lib/openldap/bin/ldappasswd -H ldapi:/// -W  -D cn=Manager,dc=DC,dc=DCC \
	-S uid=$1,ou=people,dc=DC,dc=DCC;
