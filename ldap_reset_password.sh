#!/bin/bash

if [ $# -gt 0 ]
then
	if [ `hostname` != "sscmgt1" ] && [ `hostname` != "sscmgt2" ]
	then
        	echo "Must run from sscmgt1 or sscmgt2"
        	exit
	fi

else
	echo "Error, Usage: ./ldap_reset_password.sh user"
	echo "Please try again and specify a user."
	exit
fi

/usr/lib/openldap/bin/ldappasswd -H ldapi:/// -W  -D cn=Manager,dc=sscnola,dc=oob \
	-S uid=$1,ou=people,dc=sscnola,dc=oob;
