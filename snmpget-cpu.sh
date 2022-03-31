#!/bin/sh

CAT=`which cat`
CPUFILE=/tmp/cpu

OID=.1.3.6.1.4.1.2021.48879.1
TYPE=integer

SED=`which sed`

NUMCPUS=`$CAT $CPUFILE | $SED -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'`

if [ $1 = "-g" ]; then
	# get request
	echo $OID
	echo $TYPE
	echo $NUMCPUS
elif [ $1 = "-s" ]; then
	# set request
	echo not-writable
fi

# ignore -n (getnext) requests, per documentation	
