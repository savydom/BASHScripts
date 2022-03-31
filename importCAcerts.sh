#!/usr/bin/bash

for i in `ls *.cer`
	do
	CERT=$i
	CERTNAME=`echo $i | sed -e 's/.cer//'`
	keytool -importcert -v -file $CERT -keystore cacerts -storepass changeit -alias $CERTNAME
	done
