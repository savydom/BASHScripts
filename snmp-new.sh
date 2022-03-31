OST=$(uname -s)
if [ $OST == "SunOS" ]; then
	OSR=$(uname -r)
	if [ $OSR == "5.10" ]; then

echo o10
svcadm -v disable ipfilter
svcadm -v disable sma
sleep 5
echo dlmod seaProxy /usr/sfw/lib/sparcv9/libseaProxy.so               >  /etc/sma/snmp/snmpd.conf
echo dlmod seaExtensions /usr/sfw/lib/sparcv9/libseaExtensions.so     >> /etc/sma/snmp/snmpd.conf
echo access monperfuser "" usm priv exact any any any                 >> /etc/sma/snmp/snmpd.conf
echo rouser monperfuser priv                                          >> /etc/sma/snmp/snmpd.conf
echo pass .1.3.6.1.4.1.2021.48879.1 /home/scriptid/sma/snmpget-cpu.sh >> /etc/sma/snmp/snmpd.conf
cat /etc/sma/snmp/snmpd.conf
echo
echo createuser monperfuser SHA "n0La$22551M02009!" DES               >  /var/sma_snmp/snmpd.conf
cat /var/sma_snmp/snmpd.conf
svcadm -v enable sma
svcadm -v enable ipfilter
sleep 5
cat /var/sma_snmp/snmpd.conf

	elif [ $OSR == "5.11" ]; then

echo o11
svcadm -v disable net-snmp
svcadm -v disable ipfilter
sleep 5
echo dlmod seaProxy /usr/sfw/lib/sparcv9/libseaProxy.so               >  /etc/net-snmp/snmp/snmpd.conf
echo dlmod seaExtensions /usr/sfw/lib/sparcv9/libseaExtensions.so     >> /etc/net-snmp/snmp/snmpd.conf
echo access monperfuser "" usm priv exact any any any                 >> /etc/net-snmp/snmp/snmpd.conf
echo rouser monperfuser priv                                          >> /etc/net-snmp/snmp/snmpd.conf
echo pass .1.3.6.1.4.1.2021.48879.1 /home/scriptid/sma/snmpget-cpu.sh >> /etc/net-snmp/snmp/snmpd.conf
cat /etc/net-snmp/snmp/snmpd.conf
echo
echo createuser monperfuser SHA "n0La$22551M02009!" DES               >  /var/net-snmp/snmpd.conf
cat /var/net-snmp/snmpd.conf
svcadm -v enable net-snmp
svcadm -v enable ipfilter
sleep 5
cat /var/net-snmp/snmpd.conf

	fi
elif [ $OST == "Linux" ]; then
	OSR1=$(uname -r | awk -F. '{print$4}')
	OSR2=$(uname -r | awk -F. '{print$6}')
	if [ $OSR1 == "el5" ]; then

echo el5
service snmpd stop
sleep 5
echo access monperfuser "" usm authPriv exact any any any                  >  /etc/snmp/snmpd.conf
echo rouser monperfuser priv                                               >> /etc/snmp/snmpd.conf
echo pass .1.3.6.1.4.1.2021.48879.1 /home/scriptid/scripts/snmpget-cpu.sh  >> /etc/snmp/snmpd.conf
cat /etc/snmp/snmpd.conf
echo
echo createuser monperfuser SHA n0La\$22551M02009\! AES                    >  /var/net-snmp/snmpd.conf
cat /var/net-snmp/snmpd.conf
service snmpd start
sleep 5
cat /var/net-snmp/snmpd.conf

	elif [ $OSR1 == "el7" ]; then

echo el7
service snmpd stop
sleep 5
echo access monperfuser "" usm authPriv exact any any any                  >  /etc/snmp/snmpd.conf
echo rouser monperfuser priv                                               >> /etc/snmp/snmpd.conf
echo pass .1.3.6.1.4.1.2021.48879.1 /home/scriptid/scripts/snmpget-cpu.sh  >> /etc/snmp/snmpd.conf
cat /etc/snmp/snmpd.conf
echo
echo createuser monperfuser SHA n0La\$22551M02009\! AES                    > /var/lib/net-snmp/snmpd.conf
cat /var/lib/net-snmp/snmpd.conf
service snmpd start
cat /var/lib/net-snmp/snmpd.conf
sleep 5

	elif [ $OSR2 == "el6" ]; then

echo el6
service snmpd stop
sleep 5
echo access monperfuser "" usm authPriv exact any any any                   >  /etc/snmp/snmpd.conf
echo rouser monperfuser priv                                                >> /etc/snmp/snmpd.conf
echo pass .1.3.6.1.4.1.2021.48879.1 /home/scriptid/scripts/snmpget-cpu.sh   >> /etc/snmp/snmpd.conf
cat /etc/snmp/snmpd.conf
echo
echo createuser monperfuser SHA n0La\$22551M02009\! AES                     > /var/lib/net-snmp/snmpd.conf
cat /var/lib/net-snmp/snmpd.conf
service snmpd start
sleep 5
cat /var/lib/net-snmp/snmpd.conf

	fi
fi
