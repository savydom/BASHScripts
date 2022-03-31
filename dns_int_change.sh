interface=$(route | grep '^default' | grep -o '[^ ]*$')
sed -i 's/DNS1=.*/DNS1="10.1.3.39"/g' /etc/sysconfig/network-scripts/ifcfg-$interface
sed -i 's/DNS2=.*/DNS2="10.1.3.62"/g' /etc/sysconfig/network-scripts/ifcfg-$interface
service network restart
