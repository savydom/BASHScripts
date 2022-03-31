interface=$(route | grep '^default' | grep -o '[^ ]*$')
grep DNS /etc/sysconfig/network-scripts/ifcfg-$interface | grep '.39\|.62' | wc -l
