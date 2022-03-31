nmtui hostname
echo "Server hostname has been changed to $HOSTNAME"
ip addr show
read -p "Press enter to change ens32 settings"
vi /etc/sysconfig/network-scripts/ifcfg-ens32
read -p "Press enter to change HOST settings"
vi /etc/hosts
