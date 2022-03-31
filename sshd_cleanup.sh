cp /etc/ssh/sshd_config /etc/ssh/sshd_config.$(date +%Y%m%d)
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sleep 5
for i in `grep '^AllowUsers' /etc/ssh/sshd_config`
do
cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config.mdj
echo $i | nawk '{q=$0;("getent passwd "q | getline r);if(r==""&&q!="AllowUsers")print q}' | xargs -i -t sh -c "sed -e 's/ {$1}//' </etc/ssh/sshd_config.mdj >/etc/ssh/sshd_config.bak"
sleep 1
done
echo
tail -10l /etc/ssh/sshd_config
echo
echo "-- Check validity of file with 'vi' before copying. --"
echo
echo "cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config"
echo
echo "svcadm -v refresh ssh"
echo
echo "svcs ssh"
