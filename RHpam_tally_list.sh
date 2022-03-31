echo $HOSTNAME > /home/mjohnson/backups/$HOSTNAME-pamlist.txt
echo "Login          Failures Latest failure     From" >> /home/mjohnson/backups/$HOSTNAME-pamlist.txt
grep '^AllowUsers' /etc/ssh/sshd_config | sed 's/AllowUsers//' | egrep -v '(oracle|cognos)' | \
xargs -i sh -c 'for i in '\{$1\}'; do echo $i; done' | xargs -i pam_tally2 -u {$1} 2>&1 | \
grep -v 'Login' >> /home/mjohnson/backups/$HOSTNAME-pamlist.txt
