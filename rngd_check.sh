#!/bin/ksh
. $HOME/.bash_profile >/dev/null 2>&1

typeset var ps_count=1

ps_count=`ps -ef | grep rngd | grep -v grep | wc -l`

touch /tmp/rngd_test.txt

if [ $ps_count -lt 2 ]; then
 /etc/rc.local
fi

