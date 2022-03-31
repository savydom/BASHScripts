cd /export/home/mpteci
find . ! \( -mtime -90 \) -print | grep -v '^\.\/\.' | xargs -i -t rm {$1}
