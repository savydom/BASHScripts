#!/usr/bin/bash
CL=/export/home/webadm/calist.txt
SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
for i in `/usr/bin/cat $CL`
    do
        OUTF=$(echo "$i" | sed -e 's/CN=//' -e 's/ /_/g')
        sed -n '/'"$i"'/,/-----END CERTIFICATE-----/ s/.*/&/p' trustedcas.crt > "$OUTF".txt
    done
IFS=$SAVEIFS
