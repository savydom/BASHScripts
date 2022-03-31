export PATH=/usr/sbin:/usr/bin
echo "Building list, please standby..."
ii=1;jj=1
for i in `pkg list -uH | sort`
do
 if [ "$i" = "(splunk)" ]; then
  continue
 else
  j[$jj]="${j[jj]} $i"
  if (( $ii % 25 == 0 ))
  then
   echo -n "="
  fi
  if (( $ii % 3 == 0 )); then
   j[$jj]="${j[jj]:1}"
   j1[$jj]="$(cut -d' ' -f1 <<<"${j[jj]}")"
   (( jj++ ))
  fi
  (( ii++ ))
 fi
done
if (( $jj != 1 )); then
 echo
 echo $jj "Update Patches Available"
 kk=1;ll=1
 for k in `pkg list -nH | sort`
 do
  if [ "$k" = "(splunk)" ]; then
   continue
  else
   l[$ll]="${l[ll]} $k"
   if (( $kk % 500 == 0 )); then
    echo -n "="
   fi
   if (( $kk % 3 == 0 ))
   then
    l[$ll]="${l[ll]:1}"
    l1[$ll]="$(cut -d' ' -f1 <<<"${l[ll]}")"
    (( ll++ ))
   fi
   (( kk++ ))
  fi
 done
 echo
 echo $ll "Patches in Repository"
 printf "%50s %30s %30s\n" "Package" "Current Version" "Available Version"
 p=1;q=1
 for (( n=$q; n <= $jj; n++ ))
 do
  for (( m=$p; m <= $ll; m++ ))
   do
    if [ "$(cut -d' ' -f1 <<<"${l[m]}")" = "$(cut -d' ' -f1 <<<"${j[n]}")" ]; then
     printf "%50s %30s %30s\n" "$(cut -d' ' -f1 <<<"${l[m]}")" "$(cut -d' ' -f2 <<<"${j[n]}")" "$(cut -d' ' -f2 <<<"${l[m]}")"
     p=$m;q=$n
 break
    fi
   done
 done
else
 echo "No Update Patches Available"
fi
