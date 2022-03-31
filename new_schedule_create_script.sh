/usr/bin/cat <<EOF | nsradmin -s sscprodeng2 -i - 
No resources found for query:

create type: NSR schedule;name: Skip Fri, Sat, Sun;
No resources found for query:

create type: NSR schedule;name: mon, wed, fri, SATURDAY FULL;
No resources found for query:

create type: NSR schedule;name: tues, thur, sun, FRIDAY FULL;
EOF
