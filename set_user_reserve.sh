#!/bin/bash
#
# Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.
#
# Script delivered with Oracle MOS Notes : 1663862.1
# Refer to the note for updates.
#
version="1.2"
#
# Print msg every 60 seconds while adjusting user reserve
#
print_intvl=60
#
# Abort after 1 hr if cannot converge
#
abort_intvl=3600
#
# Do upward adjustment in 5 points increments
#
incr=5
#
# Acceptable range
#
minval=0
maxval=99

function usage
{
        echo "$0: $*" >& 2

        echo "Usage: $(basename $0)" \
            "[-cfp] user_reserve_hint_pct\n"
	echo Dynamically adjust kernel value of user_reserve_hint_pct.
	echo value must be in [$minval,$maxval] range
	echo "\t-c  print current value for user_reserve_hint_pct" 
	echo "\t-f  allow upward adjustment of the value"
	echo "\t-p  print instructions for make value persistent on reboot "
	exit 0
}

function persist_msg
{
    mdb_getint  user_reserve_hint_pct
    date=`date`
    printf "Make the setting persistent across reboot by adding to /etc/system\n"
    printf "\n"
    printf "* Tuning based on MOS note 1663862.1, script version $version\n"
    printf "* added %s by system administrator : <me>\n" "$date"
    printf "set user_reserve_hint_pct=$user_reserve_hint_pct\n"
    printf "\n"
    exit 0
}

function on_error()
{
    printf "Interrupted or error; exiting\n"
    exit
}
trap on_error INT TERM

function mdb_getlong ()
{
    eval $1=$(echo $1/E | mdb -k | tail -1 | nawk '{print $2}' )
    eval x=\"\$$1\"
    if [[ $x == "" ]]; then
	echo failing to get $1
	on_error
    fi
}

function mdb_setlong ()
{
    echo $1/Z0t$2 | mdb -kw  2>/dev/null 1>&2
    mdb_getlong $1
    if [[ $1 -ne $2 ]]; then
	echo failing to set $1 to $2
	on_error
    fi
}

function mdb_getint ()
{
    eval $1=$(echo $1/D | mdb -k | tail -1 | nawk '{print $2}' )
    eval x=\"\$$1\"
    if [[ $x == "" ]]; then
	echo failing to get $1
	on_error
    fi
}

function mdb_setint ()
{
    echo $1/W0t$2 | mdb -kw  2>/dev/null 1>&2
    mdb_getint $1
    if [[ $1 -ne $2 ]]; then
	echo failing to set $1 to $2
	on_error
    fi
}

function set_current_pct()
{

    mdb_getlong physmem
    mdb_getlong kpages_locked
    mdb_getint  user_reserve_hint_pct
    current_pct=$(( ($physmem - $kpages_locked) * 100 / $physmem ))
}

function wait_for_adjustment ()
{
    set_current_pct
    i=0
    #
    # Wait while the adjustment in being handled in the kernel
    # Print a progress indicator every 5 seconds.
    # If not successful within 1 hr, then time to abort.
    #
    while [[ $current_pct -lt $user_reserve_hint_pct ]]; do
	if [[ $(( (i++)%print_intvl )) -eq 0 ]]; then
	    date=`date`
	    printf "%s : waiting for current value : %d to grow to target : %d\n" "$date" \
    $current_pct $user_reserve_hint_pct
	fi
	if [[ $(( i%abort_intvl )) -eq 0 ]]; then
	    printf "Seemingly unable to set reserve; reboot might be required \n"
	    exit
	fi
	sleep 1
	set_current_pct
    done
}
#
#
# BEGIN
#
#
OPTIND=1; while getopts ':cfp' c; do
        case "$c" in
	c|f|p) eval opt_$c=true ;;
	esac
done

let OPTIND="$OPTIND - 1"; shift $OPTIND
[[ $# -gt 1 && $opt_c != "true" ]] && usage "illegal argument -- $2"

[[ $# -eq 0 && $opt_p != "true" && $opt_c != "true" ]] && usage ""

[[ $# -eq 0 && $opt_p == "true" ]] && persist_msg

[[ ! -z "`echo \"$1\"|sed 's/[0-9]*//'`" ]] && usage "argument must be numeric"

mdb_getint user_reserve_hint_pct
oldval=$user_reserve_hint_pct

printf "Current user_reserve_hint_pct value is %d.\n" $oldval
[[ $opt_c == "true" ]] && exit 0


#
# Range check
#
newval=$1

[[ $newval -lt $minval || $newval -gt $maxval ]] && usage "$newval out of range; allowed values in [$minval,$maxval]"

#
# Null adjustment check
#
if [[ $newval -eq $oldval ]]; then
    printf "user_reserve_hint_pct already set to %d.\n" $newval
    if [[ $opt_p == "true" ]]; then
    	persist_msg
    fi
    exit
fi

#
# Upward adjustment check
#
[[ $newval -gt $oldval && $opt_f != "true" ]]  && usage "$newval greater that $oldval; use -f to force upward adjustment"

#
#
#

printf "Adjusting user_reserve_hint_pct from %d to %d\n" $oldval $newval
if [[ $newval -lt $oldval ]]; then
    #
    # Downward adjustment
    #
    mdb_setint user_reserve_hint_pct $newval
else
    #
    # adjust value using 5 % points increment then wait for value to converge
    # before subsequent adjustments
    #
    for ((new = $oldval + $incr; new < $newval+$incr; new=new+$incr)) {
	(( new = $new > $newval ? $newval : $new ))
	mdb_setint user_reserve_hint_pct $new
	wait_for_adjustment
    }
fi
#
# Successs
#
printf "Adjustment of user_reserve_hint_pct to %d successful.\n" $newval
#
# Inform user about persisting the setting
#
if [[ $opt_p == "true" ]]; then
	persist_msg
fi
exit 0
