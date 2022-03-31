#!/bin/bash
#
# RHEL 6 Content based on the RHEL6 V1R24 STIG
#
# Set current Version/Release # for this STIG Checklist script
cklVersion="V1R24"

#Set unclean variable. If set to 1, special characters won't be converted to the XML equivalent
if [[ "$(echo $1 | grep [Uu][Nn][Cc][Ll][Ee][Aa][Nn])" ]] || [[ "$(echo $2 | grep [Uu][Nn][Cc][Ll][Ee][Aa][Nn])" ]]; then
	unclean=1
fi

# We want to redirect all output (stdout and stderr to /tmp/RHEL_Lockdown.log
# Setup file descriptor 3 to point to stdout, we can use this if we need to output to the console
tempOut="/tmp/Validation_RHEL6_${cklVersion}.log"
exec 3>&1
exec 1>$tempOut 2>&1

# Create the result file
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESULTS="$DIR/Validation_RHEL6_${cklVersion}_Results.$HOSTNAME.$(date +%F_%H.%M)_XCCDF.ckl"

############### Result Functions ###############

### Zero Test ###
#Accepted format: RuleID, Test
#If it should come back as zero and pass, use this function
#$1 Rule ID
#$2 Test Criteria
#$3 Passed variable (comment) variable
function zero() {
	echo "Check $1"
	comment=$3
        commentFail=$4
	result="$(eval $2)"
	if [[ -z "$result" ]]; then
		result "$1" "pass" "$2" "$result" "$comment"
	else
		result "$1" "fail" "$2" "$result" "$commentFail"
	fi
	unset result comment
}

### Non-Zero Test ###
#Accepted format: RuleID, Test
#If it should come back as non-zero and pass, use this function
#$1 Rule ID
#$2 Test Criteria
#$3 Passed variable (pvar) variable
function nonzero() {
	echo "Check $1"
	comment=$3
	commentFail=$4
	result="$(eval $2)"
	if [[ -n "$result" ]]; then
		result "$1" "pass" "$2" "$result" "$comment"
	else
		result "$1" "fail" "$2" "$result" "$commentFail"
	fi
	unset result comment
}

### Not Reviewed ###
#The NR status does not work with the DISA STIG viewer, only the Sotera CKL Viewer
#$1 Rule ID
#$2 Test Criteria
#$3 Passed variable (comment) variable
function nr() {
	echo "Check $1"
	comment=$3
	result="$(eval $2)"
	result "$1" "NR" "$2" "$result" "$comment"
	unset result comment 
}

### Pass ###
#$1 Rule ID
#$2 Test Criteria
#$3 Passed variable (comment) variable
function pass() {
	echo "Check $1"
	comment=$3
	result="$(eval $2)"
	result "$1" "pass" "$2" "$result" "$comment"
	unset result comment
}

### Fail ###
#$1 Rule ID
#$2 Test Criterir
#$3 Passed variable (comment) variable
function fail() {
	echo "Check $1"
	comment=$3
	result="$(eval $2)"
	result "$1" "fail" "$2" "$result" "$comment"
        unset result comment
}

### Not Applicable ###
#The NA status does not work with the DISA STIG viewer, only the Sotera CKL Viewer
#$1 Rule ID
#$2 Comment
#$3 Passed variable (comment) variable
function na() {
	echo "Check $1"
	comment=$3
	result="$(eval $2)"
	result "$1" "notapplicable" "$2" "$result" "$comment"
	unset result comment
}

### Result Function  ###
#This function handles outputing results in an CKL format
#Made to handle 5 parameters
#$1 Rule ID
#$2 pass or fail
#$3 Test Criteria
#$4 Test Result
#$5 Comment
function result(){
	#If a 'clean' flag is given, results will clean XML special characters and make them XML appropriate
	if [[ $unclean -eq 1 ]]; then
		cleanxmla="$3"
		cleanxmlb="$4"
	else
		cleanxmla="$(echo $3 | sed -r 's/\&/\&amp;/g' | sed -r 's/</\&lt;/g' | sed -r 's/>/\&gt;/g' | sed -r "s/'/\&apos;/g" | sed -r 's/\"/\&quot;/g')"
		cleanxmlb="$(echo $4 | sed -r 's/</\&lt;/g' | sed -r 's/>/\&gt;/g')"
	fi
	
	if [[ "$2" == "pass" ]]; then
		status="NotAFinding"
	elif [[ "$2" == "fail" ]]; then
		status="Open"
	elif [[ "$2" == "NR" ]]; then
		status="Not_Reviewed"
	elif [[ "$2" == "notapplicable" ]]; then
		status="Not_Applicable"
	else
		status="ERROR"
		echo "<!-- result: $2, passed $2!=1 test, something WRONG-->" >> $Results			
	fi
	
	echo "<VULN>" >> $RESULTS
	echo "	<STIG_DATA>" >> $RESULTS
	echo "		<VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>" >> $RESULTS
	echo "		<ATTRIBUTE_DATA>$1</ATTRIBUTE_DATA>" >> $RESULTS
	echo "	</STIG_DATA>" >> $RESULTS
	echo "	<STATUS>$status</STATUS>" >> $RESULTS
	echo "	<FINDING_DETAILS># $cleanxmla" >> $RESULTS
	echo "$(eval $3 | sed -r 's/</\&lt;/g' | sed -r 's/>/\&gt;/g')</FINDING_DETAILS>" >> $RESULTS
	echo "	<COMMENTS>$(echo $5 | sed -r 's/</\&lt;/g' | sed -r 's/>/\&gt;/g')</COMMENTS>" >> $RESULTS
	echo "</VULN>" >> $RESULTS
	echo "" >> $RESULTS
	
}

### resetRule Function  ###
#This function updates variable value for the current rule being checked
#Made to handle 1 parameter in the following order: Rule ID
#$1 Rule ID
resetRule() {
	unset rule
	rule="$1"
	echo "$rule" >> /dev/tty
}

rule=""

############### End Result Functions ###############

### get information about the RHEL version/configuration ###
SRHELver=$(cat /etc/srhel-release)
IPaddr=$(ip -o -4  address show  | awk ' NR==2 { gsub(/\/.*/, "", $4); print $4 } ')
macAddr=$(ifconfig -a | grep -A 1 "$IPaddr" | grep -i 'ether*' | cut -d " " -f10)
RHELverNumb=$(grep -Eo '[0-9].[0-9]' /etc/redhat-release)

############### .ckl Header ###############
# This Creates the necessary header for the output file to be .ckl compliant
echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" > $RESULTS
echo "<!--DISA STIG Viewer :: 2.7.1-->" >> $RESULTS
echo "<CHECKLIST>" >> $RESULTS
echo "	<ASSET>" >> $RESULTS
echo "		<ROLE>Member Server</ROLE>" >> $RESULTS
echo "		<ASSET_TYPE>Computing</ASSET_TYPE>" >> $RESULTS
echo "		<HOST_NAME>$HOSTNAME</HOST_NAME>" >> $RESULTS
echo "		<HOST_IP>$IPaddr</HOST_IP>" >> $RESULTS
echo "		<HOST_MAC>$macAddr</HOST_MAC>" >> $RESULTS
echo "		<HOST_FQDN>$SRHELver</HOST_FQDN>" >> $RESULTS
echo "		<TECH_AREA>UNIX OS</TECH_AREA>" >> $RESULTS
echo "		<TARGET_KEY>2777</TARGET_KEY>" >> $RESULTS
echo "		<WEB_OR_DATABASE>false</WEB_OR_DATABASE>" >> $RESULTS
echo "		<WEB_DB_SITE></WEB_DB_SITE>" >> $RESULTS
echo "		<WEB_DB_INSTANCE></WEB_DB_INSTANCE>" >> $RESULTS
echo "	</ASSET>" >> $RESULTS
echo "	<STIGS>" >> $RESULTS
echo "		<iSTIG>" >> $RESULTS
echo "			<STIG_INFO>" >> $RESULTS
echo "				<SI_DATA>" >> $RESULTS
echo "					<SID_NAME>classification</SID_NAME>" >> $RESULTS
echo "					<SID_DATA>UNCLASSIFIED</SID_DATA>" >> $RESULTS
echo "				</SI_DATA>" >> $RESULTS
echo "				<SI_DATA>" >> $RESULTS
echo "					<SID_NAME>title</SID_NAME>" >> $RESULTS
echo "					<SID_DATA>Red Hat Enterprise Linux 6 Security Technical Implementation Guide</SID_DATA>" >> $RESULTS
echo "				</SI_DATA>" >> $RESULTS
echo "			</STIG_INFO>" >> $RESULTS
echo "" >> $RESULTS
############### End CKL Header ###############

### Start Checks ###
echo "<!-- Starting checks... $(date) -->" >> $RESULTS
echo "" >> $RESULTS

echo "" >> /dev/tty
echo "Starting checks... $(date)" >> /dev/tty
echo "" >> /dev/tty

#example check
#[function] [Rule ID] [Test command] [Variable pvar]
#zero "SV-38177r2_rule" "cat $pvar | awk -F: '{ print $1 }' | grep -i ^games" "/etc/passwd"
#nonzero "SV-38177r2_rule" "cat /etc/passwd | awk -f: '{ print $1 }' | grep -i ^games"
##

echo "The first two checks take a while to complete, be patient." >> /dev/tty

### V-38437 | SV-50237r1_rule ###
# May need to make this manual if the check check below fails, the local ISSO can document as permissable.
resetRule "SV-50237r1_rule"
if [[ -z "$(service autofs status | grep running)" ]]; then
        pass "$rule" "systemctl status autofs" "Verified the Red Hat Enterprise Linux operating system disables the file system automounter unless required, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        pass "$rule" "systemctl status autofs" "autofs status is set to active, however it is documented with the Information System Security Officer (ISSO) that this is an operational requirement, therefore the reference STIG is not a finding.  Engineer did NOT apply a change."
fi

### V-38438 | SV-50238r4_rule ###
resetRule "SV-50238r4_rule"
if [[ -f /boot/efi/EFI/redhat/grub.cfg ]]; then
        zero "$rule" "grep kernel /boot/efi/EFI/redhat/grub.conf | grep -v audit=1 | grep -v "^#"" "Verified auditing is enabled at boot by setting a kernel parameter, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified auditing is NOT enabled at boot by setting a kernel parameter, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	zero "$rule" "grep kernel /boot/grub/grub.conf | grep -v audit=1 | grep -v \"^#\"" "Verified auditing is enabled at boot by setting a kernel parameter, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified auditing is NOT enabled at boot by setting a kernel parameter, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38443 | SV-50243r1_rule ###
resetRule "SV-50243r1_rule"
nonzero "$rule" "ls -l /etc/gshadow | awk -F\" \" '{print \$3}' | grep root" "Verified the /etc/gshadow file IS owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/gshadow file is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38444 | SV-50244r2_rule ###
resetRule "SV-50244r2_rule"
nonzero "$rule" "grep \":INPUT\" /etc/sysconfig/ip6tables | grep DROP" "Verified the systems local IPv6 firewall implements a deny-all, allow-by-exception policy for inbound packets, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the systems local IPv6 firewall does NOT implement a deny-all, allow-by-exception policy for inbound packets, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary"

### V-38445 | SV-50245r2_rule ###
resetRule "SV-50245r2_rule"
nonzero "$rule" 'grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G:%n | grep root' "Verified audit log files IS group-owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified audit log files is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38446 ###
resetRule "SV-50246r2_rule"
nonzero "$rule" "postmap -q root hash:/etc/aliases | grep -v \"^#\"" "Verified the mail system forwards all mail for root to one or more system administrators, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the mail system does NOT forward all mail for root to one or more system administrators, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71855 ###
resetRule "SV-50247r4_rule"
nr "$rule" "rpm -Va | awk '\$1 ~ /..5/ && \$2 != \"c\"'" "Check only. Verify the findings from this output contain no system files or binaries. Standard Verbiage: Verified the cryptographic hash of system files and commands match vendor values, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-38448 ###
resetRule "SV-50248r1_rule"
nonzero "$rule" "ls -l /etc/gshadow | awk -F\" \" '{print \$4}' | grep root" "Verified the /etc/gshadow file IS group-owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/gshadow file is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38449 ###
resetRule "SV-50249r1_rule"
nonzero "$rule" "stat -c '%a' /etc/gshadow | grep \"^0\s*\"" "Verified the /etc/gshadow file have mode 0000, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/gshadow file does NOT have mode 0000, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38450 ###
resetRule "SV-50250r1_rule"
nonzero "$rule" "ls -l /etc/passwd | awk -F\" \" '{print \$3}' | grep root" "Verified the /etc/passwd file IS owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/passwd file is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38451 ###
resetRule "SV-50251r1_rule"
nonzero "$rule" "ls -l /etc/passwd | awk -F\" \" '{print \$4}' | grep root" "Verified the /etc/passwd file IS group-owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/passwd file is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38452 ###
resetRule "SV-50252r2_rule"
nr "$rule" "rpm -Va | grep '^.M'" "Check only. Verify the findings from this output contain no system files or binaries. Standard Verbiage: Verified the permissions on system binaries and configuration files that are NOT too generous allowing an unauthorized user to gain privileges that they should not have, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-38453 ###
resetRule "SV-50253r2_rule"
nr "$rule" "rpm -Va | grep '^......G'" "Check only. Verify the findings from this output contain no system files or binaries. Standard Verbiage: Verified the permissions on system binaries and configuration files that are NOT too generous allowing an unauthorized user to gain privileges that they should not have, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-38454 ###
resetRule "SV-50254r2_rule"
nr "$rule" "rpm -Va | grep '^.....U'" "Check only. Verify the findings from this output contain no system files or binaries. Standard Verbiage: Verified the permissions on system binaries and configuration files that are NOT too generous allowing an unauthorized user to gain privileges that they should not have, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-38455 ###
resetRule "SV-50255r1_rule"
nonzero "$rule" "mount | grep \"on /tmp \"" "Verified the system uses a separate file system for /tmp, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a separate file system for /tmp, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38456 ###
resetRule "SV-50256r1_rule"
nonzero "$rule" "mount | grep \"on /var \"" "Verified the system uses a separate file system for /var, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a separate file system for /var, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38457 ###
resetRule "SV-50257r1_rule"
nonzero "$rule" "stat -c '%a' /etc/passwd | grep \"^644\s*\"" "Verified the /etc/passwd file does have mode 0644 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/passwd file does NOT have mode 0644 or less permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38458 ###
resetRule "SV-50258r1_rule"
nonzero "$rule" "ls -l /etc/group | awk -F\" \" '{print \$3}' | grep root" "Verified the /etc/group file IS owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/group file is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38459 ###
resetRule "SV-50259r1_rule"
nonzero "$rule" "ls -l /etc/group | awk -F\" \" '{print \$4}' | grep root" "Verified the /etc/group file IS group-owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/group file is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38460 ###
resetRule "SV-50260r1_rule"
if [[ -n $(service nfs status | grep nfsd | grep stopped) ]]; then
	pass "$rule" "service nfs status | grep nfsd | grep stopped" "Verified the server is not hosting any NFS shares, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	zero "$rule" "grep all_squash /etc/exports" "Verified the NFS server does NOT have the all_squash option enabled, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the NFS server does have the all_squash option enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38461 ###
resetRule "SV-50261r1_rule"
nonzero "$rule" "stat -c '%a' /etc/group | grep \"^644\s*\"" "Verified the /etc/group file does have mode 0644 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/group file does NOT have mode 0644 or less permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38463 ###
resetRule "SV-50263r1_rule"
nonzero "$rule" "mount | grep \"on /var/log \"" "Verified the system uses a separate file system for /var/log, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a separate file system for /var/log, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38464 ###
resetRule "SV-50264r1_rule"
nonzero "$rule" "grep disk_error_action /etc/audit/auditd.conf | grep -i 'ignore\|syslog\|exec\|suspend\|single\|halt'" "Verified the audit system takes appropriate action when there are disk errors on the audit storage volume, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT take appropriate action when there are disk errors on the audit storage volume, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38465 ###
resetRule "SV-50265r3_rule"
paths=(/lib /lib64 /usr/lib /usr/lib64)
testFail=false
failstring=""
for i in ${paths[@]}; do
	if [[ $(find -L $i -perm /022 -type f) ]]; then
		testFail=true
		failstring+=" $i "
	else
		$nothing
	fi
done

if [[ $testFail = true ]]; then
	fail "$rule" "echo $failstring" "Verified all system-wide shared library files, which are linked to executables during process load time or run time ARE group-writable or world-writable, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	pass "$rule" "find -L [DIR] -perm /022 -type f" "Verified all system-wide shared library files, which are linked to executables during process load time or run time are NOT group-writable or world-writable, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."	
fi
unset testFail
unset failstring
unset paths

### V-38466 ###
resetRule "SV-50266r4_rule"
zero "$rule" "$(for i in /lib /lib64 /usr/lib /usr/lib64 ;  do  for j in `find -L $i \! -user root` ;  do  rpm -V -f $j | grep '^.....U' ;  done ;  done)" "Verified all shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime have proper ownership, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Some shared library directories were found loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime have proper ownership, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38467 ###
resetRule "SV-50267r1_rule"
nonzero "$rule" "mount | grep \"on /var/log/audit \"" "Verified the system uses a separate file system for /var/log/audit, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a separate file system for /var/log/audit, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38468 ###
resetRule "SV-50268r1_rule"
nonzero "$rule" "grep disk_full_action /etc/audit/auditd.conf | grep -i 'ignore\|syslog\|exec\|suspend\|single\|halt'" "Verified the audit system takes appropriate action when the audit storage volume is full, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT take appropriate action when the audit storage volume is full, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38469 ###
resetRule "SV-50269r3_rule"
paths=(/bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin)
testFail=false
failstring=""
for i in ${paths[@]}; do
        if [[ $(find -L $i -perm /022 -type f) ]]; then
                testFail=true
                failstring+=" $i "
        else
                $nothing
        fi
done

if [[ $testFail = true ]]; then
        fail "$rule" "echo $failstring" "Verified some files in these directories ARE group-writable or world-writable, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        pass "$rule" "find -L [DIR] -perm /022 -type f" "Verified all files in these directories are NOT group-writable or world-writable, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi
unset testFail
unset failstring
unset paths

### V-38470 ###
resetRule "SV-50270r2_rule"
nonzero "$rule" "grep space_left_action /etc/audit/auditd.conf | grep -i 'ignore\|syslog\|exec\|suspend\|single\|halt'" "Verified the audit system alerts designated staff members when the audit storage volume approaches capacity, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT alert designated staff members when the audit storage volume approaches capacity, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38471 ###
resetRule "SV-50271r1_rule"
nonzero "$rule" "grep active /etc/audisp/plugins.d/syslog.conf | grep yes" "Verified the system DOES forward audit records to the syslog service, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT forward audit records to the syslog service, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38472 ###
resetRule "SV-50272r1_rule"
paths=(/bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin)
testFail=false
failstring=""
for i in ${paths[@]}; do
        if [[ $(find -L $i \! -user root) ]]; then
                testFail=true
                failstring+=" $i "
        else
                $nothing
        fi
done

if [[ $testFail = true ]]; then
        fail "$rule" "echo $failstring" "Verified some files in these directories are NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        pass "$rule" "find -L [DIR] \! -user root" "Verified all files in these directories are owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi
unset testFail
unset failstring
unset paths

### V-38473 ###
resetRule "SV-50273r1_rule"
nonzero "$rule" "mount | grep \"on /home \"" "Verified the system uses a separate file system for /home, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a separate file system for /home, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38474 ###
resetRule "SV-50274r2_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
	na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nonzero "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver" "Verified the system allows locking of graphical desktop sessions, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system allows locking of graphical desktop sessions, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38475 ###
resetRule "SV-50275r3_rule"
nonzero "$rule" "grep PASS_MIN_LEN /etc/login.defs | grep -v "^\s*#" | awk -F ' ' '\$2 >=15'" "Verified the system requires passwords to contain a minimum of 15 characters, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain a minimum of 15 characters, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38476 ###
resetRule "SV-50276r3_rule"
zero "$rule" "rpm -q gpg-pubkey | grep \"not installed\"" "Verified the vendor-provided cryptographic certificates are installed to verify the integrity of system software, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the vendor-provided cryptographic certificates are NOT installed to verify the integrity of system software, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38477 ###
resetRule "SV-50277r1_rule"
nonzero "$rule" "grep PASS_MIN_DAYS /etc/login.defs | grep 1" "Verified users must not be able to change passwords more than once every 24 hours, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified users must not be able to change passwords more than once every 24 hours, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38478 ###
resetRule "SV-50278r2_rule"
nonzero "$rule" "chkconfig \"rhnsd\" --list | grep -v on" "Verified the Red Hat Network Service (rhnsd) service is NOT be running, unless using RHN or an RHN Satellite, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Network Service (rhnsd) service IS be running, unless using RHN or an RHN Satellite, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38479 ###
resetRule "SV-50279r1_rule"
nonzero "$rule" "grep PASS_MAX_DAYS /etc/login.defs | grep 60" "Verified the user passwords are changed at least every 60 days, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the user passwords are NOT changed at least every 60 days, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38480 ###
resetRule "SV-50280r1_rule"
nonzero "$rule" "grep PASS_WARN_AGE /etc/login.defs | grep 7" "Verified users are warned 7 days in advance of password expiration, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified users are NOT warned 7 days in advance of password expiration, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38481 ###
# Manual inspection - will need to lookup if returned results are at supported versions.
resetRule "SV-50281r1_rule"
nr "$rule" "echo '#Manual Inspection Required
'; yum history list;" "Verify the latest patches were applied within the last 4 weeks. Standard Verbiage: Verified vendor packaged system security patches and updates are installed and up to date, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-38482 ###
resetRule "SV-50282r2_rule"
nonzero "$rule" "grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth | egrep \"dcredit\s*=\s*-1\"" "Verified the system must require passwords to contain at least one numeric character, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain at least one numeric character, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38483 ###
resetRule "SV-50283r1_rule"
nonzero "$rule" "grep \"^gpgcheck\s*=\s*1\" /etc/yum.conf | grep -v '^#'" "Verified the operating system prevents the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38484 ###
resetRule "SV-50285r2_rule"
nonzero "$rule" "grep -i "^PrintLastLog" /etc/ssh/sshd_config | grep -i yes" "Verified the operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system, upon successful logon, does NOT display to the user the date and time of the last logon or access via ssh, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." 

### V-38486 ###
resetRule "SV-50287r1_rule"
nonzero "$rule" "/opt/splunkforwarder/bin/splunk btool deploymentclient list | grep targetUri | grep -v '^#'" "Verified the operating system off-loads audit records onto a different system or media from the system being audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT off-load audit records onto a different system or media from the system being audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38487 ###
resetRule "SV-50288r1_rule"
zero "$rule" "egrep \"gpgcheck\s*=\s*0\" /etc/yum.repos.d/*" "Verified the system package management tool must cryptographically verify the authenticity of all software packages during installation, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system package management tool must cryptographically verify the authenticity of all software packages during installation, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-38488 ###
resetRule "SV-50289r1_rule"
nonzero "$rule" "/opt/splunkforwarder/bin/splunk btool deploymentclient list | grep targetUri | grep -v '^#'" "Verified the operating system off-loads audit records onto a different system or media from the system being audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT off-load audit records onto a different system or media from the system being audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38489 ###
resetRule "SV-50290r1_rule"
nonzero "$rule" "rpm -q aide | grep aide-.*el6" "Verified a file integrity tool IS installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified a file integrity tool is NOT installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38490 ###
resetRule "SV-50291r6_rule"
nonzero "$rule" "grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true" | grep -v \"^\s*#\"" "Verified the operating system must enforce requirements for the connection of mobile devices to operating systems, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT enforce requirements for the connection of mobile devices to operating systems, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38491 ###
resetRule "SV-50292r1_rule"
if [[ -z $(find /home -name .rhosts) && ! -f /etc/hosts.equiv ]]; then
	pass "$rule" "find /home -name .rhosts; ls -l /etc/hosts.equiv" "Verified no .rhosts or hosts.equiv files on the system, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "find /home -name .rhosts; ls -l /etc/hosts.equiv" "Verified some .rhosts or hosts.equiv files were found on the system, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38492 ###
resetRule "SV-50293r1_rule"
zero "$rule" "grep '^vc/[0-9]' /etc/securetty" "Verified the system must prevent the root account from logging in from virtual consoles, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT prevent the root account from logging in from virtual consoles, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38493 ###
resetRule "SV-50294r1_rule"
declare -A perm
testFail=false
output=$(grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n | awk -F":" '{print $1}')
while read -n1 octet; do
    perm+=$octet
    #count=$(($count+1))
done < <(echo -n "$output")
if [[ $(echo $perm[0] -le "7") && $(echo $perm[1] -le "5") && $(echo $perm[2] -le "5") ]]; then
	$nothing
else
	testFail=true
fi

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "grep \"^log_file\" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*\$//'|xargs stat -c %a:%n" "Verified audit log directories do NOT have mode 0755 or less permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  pass "$rule" "grep \"^log_file\" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*\$//'|xargs stat -c %a:%n" "Verified audit log directories have mode 0755 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail
unset output
unset perm
unset octet

### V-38494 ###
resetRule "SV-50295r1_rule"
zero "$rule" "grep '^ttyS[0-9]' /etc/securetty" "Verified the system prevents the root account from logging in from serial consoles, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT prevent the root account from logging in from serial consoles, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38495 ###
resetRule "SV-50296r1_rule"
nonzero "$rule" "grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U:%n | grep root" "Verified audit log files are owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified audit log files are NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38496 ###
resetRule "SV-50297r3_rule"
testFail=false
account=$(awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 ":" $2}' /etc/shadow | awk -F":" '{print $1}')
for i in $account; do
	if [[ $(id -u $i) -ge 500 ]]; then
		$nothing
	else
		testFail=true
	fi
done

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "awk -F: '\$1 !~ /^root$/ && \$2 !~ /^[!*]/ {print \$1 ":" \$2}' /etc/shadow" "Verified some default operating system accounts, other than root, are NOT locked, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  pass "$rule" "awk -F: '\$1 !~ /^root$/ && \$2 !~ /^[!*]/ {print \$1 ":" \$2}' /etc/shadow" "Verified all default operating system accounts, other than root, are locked, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail
unset account

### V-38497 ###
resetRule "SV-50298r3_rule"
zero "$rule" "grep nullok /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system does NOT have accounts configured with blank or null passwords, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES have accounts configured with blank or null passwords, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38498 ###
resetRule "SV-50299r1_rule"
declare -A perm
testFail=false
output=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n | awk -F":" '{print $1}')
while read -n1 octet; do
    perm+=$octet
    #count=$(($count+1))
done < <(echo -n "$output")
if [[ $(echo $perm[0] -le "6") && $(echo $perm[1] -le "4") && $(echo $perm[2] -eq "0") ]]; then
        $nothing
else
        testFail=true
fi

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n" "Verified audit log files do NOT have mode 0640 or less permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  pass "$rule" "grep \"^log_file\" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n" "Verified audit log files have mode 0640 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail
unset output
unset perm
unset octet

### V-38499 ###
resetRule "SV-50300r1_rule"
zero "$rule" "awk -F: '($2 != "x") {print}' /etc/passwd" "Verified the /etc/passwd file does NOT contain password hashes,  therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/passwd file DOES contain password hashes, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38500 ###
resetRule "SV-50301r2_rule"
if [[ $(awk -F: '($3 == 0) {print}' /etc/passwd | wc -l) -eq 1 ]]; then
	nonzero "$rule" "awk -F: '(\$3 == 0) {print}' /etc/passwd | grep root" "Verified the root account is the only account having a UID of 0, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the root account is NOT the only account having a UID of 0, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	fail "$rule" "awk -F: '($3 == 0) {print}' /etc/passwd" "Verified the root account is NOT the only account having a UID of 0, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38501 ###
resetRule "SV-50302r4_rule"
testFail=false
if [[ $(grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth | grep -v account | wc -l) -eq $(grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth | grep -v account | grep fail_interval | wc -l) ]]; then
	interval=$(grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth | grep -v account)
	for i in $interval; do
		if [[ $(echo $i | sed 's/.*\(fail_interval=[0-9]\+\).*/\1/') -ge 900 ]]; then
			$nothing
		else
			testFail=true
		fi
	done
else
	fail "$rule" "grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system does NOT disable accounts after excessive login failures within a 15-minute interval, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system does NOT disable accounts after excessive login failures within a 15-minute interval, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  pass "$rule" "grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system disables accounts after excessive login failures within a 15-minute interval, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail

### V-38502 ###
resetRule "SV-50303r1_rule"
nonzero "$rule" "ls -l /etc/shadow | awk -F\" \" '{print \$3}' | grep root" "Verified the /etc/shadow file IS owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/shadow file is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38503 ###
resetRule "SV-50304r1_rule"
nonzero "$rule" "ls -l /etc/shadow | awk -F\" \" '{print \$4}' | grep root" "Verified the /etc/shadow file IS group-owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/shadow file is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38504 ###
resetRule "SV-50305r1_rule"
nonzero "$rule" "stat -c '%a' /etc/shadow | grep \"^0\s*\"" "Verified the /etc/shadow file have mode 0000, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/shadow file does NOT have mode 0000, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38511 ###
resetRule "SV-50312r3_rule"
nonzero "$rule" "sysctl net.ipv4.ip_forward | grep 0" "Verified IP forwarding for IPv4 is NOT enabled, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified IP forwarding for IPv4 IS enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38512 ###
resetRule "SV-50313r2_rule"
nonzero "$rule" "service iptables status | grep -v \"not running\"" "Verified the operating system prevents public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38513 ###
resetRule "SV-50314r2_rule"
nonzero "$rule" "iptables -nvL | grep -i input | grep \"policy DROP\"" "Verified the systems local IPv4 firewall implements a deny-all, allow-by-exception policy for inbound packets, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the systems local IPv4 firewall does NOT implement a deny-all, allow-by-exception policy for inbound packets, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38514 ###
resetRule "SV-50315r5_rule"
nonzero "$rule" "grep -r dccp /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\" | grep -v \"#\"" "Verified the Datagram Congestion Control Protocol (DCCP) must be disabled unless required, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Datagram Congestion Control Protocol (DCCP) is NOT disabled unless required, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38515 ###
resetRule "SV-50316r5_rule"
nonzero "$rule" "grep -r sctp /etc/modprobe.conf /etc/modprobe.d | grep -i \"/bin/true\" | grep -v \"#\"" "Verified the Stream Control Transmission Protocol (SCTP) must be disabled unless required, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Stream Control Transmission Protocol (SCTP) is NOT disabled unless required, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38516 ###
resetRule "SV-50317r3_rule"
nonzero "$rule" "grep -r rds /etc/modprobe.conf /etc/modprobe.d | grep 'true\|false'" "Verified the Reliable Datagram Sockets (RDS) protocol IS disabled unless required, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Reliable Datagram Sockets (RDS) protocol is NOT disabled unless required, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38517 ###
resetRule "SV-50318r5_rule"
nonzero "$rule" "grep -r tipc /etc/modprobe.conf /etc/modprobe.d | grep 'true\|false'" "Verified the Transparent Inter-Process Communication (TIPC) protocol IS disabled unless required, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Transparent Inter-Process Communication (TIPC) protocol is NOT disabled unless required, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38518 ###
resetRule "SV-50319r2_rule"
testFail=false
paths=$(cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F" " '{print $2}' | grep -v ":" | sed 's/-//g')
for i in $paths; do
	if [[ -n $(ls -l $i | awk -F" " '{print $3}' | grep root) ]]; then
		$nothing
	else
		testFail=true
	fi
done

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F\" \" '{print \$2}' | grep -v \":\" | sed 's/-//g'" "Verified some rsyslog-generated log files are NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  pass "$rule" "cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F\" \" '{print \$2}' | grep -v \":\" | sed 's/-//g'" "Verified all rsyslog-generated log files are owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail
unset paths

### V-38519 ###
resetRule "SV-50320r2_rule"
testFail=false
paths=$(cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F" " '{print $2}' | grep -v ":" | sed 's/-//g')
for i in $paths; do
        if [[ -n $(ls -l $i | awk -F" " '{print $4}' | grep root) ]]; then
                $nothing
        else
                testFail=true
        fi
done

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F\" \" '{print \$2}' | grep -v \":\" | sed 's/-//g'" "Verified some rsyslog-generated log files are NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  pass "$rule" "cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F\" \" '{print \$2}' | grep -v \":\" | sed 's/-//g'" "Verified all rsyslog-generated log files are group-owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail
unset paths

### V-38520 ###
resetRule "SV-50321r1_rule"
nonzero "$rule" "/opt/splunkforwarder/bin/splunk btool deploymentclient list | grep targetUri | grep -v '^#'" "Verified the operating system off-loads audit records onto a different system or media from the system being audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT off-load audit records onto a different system or media from the system being audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38521 ###
resetRule "SV-50322r1_rule"
nonzero "$rule" "/opt/splunkforwarder/bin/splunk btool deploymentclient list | grep targetUri | grep -v '^#'" "Verified the operating system off-loads audit records onto a different system or media from the system being audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT off-load audit records onto a different system or media from the system being audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38522 ###
resetRule "SV-50323r4_rule"
nonzero "$rule" "grep -w \"settimeofday\" /etc/audit/audit.rules | grep 'b32\|b64' | grep -v "^\s*#" | wc -l | grep 2" "Verified the audit system IS configured to audit all attempts to alter system time through settimeofday, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system is NOT configured to audit all attempts to alter system time through settimeofday, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38523 ###
resetRule "SV-50324r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.all.accept_source_route | grep 0" "Verified the system does not accept IPv4 source-routed packets on any interface, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES accept IPv4 source-routed packets on any interface, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38524 ###
resetRule "SV-50325r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.all.accept_redirects | grep 0" "Verified the system does NOT accept ICMPv4 redirect packets on any interface, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES accept ICMPv4 redirect packets on any interface, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38525 ###
resetRule "SV-50326r5_rule"
if [[ -n $(uname -m | grep x86_64) ]]; then
	na "$rule" "uname -m" "Verified the system is 64-bit only, therefore the reference STIG is not applicable"
else
	nonzero "$rule" "grep -w \"stime\" /etc/audit/audit.rules | grep 'b32\|b64' | grep -v "^\s*#" | wc -l | grep 2" "Verified the audit system IS configured to audit all attempts to alter system time through stime, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system is NOT configured to audit all attempts to alter system time through stime, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38526 ###
resetRule "SV-50327r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.all.secure_redirects | grep 0" "Verified the system does NOT accept ICMPv4 secure redirect packets on any interface, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES accept ICMPv4 secure redirect packets on any interface, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38527 ###
resetRule "SV-50328r4_rule"
nonzero "$rule" "grep -w \"clock_settime\" /etc/audit/audit.rules | grep 'b32\|b64' | grep -v "^\s*#" | wc -l | grep 2" "Verified the audit system IS configured to audit all attempts to alter system time through clock_settime, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system is NOT configured to audit all attempts to alter system time through clock_settime, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38528 ###
resetRule "SV-50329r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.all.log_martians | grep 1" "Verified the system logs Martian packets, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT log Martian packets, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38529 ###
resetRule "SV-50330r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.default.accept_source_route | grep 0" "Verified the system does NOT accept IPv4 source-routed packets by default, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES accept IPv4 source-routed packets by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38530 ###
resetRule "SV-50331r2_rule"
nonzero "$rule" "grep -w "/etc/localtime" /etc/audit/audit.rules | grep -v "^\s*#" | grep wa" "Verified the audit system IS configured to audit all attempts to alter system time through /etc/localtime, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system is NOT configured to audit all attempts to alter system time through /etc/localtime, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38531 ###
resetRule "SV-50332r2_rule"
zero "$rule" "egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules | grep -v \"\-p wa\"" "Verified the operating system must automatically audit account creation, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT automatically audit account creation, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38532 ###
resetRule "SV-50333r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.default.secure_redirects | grep 0" "Verified the system does NOT accept ICMPv4 secure redirect packets by default, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES accept ICMPv4 secure redirect packets by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38533 ###
resetRule "SV-50334r4_rule"
nonzero "$rule" "sysctl net.ipv4.conf.default.accept_redirects | grep 0" "Verified the system must ignore ICMPv4 redirect messages by default, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT ignore ICMPv4 redirect messages by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38534 ###
resetRule "SV-50335r2_rule"
zero "$rule" "egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules | grep -v \"\-p wa\"" "Verified the operating system must automatically audit account modification, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT automatically audit account modification, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38535 ###
resetRule "SV-50336r3_rule"
nonzero "$rule" "sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep 1" "Verified the system must not respond to ICMPv4 sent to a broadcast address, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system responds to ICMPv4 sent to a broadcast address, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38536 ###
resetRule "SV-50337r2_rule"
zero "$rule" "egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules | grep -v \"\-p wa\"" "Verified the operating system must automatically audit account disabling actions, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT automatically audit account disabling actions, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38537 ###
resetRule "SV-50338r3_rule"
nonzero "$rule" "sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep 1" "Verified the system ignores ICMPv4 bogus error responses, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT ignore ICMPv4 bogus error responses, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38538 ###
resetRule "SV-50339r2_rule"
zero "$rule" "egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules | grep -v \"\-p wa\"" "Verified the operating system must automatically audit account termination, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT automatically audit account termination, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38539 ###
resetRule "SV-50340r3_rule"
nonzero "$rule" "sysctl net.ipv4.tcp_syncookies | grep 1" "Verified the system IS configured to use TCP syncookies when experiencing a TCP SYN flood, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system is NOT configured to use TCP syncookies when experiencing a TCP SYN flood, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38540 ###
resetRule "SV-50341r5_rule"
if [[ $(ausyscall i386 sethostname | awk -F" " '{print $2}') -ne $(ausyscall x86_64 sethostname | awk -F" " '{print $2}') ]]; then
	if [[ -n $(egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules | grep 'b64\|b32' | wc -l | grep 2) && -n $(egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules | grep "\-p wa") ]]; then
		pass "$rule" "egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules" "Verified the audit system is configured to audit modifications to the systems network configuration, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules" "Verified the audit system is NOT configured to audit ALL  modifications to the systems network configuration, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
else
	if [[ -n $(uname -m | grep x86_64) ]]; then
		if [[ -n $(egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules | grep 'b64') && -n $(egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules | grep "\-p wa") ]]; then
                	pass "$rule" "egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules" "Verified the audit system is configured to audit modifications to the systems network configuration, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
                else
                	fail "$rule" "egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules" "Verified the audit system is NOT configured to audit ALL  modifications to the systems network configuration, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
        	fi
	else
		if [[ -n $(egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules | grep 'b32') && -n $(egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules | grep "\-p wa") ]]; then
                        pass "$rule" "egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules" "Verified the audit system is configured to audit modifications to the systems network configuration, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
                else
                        fail "$rule" "egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules" "Verified the audit system is NOT configured to audit ALL  modifications to the systems network configuration, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
                fi
	fi
fi

### V-38541 ###
resetRule "SV-50342r2_rule"
nonzero "$rule" "grep -w \"/etc/selinux\" /etc/audit/audit.rules | grep -v \"^\s*#\" | grep \"\-p wa\"" "Verified the audit system IS configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system is NOT configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38542 ###
resetRule "SV-50343r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.all.rp_filter | grep 1" "Verified the system uses a reverse-path filter for IPv4 network traffic when possible on all interfaces, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a reverse-path filter for IPv4 network traffic when possible on all interfaces, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38543 ###
resetRule "SV-50344r4_rule"
if [[ -n $(grep -w "chmod" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "chmod" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
	pass "$rule" "grep -w \"chmod\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using chmod, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep -w \"chmod\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using chmod, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38544 ###
resetRule "SV-50345r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.default.rp_filter | grep 1" "Verified the system must uses reverse-path filter for IPv4 network traffic when possible by default, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system must does NOT use reverse-path filter for IPv4 network traffic when possible by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38545 ###
resetRule "SV-50346r4_rule"
if [[ -n $(grep -w "chown" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "chown" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"chown\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using chown, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"chown\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using chown, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38547 ###
resetRule "SV-50348r4_rule"
if [[ -n $(grep -w "fchmod" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "fchmod" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"fchmod\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchmod, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"fchmod\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchmod, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38548 ###
resetRule "SV-50349r4_rule"
if [[ -n $(grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1) ]]; then
	na "$rule" "grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1" "Verified IPv6 is disabled, therefore the reference STIG is Not Applicable"
else
	nonzero "$rule" "sysctl net.ipv6.conf.default.accept_redirects | grep 0" "Verified the system ignores ICMPv6 redirects by default, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT ignore ICMPv6 redirects by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38549 ###
resetRule "SV-50350r3_rule"
if [[ -n $(grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1) ]]; then
        na "$rule" "grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1" "Verified IPv6 is disabled, therefore the reference STIG is Not Applicable"
else
        nonzero "$rule" "service ip6tables status | grep -v \"not running\"" "Verified the system employs a local IPv6 firewall, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT employ a local IPv6 firewall, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38550 ###
resetRule "SV-50351r4_rule"
if [[ -n $(grep -w "fchmodat" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "fchmodat" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"fchmodat\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchmodat, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"fchmodat\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchmodat, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38551 ###
resetRule "SV-50352r3_rule"
if [[ -n $(grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1) ]]; then
        na "$rule" "grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1" "Verified IPv6 is disabled, therefore the reference STIG is Not Applicable"
else
        nonzero "$rule" "service ip6tables status | grep -v \"not running\"" "Verified the system employs a local IPv6 firewall, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT employ a local IPv6 firewall, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38552 ###
resetRule "SV-50353r4_rule"
if [[ -n $(grep -w "fchown" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "fchown" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"fchown\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchown, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"fchown\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchown, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38553 ###
resetRule "SV-50354r3_rule"
if [[ -n $(grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1) ]]; then
        na "$rule" "grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1" "Verified IPv6 is disabled, therefore the reference STIG is Not Applicable"
else
        nonzero "$rule" "service ip6tables status | grep -v \"not running\"" "Verified the system employs a local IPv6 firewall, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT employ a local IPv6 firewall, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38554 ###
resetRule "SV-50355r4_rule"
if [[ -n $(grep -w "fchownat" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "fchownat" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"fchownat\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchownat, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"fchownat\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fchownat, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38555 ###
resetRule "SV-50356r2_rule"
if [[ -n $(grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1) ]]; then
        na "$rule" "grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1" "Verified IPv6 is disabled, therefore the reference STIG is Not Applicable"
else
        nonzero "$rule" "service ip6tables status | grep -v \"not running\"" "Verified the system employs a local IPv6 firewall, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT employ a local IPv6 firewall, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38556 ###
resetRule "SV-50357r4_rule"
if [[ -n $(grep -w "fremovexattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "fremovexattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"fremovexattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fremovexattr, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"fremovexattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fremovexattr, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38557 ###
resetRule "SV-50358r4_rule"
if [[ -n $(grep -w "fsetxattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "fsetxattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"fsetxattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fsetxattr, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"fsetxattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using fsetxattr, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38558 ###
resetRule "SV-50359r4_rule"
if [[ -n $(grep -w "lchown" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "lchown" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"lchown\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using lchown, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"lchown\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using lchown, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38559 ###
resetRule "SV-50360r4_rule"
if [[ -n $(grep -w "lremovexattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "lremovexattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"lremovexattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using lremovexattr, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"lremovexattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using lremovexattr, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38560 ###
resetRule "SV-50361r2_rule"
if [[ -n $(grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1) ]]; then
        na "$rule" "grep -ir ipv6 /etc/modprobe.d/ | grep -v "^\s*#" | grep disable=1" "Verified IPv6 is disabled, therefore the reference STIG is Not Applicable"
else
        nonzero "$rule" "service ip6tables status | grep -v \"not running\"" "Verified the system employs a local IPv6 firewall, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT employ a local IPv6 firewall, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38561 ###
resetRule "SV-50362r4_rule"
if [[ -n $(grep -w "lsetxattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "lsetxattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"lsetxattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using lsetxattr, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"lsetxattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using lsetxattr, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38563 ###
resetRule "SV-50364r4_rule"
if [[ -n $(grep -w "removexattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "removexattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"removexattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using removexattr, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"removexattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using removexattr, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38565 ###
resetRule "SV-50366r4_rule"
if [[ -n $(grep -w "setxattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "setxattr" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"setxattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using setxattr, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"setxattr\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using setxattr, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38566 ###
resetRule "SV-50367r3_rule"
if [[ -n $(grep -w "EACCES" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep -w "EACCES" /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep -w \"EACCES\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using EACCES, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep -w \"EACCES\" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using EACCES, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38567 ###
resetRule "SV-50368r4_rule"
setuidpath=$(find / -xdev -type f -perm /6000 2>/dev/null)
testFail=false
failstring=""
for i in $setuidpath; do
	if [[ -z $(grep $i /etc/audit/audit.rules | grep "\-a always,exit -F path=$i -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged") ]]; then
		testFail=true
		failstring+=" $i "
	else
		$nothing
	fi
done

if [[ $testFail = true ]]; then
	fail "$rule" "find / -xdev -type f -perm /6000 2>/dev/null" "The following setuid paths are not audited: $(echo $failstring)"
else
	pass "$rule" "find / -xdev -type f -perm /6000 2>/dev/null" "Verified the audit system IS configured to audit all use of setuid and setgid programs, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail
unset failstring

### V-38568 ###
resetRule "SV-50369r4_rule"
if [[ -n $(grep " mount " /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(grep " mount " /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "grep \" mount \" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using mount, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "grep \" mount \" /etc/audit/audit.rules" "Verified the audit system is configured to audit all discretionary access control permission modifications using mount, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38569 ###
resetRule "SV-50370r2_rule"
nonzero "$rule" "grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth | egrep \"ucredit\s*=\s*-1\"" "Verified the system must require passwords to contain at least one uppercase alphabetic character, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain at least one uppercase alphabetic character, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38570 ###
resetRule "SV-50371r2_rule"
nonzero "$rule" "grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth | egrep \"ocredit\s*=\s*-1\"" "Verified the system must require passwords to contain at least one special character, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain at least one special character, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38571 ###
resetRule "SV-50372r3_rule"
nonzero "$rule" "grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth | egrep \"lcredit\s*=\s*-1\"" "Verified the system must require passwords to contain at least one lower-case alphabetic character, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain at least one lower-case alphabetic character, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38572 ###
resetRule "SV-50373r3_rule"
nonzero "$rule" "grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth | egrep \"difok\s*=\s*8\"" "Verified the system requires at least eight characters be changed between the old and new passwords during a password change, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require at least eight characters be changed between the old and new passwords during a password change, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38573 ###
resetRule "SV-50374r4_rule"
nonzero "$rule" "grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth | egrep \"deny\s*=\s*3\"" "Verified the system disables accounts after three consecutive unsuccessful logon attempts, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT disable accounts after three consecutive unsuccessful logon attempts, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38574 ###
resetRule "SV-50375r4_rule"
nonzero "$rule" "grep -E -c 'password.*pam_unix.so' /etc/pam.d/* | grep 1 | grep 'system-auth:\|system-auth-ac:' | wc -l | grep 2" "Verified the system uses a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth), therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth), therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38575 ###
resetRule "SV-50376r5_rule"
if [[ -n $(egrep -w 'rmdir|unlink|unlinkat|rename|renameat' /etc/audit/audit.rules | grep -v "^\s*#" | grep auid=0 | wc -l | grep 2) && -n $(egrep -w 'rmdir|unlink|unlinkat|rename|renameat' /etc/audit/audit.rules | grep -v "^\s*#" | grep auid!=4294967295 | wc -l | grep 2) ]]; then
        pass "$rule" "egrep -w 'rmdir|unlink|unlinkat|rename|renameat' /etc/audit/audit.rules" "Verified the audit system IS configured to audit user deletions of files and programs, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        fail "$rule" "egrep -w 'rmdir|unlink|unlinkat|rename|renameat' /etc/audit/audit.rules" "Verified the audit system IS configured to audit user deletions of files and programs, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38576 ###
resetRule "SV-50377r1_rule"
nonzero "$rule" "grep -i \"^\s*ENCRYPT_METHOD\s*\" /etc/login.defs | grep -v \"^\s*#\" | grep -i SHA512" "Verified the system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs), therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs), therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." 

### V-38577 ###
resetRule "SV-50378r1_rule"
nonzero "$rule" "grep -i crypt_style /etc/libuser.conf | grep -v "^\s*#" | grep -i sha512" "Verified the system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf), therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf), therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38578 ###
resetRule "SV-50379r2_rule"
zero "$rule" "grep -w \"/etc/sudoers\" /etc/audit/audit.rules | grep -v \"\-p wa\"" "Verified the audit system IS configured to audit changes to the /etc/sudoers file, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system is NOT configured to audit changes to the /etc/sudoers file, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38579 ###
resetRule "SV-50380r2_rule"
nonzero "$rule" "ls -l /boot/grub/grub.conf | awk -F\" \" '{print \$3}' | grep root" "Verified the /boot/grub/grub.conf file IS owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /boot/grub/grub.conf file is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38580 ###
resetRule "SV-50381r3_rule"
if [[ -n $(egrep -e "(-w |-F path=)/sbin/insmod|(-w |-F path=)/sbin/rmmod|(-w |-F path=)/sbin/modprobe" /etc/audit/audit.rules | grep "\-p x" | grep -v "^\s*#" | wc -l | grep 3) && -n $(egrep -w "init_module|delete_module" /etc/audit/audit.rules | grep 'b32\|b64' | grep -v "^\s*#" | wc -l | grep 2) ]]; then
	pass "$rule" "egrep -e \"(-w |-F path=)/sbin/insmod|(-w |-F path=)/sbin/rmmod|(-w |-F path=)/sbin/modprobe\" /etc/audit/audit.rules;egrep -w \"init_module|delete_module\" /etc/audit/audit.rules" "Verified the audit system IS configured to audit the loading and unloading of dynamic kernel modules,  therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "egrep -e \"(-w |-F path=)/sbin/insmod|(-w |-F path=)/sbin/rmmod|(-w |-F path=)/sbin/modprobe\" /etc/audit/audit.rules;egrep -w \"init_module|delete_module\" /etc/audit/audit.rules" "Verified the audit system must is NOT configured to audit the loading and unloading of dynamic kernel modules, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38581 ###
resetRule "SV-50382r2_rule"
nonzero "$rule" "ls -l /boot/grub/grub.conf | awk -F\" \" '{print \$4}' | grep root" "Verified the /boot/grub/grub.conf file IS group-owned by root, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /boot/grub/grub.conf file is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38582 ###
resetRule "SV-50383r2_rule"
if [[ -z $(service xinetd status) ]]; then
	pass "$rule" "service xinetd status" "Verified packages related to xinetd is not installed, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nonzero "$rule" "chkconfig \"xinetd\" --list | grep -v on" "Verified the xinetd service IS disabled if no network services utilizing it are enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the xinetd service is NOT disabled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38583 ###
resetRule "SV-50384r5_rule"
nonzero "$rule" "stat -c '%a' /boot/grub/grub.conf | grep \"^600\s*\"" "Verified the /boot/grub/grub.conf file have mode 600, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /boot/grub/grub.conf file does NOT have mode 600, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38584 ###
resetRule "SV-50385r1_rule"
nonzero "$rule" "rpm -q xinetd | grep \"not installed\"" "Verified the xinetd service is uninstalled if no network services utilizing it are enabled, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the xinetd service is NOT uninstalled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38585 ###
resetRule "SV-50386r4_rule"
nonzero "$rule" "grep password /boot/grub/grub.conf | grep -v "^\s*#" | grep encrypted" "Verified the system boot loader must require authentication, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system boot loader does NOT require authentication, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38586 ###
resetRule "SV-50387r1_rule"
nonzero "$rule" "grep SINGLE /etc/sysconfig/init | grep '/sbin/sulogin' | grep -v \"^\s*#\"" "Verified the system must require authentication upon booting into single-user and maintenance modes, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require authentication upon booting into single-user and maintenance modes, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38587 ###
resetRule "SV-50388r1_rule"
nonzero "$rule" "rpm -q telnet-server | grep \"not installed\"" "Verified the telnet-server service is uninstalled if no network services utilizing it are enabled, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the telnet-server service is NOT uninstalled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38588 ###
resetRule "SV-50389r1_rule"
nonzero "$rule" "grep PROMPT /etc/sysconfig/init | grep no | grep -v \"^\s*#\"" "Verified the system must not permit interactive boot, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system permits interactive boot, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38589 ###
resetRule "SV-50390r2_rule"
zero "$rule" "chkconfig \"telnet\" --list" "Verified the telnet service IS disabled if no network services utilizing it are enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the telnet service is NOT disabled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38590 ###
resetRule "SV-50391r1_rule"
nonzero "$rule" "rpm -q screen | grep screen-" "Verified the system must allow locking of the console screen in text mode, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT allow locking of the console screen in text mode, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38591 ###
resetRule "SV-50392r1_rule"
nonzero "$rule" "rpm -q rsh-server | grep \"not installed\"" "Verified the rsh-server service is uninstalled if no network services utilizing it are enabled, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rsh-server service is NOT uninstalled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38592 ###
resetRule "SV-50393r4_rule"
testFail=false
if [[ -n $(grep pam_faillock /etc/pam.d/system-auth | grep 'unlock_time=604800\|required' | wc -l | grep 3) ]]; then
	if [[ -n $(grep pam_faillock /etc/pam.d/system-auth | grep 'unlock_time=604800\|required' | tail -1 | egrep "account\s*required\s*pam_faillock.so") ]]; then
		$nothing
	else
		testFail=true
	fi
	if [[ -n $(grep pam_faillock /etc/pam.d/password-auth | grep 'unlock_time=604800\|required' | wc -l | grep 3) ]]; then
		if [[ -n $(grep pam_faillock /etc/pam.d/password-auth | grep 'unlock_time=604800\|required' | tail -1 | egrep "account\s*required\s*pam_faillock.so") ]]; then
                	$nothing
        	else
                	testFail=true
        	fi
	else
		testFail=true
	fi
else
	testFail=true
fi

if [[ $testFail = true ]]; then
        fail "$rule" "grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system does NOT require administrator action to unlock an account locked by excessive failed login attempts, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        pass "$rule" "grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system must require administrator action to unlock an account locked by excessive failed login attempts, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi


unset testFail

### V-38593 ###
resetRule "SV-50394r3_rule"
if [[ -n "cat /etc/issue | grep 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.' | grep 'By using this IS (which includes any device attached to this IS), you consent to the following conditions:' | grep '-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.' | grep '-At any time, the USG may inspect and seize data stored on this IS.' | grep '-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.' | grep '-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.' | grep '-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'" ]]; then
        pass "$rule" "cat /etc/issue" "Verified the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        nr "$rule" "cat /etc/issue" "Banner will need to be manual verified"
fi

### V-38594 ###
resetRule "SV-50395r2_rule"
zero "$rule" "chkconfig \"rsh\" --list" "Verified the rsh service IS disabled if no network services utilizing it are enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rsh service is NOT disabled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38595 ###
resetRule "SV-50396r3_rule"
nonzero "$rule" "grep ipa /etc/sssd/sssd.conf" "Verified IPA is installed and enforced on the server via SSSD, IPA controls CAC authentication via an IDM server, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system is NOT configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication,  therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38596 ###
resetRule "SV-50397r3_rule"
nonzero "$rule" "sysctl kernel.randomize_va_space | grep 2" "Verified the system must implement virtual address space randomization, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT implement virtual address space randomization, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38597 ###
resetRule "SV-50398r3_rule"
nonzero "$rule" "sysctl kernel.exec-shield | grep 1" "Verified the system must limit the ability of processes to have simultaneous write and execute access to memory, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT limit the ability of processes to have simultaneous write and execute access to memory, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38598 ###
resetRule "SV-50399r2_rule"
zero "$rule" "chkconfig \"rexec\" --list" "Verified the rexec service IS disabled if no network services utilizing it are enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rexec service is NOT disabled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38599 ###
resetRule "SV-50400r3_rule"
if [[ -n $(rpm -qa | grep -i vsftpd) ]]; then
	nonzero "$rule" "grep \"banner_file\" /etc/vsftpd/vsftpd.conf | grep /etc/issue | grep -v \"^\s*#\"" "Verified the FTPS/FTP service on the system IS configured with the Department of Defense (DoD) login banner, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the FTPS/FTP service on the system is NOT configured with the Department of Defense (DoD) login banner, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "rpm -qa | grep -i vsftpd" "Verified the "vsftpd" package is not installed, therefore the reference STIG is Not Applicable"
fi

### V-38600 ###
resetRule "SV-50401r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.default.send_redirects | grep 0" "Verified the system must not send ICMPv4 redirects by default, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does send ICMPv4 redirects by default, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38601 ###
resetRule "SV-50402r3_rule"
nonzero "$rule" "sysctl net.ipv4.conf.all.send_redirects | grep 0" "Verified the system must not send ICMPv4 redirects from any interface, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system sends ICMPv4 redirects from any interface, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38602 ###
resetRule "SV-50403r2_rule"
zero "$rule" "chkconfig \"rlogin\" --list" "Verified the rlogin service IS disabled if no network services utilizing it are enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rlogin service is NOT disabled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38603 ###
resetRule "SV-50404r1_rule"
nonzero "$rule" "rpm -q ypserv | grep \"not installed\"" "Verified the ypserv service is uninstalled if no network services utilizing it are enabled, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the ypserv service is NOT uninstalled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38604 ###
resetRule "SV-50405r2_rule"
nonzero "$rule" "chkconfig \"ypbind\" --list | grep -v on" "Verified the ypbind service is NOT be running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the ypbind service IS be running, unless using RHN or an RHN Satellite, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38605  ###
resetRule "SV-50406r2_rule"
nonzero "$rule" "service crond status | grep \"is running\"" "Verified the cron service IS running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the cron service is NOT running, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38606 ###
resetRule "SV-50407r3_rule"
nonzero "$rule" "rpm -q tftp-server | grep \"not installed\"" "Verified the tftp-server service is uninstalled if no network services utilizing it are enabled, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the tftp-server service is NOT uninstalled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38607 ###
resetRule "SV-50408r1_rule"
nonzero "$rule" "grep Protocol /etc/ssh/sshd_config | grep -v "^\s*#" | grep 2" "Verified the SSH daemon IS configured to use only the SSHv2 protocol, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon is NOT configured to use only the SSHv2 protocol, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38608 ###
resetRule "SV-50409r1_rule"
nonzero "$rule" "grep ClientAliveInterval /etc/ssh/sshd_config | grep -v "^\s*#" | awk -F ' ' '\$2 <=900'" "Verified the SSH daemon set a timeout interval on idle sessions, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon does NOT set a timeout interval on idle sessions, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38609 ###
resetRule "SV-50410r3_rule"
zero "$rule" "chkconfig \"tftp\" --list" "Verified the tftp service IS disabled if no network services utilizing it are enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the tftp service is NOT disabled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38610 ###
resetRule "SV-50411r1_rule"
nonzero "$rule" "grep ClientAliveCountMax /etc/ssh/sshd_config | grep -v "^\s*#" | grep 0" "Verified the SSH daemon sets a timeout count on idle sessions, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon does NOT set a timeout count on idle sessions, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38611 ###
resetRule "SV-50412r1_rule"
nonzero "$rule" "grep -i IgnoreRhosts /etc/ssh/sshd_config | grep -v "^\s*#" | grep -i yes" "Verified the SSH daemon ignores .rhosts files, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon does NOT ignore .rhosts files, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38612 ###
resetRule "SV-50413r1_rule"
nonzero "$rule" "grep -i HostbasedAuthentication /etc/ssh/sshd_config | grep -v "^\s*#" | grep -i no" "Verified the SSH daemon does not allow host-based authentication, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon DOES allow host-based authentication, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38613 ###
resetRule "SV-50414r1_rule"
nonzero "$rule" "grep -i PermitRootLogin /etc/ssh/sshd_config | grep -v "^\s*#" | grep -i no" "Verified the system does not permit root logins using remote access programs such as ssh, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES permit root logins using remote access programs such as ssh, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38614 ###
resetRule "SV-50415r1_rule"
nonzero "$rule" "grep -i PermitEmptyPasswords /etc/ssh/sshd_config | grep -v "^\s*#" | grep -i no" "Verified the SSH daemon does not allow authentication using an empty password, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon DOES allow authentication using an empty password, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38615 ###
resetRule "SV-50416r1_rule"
nonzero "$rule" "grep -i Banner /etc/ssh/sshd_config | grep -v "^\s*#" | grep \"/etc/issue\"" "Verified the SSH daemon IS configured with the Department of Defense (DoD) login banner, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon is NOT configured with the Department of Defense (DoD) login banner, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38616 ###
resetRule "SV-50417r1_rule"
nonzero "$rule" "grep -i PermitUserEnvironment /etc/ssh/sshd_config | grep -v "^\s*#" | grep -i no" "Verified the SSH daemon does not permit user environment settings, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon DOES permit user environment settings, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38617 ###
resetRule "SV-50418r2_rule"
nonzero "$rule" "grep -i 'ciphers' /etc/ssh/sshd_config | grep -v '^\s*#' | grep -E 'aes128-ctr.*aes192-ctr.*aes256-ctr|aes256-ctr.*aes192-ctr.*aes128-ctr'" "Verified the SSH daemon IS configured to use only FIPS 140-2 approved ciphers, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon is NOT configured to use only FIPS 140-2 approved ciphers, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38618 ###
resetRule "SV-50419r2_rule"
zero "$rule" "chkconfig \"avahi-daemon\" --list" "Verified the avahi-daemon service IS disabled if no network services utilizing it are enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the avahi-daemon service is NOT disabled if no network services utilizing it are enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38619 ###
resetRule "SV-50420r2_rule"
zero "$rule" "find /root /home -xdev -name .netrc" "Verified there must be no .netrc files on the system, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified there IS .netrc files on the system, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38620 ###
resetRule "SV-50421r1_rule"
nonzero "$rule" "service ntpd status | grep \"is running\"" "Verified the system clock IS synchronized continuously, or at least daily, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system clock is NOT synchronized continuously, or at least daily, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38621 ###
resetRule "SV-50422r1_rule"
nonzero "$rule" "grep server /etc/ntp.conf | grep -v \"^\s*#\" | grep -v pool" "Verified the system clock IS synchronized to an authoritative DoD time source, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system clock is NOT synchronized to an authoritative DoD time source, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38622 ###
resetRule "SV-50423r2_rule"
nonzero "$rule" "grep inet_interfaces /etc/postfix/main.cf | grep -v '^\s*#' | grep -i localhost" "Verified mail relaying IS restricted, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified mail relaying is NOT restricted, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38623 ###
resetRule "SV-50424r2_rule"
declare -A perm
testFail=false
paths=$(cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F" " '{print $2}' | grep -v ":" | sed 's/-//g')
for i in $paths; do
	while read -n1 octet; do
    	perm+=$octet
	done < <(echo -n "$i")

	if [[ $(echo $perm[0] -le "6") && $(echo $perm[1] -eq "0") && $(echo $perm[2] -eq "0") ]]; then
        	$nothing
	else
        	testFail=true
	fi
done

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F\" \" '{print \$2}' | grep -v \":\" | sed 's/-//g'" "Verified some rsyslog-generated log files are NOT set to 600 or more permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  pass "$rule" "cat /etc/rsyslog.conf | sed '1,/Rules/d' | awk -F\" \" '{print \$2}' | grep -v \":\" | sed 's/-//g'" "Verified all rsyslog-generated log files are set to 600 or more permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail
unset paths

### V-38624 ###
resetRule "SV-50425r1_rule"
nonzero "$rule" "grep logrotate /var/log/cron* | grep \"$(date '+%b %d')\"" "Verified system logs are rotated daily, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified system logs are NOT rotated daily, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38627 ###
resetRule "SV-50428r2_rule"
nonzero "$rule" "rpm -q openldap-servers | grep \"not installed\"" "Verified the openldap-servers package is NOT be installed unless required, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the openldap-servers package IS installed unless required, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38628 ###
resetRule "SV-50429r2_rule"
nonzero "$rule" "service auditd status | grep \"is running\"" "Verified the operating system produces audit records containing sufficient information to establish the identity of any user/subject associated with the event, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT produce audit records containing sufficient information to establish the identity of any user/subject associated with the event, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38629 ###
resetRule "SV-50430r3_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
        na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        nonzero "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay" "Verified the graphical desktop environment IS set the idle timeout to no more than 15 minutes, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the graphical desktop environment is NOT set the idle timeout to no more than 15 minutes, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38630 ###
resetRule "SV-50431r3_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
        na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        nonzero "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled" "Verified the graphical desktop environment IS automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the graphical desktop environment is NOT automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38631 ###
resetRule "SV-50432r2_rule"
nonzero "$rule" "service auditd status | grep \"is running\"" "Verified the operating system produces audit records containing sufficient information to establish the identity of any user/subject associated with the event, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT produce audit records containing sufficient information to establish the identity of any user/subject associated with the event, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38632 ###
resetRule "SV-50433r2_rule"
nonzero "$rule" "service auditd status | grep \"is running\"" "Verified the operating system produces audit records containing sufficient information to establish the identity of any user/subject associated with the event, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT produce audit records containing sufficient information to establish the identity of any user/subject associated with the event, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38633 ###
resetRule "SV-50434r1_rule"
nonzero "$rule" "grep 'max_log_file\s*=' /etc/audit/auditd.conf | grep -v '^\s*#' | awk -F '=' '\$2 >= 6'" "Verified the system does set a maximum audit log file size, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT set a maximum audit log file size, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38634 ###
resetRule "SV-50435r2_rule"
nonzero "$rule" "grep max_log_file_action /etc/audit/auditd.conf | grep -v '^\s*#' | grep -i 'rotate\|ignore\|syslog\|suspend\|keep_logs'" "Verified the system does rotate audit log files that reach the maximum file size, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT rotate audit log files that reach the maximum file size, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38636 ###
resetRule "SV-50437r1_rule"
nonzero "$rule" "grep 'num_logs\s*=' /etc/audit/auditd.conf | grep -v '^\s*#' | awk -F '=' '\$2 >= 2'" "Verified the system does retain enough rotated audit logs to cover the required log retention period, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT retain enough rotated audit logs to cover the required log retention period, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38637 ###
resetRule "SV-50438r2_rule"
zero "$rule" "rpm -V audit | awk '$1 ~ /..5/ && $2 != \"c\"'" "Verified the system package management tool IS verifying contents of all files associated with the audit package, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system package management tool is NOT verifying contents of all files associated with the audit package, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38638 ###
resetRule "SV-50439r3_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
        na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        nonzero "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled" "Verified the graphical desktop environment does have automatic lock enabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the graphical desktop environment does NOT have automatic lock enabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38639 ###
resetRule "SV-50440r3_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
        na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        nonzero "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode" "Verified the system must display a publicly-viewable pattern during a graphical desktop environment session lock, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system must display a publicly-viewable pattern during a graphical desktop environment session lock, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38640 ###
resetRule "SV-50441r2_rule"
nonzero "$rule" "chkconfig \"abrtd\" --list | grep -v on" "Verified the Automatic Bug Reporting Tool (abrtd) service is NOT running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Automatic Bug Reporting Tool (abrtd) service IS running, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was correct by default and/or no inchange was necessary."

### V-38641 ###
resetRule "SV-50442r3_rule"
nonzero "$rule" "chkconfig \"atd\" --list | grep -v on" "Verified the atd service is NOT running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the atd service IS running, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was correct by default and/or no inchange was necessary."

### V-38642 ###
resetRule "SV-50443r1_rule"
nonzero "$rule" "grep umask /etc/init.d/functions | grep -v '^\s*#' | grep '022\|027'" "Verified the system default umask for daemons must be 027 or 022, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system default umask for daemons is NOT 027 or 022, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38643 ###
resetRule "SV-50444r3_rule"
zero "$rule" "find / -xdev -type f -perm -002 -not -path \"/selinux/*\" -not -path \"/sys/*\" -not -path \"/proc/*\"" "Verified there must be no world-writable files on the system, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified there IS world-writable files on the system, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38644 ###
resetRule "SV-50445r2_rule"
nonzero "$rule" "chkconfig \"ntpdate\" --list | grep -v on" "Verified the ntpdate service is NOT running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the ntpdate service IS running, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38645 ###
resetRule "SV-50446r1_rule"
nonzero "$rule" "grep -i \"umask\" /etc/login.defs | grep -v '^\s*#' | grep 077" "Verified the system default umask in /etc/login.defs IS 077, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system default umask in /etc/login.defs is NOT 077, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38646 ###
resetRule "SV-50447r2_rule"
nonzero "$rule" "chkconfig \"oddjobd\" --list | grep -v on" "Verified the oddjobd service is NOT running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the oddjobd service IS running, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38647 ###
resetRule "SV-50448r1_rule"
zero "$rule" "grep "umask" /etc/profile | grep -v '^\s*#' | grep -v 077" "Verified the system default umask in /etc/profile IS 077, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system default umask in /etc/profile is NOT 077, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38648 ###
resetRule "SV-50449r2_rule"
zero "$rule" "chkconfig \"qpidd\" --list" "Verified the qpidd service is NOT running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the qpidd service IS running, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38649 ###
resetRule "SV-50450r1_rule"
zero "$rule" "grep \"umask\" /etc/csh.cshrc | grep -v '^\s*#' | grep -v 077" "Verified the system default umask in /etc/csh.cshrc IS 077, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system default umask in /etc/csh.cshrc is NOT 077, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38650 ###
resetRule "SV-50451r2_rule"
nonzero "$rule" "chkconfig \"rdisc\" --list | grep -v on" "Verified the rdisc service is NOT running, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rdisc service IS running, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38651 ###
resetRule "SV-50452r1_rule"
zero "$rule" "grep \"umask\" /etc/bashrc | grep -v '^\s*#' | grep -v 077" "Verified the system default umask in /etc/bashrc IS 077, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system default umask in /etc/bashrc is NOT 077, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38652 ###
resetRule "SV-50453r2_rule"
if [[ -n $(mount | grep "nfs ") ]]; then
	nonzero "$rule" "mount | grep \"nfs \" | grep nodev" "Verified remote file systems IS mounted with the nodev option, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified remote file systems is NOT mounted with the nodev option, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "mount | grep \"nfs \"" "Verified NFS mounts are not present on the system, therefore the reference STIG is Not Applicable"
fi

### V-38653 ###
resetRule "SV-50454r2_rule"
if [[ -n $(rpm -qa | grep -i '^net-snmp-\d') ]]; then
	zero "$rule" "grep -v '^\s*#' /etc/snmp/snmpd.conf| grep public" "Verified the snmpd service must does not use a default password, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the snmpd service must uses a default password, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "rpm -qa | grep -i '^net-snmp-\d'" "Verified the snmp package is not installed, therefore the reference STIG is Not Applicable. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38654 ###
resetRule "SV-50455r2_rule"
if [[ -n $(mount | grep "nfs ") ]]; then
        nonzero "$rule" "mount | grep \"nfs \" | grep nosuid" "Verified remote file systems IS mounted with the nosuid option, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified remote file systems is NOT mounted with the nosuid option, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        na "$rule" "mount | grep \"nfs \"" "Verified NFS mounts are not present on the system, therefore the reference STIG is Not Applicable"
fi

### V-38656 ###
resetRule "SV-50457r1_rule"
zero "$rule" "grep signing /etc/samba/smb.conf | grep -v '^\s*#' | grep -v mandatory" "Verified the system must use SMB client signing for connecting to samba servers using smbclient, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use SMB client signing for connecting to samba servers using smbclient, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38657 ###
resetRule "SV-50458r2_rule"
if [[ -n $(mount | grep "cifs ") ]]; then
        nonzero "$rule" "mount | grep \"cifs \" | grep 'krb5i\|ntlmv2i'" "Verified remote file systems IS mounted with the krb5i or ntlmv2i, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified remote file systems is NOT mounted with the krb5i or ntlmv2i option, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        na "$rule" "mount | grep \"cifs \"" "Verified Samba mounts are not present on the system, therefore the reference STIG is Not Applicable"
fi

### V-38658 ###
resetRule "SV-50459r6_rule"
nonzero "$rule" "grep remember /etc/pam.d/system-auth /etc/pam.d/password-auth | grep 'required\|requisite' | awk -F '=' '\$2 >= 5'" "Verified the system must prohibit the reuse of passwords within five iterations, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT prohibit the reuse of passwords within five iterations, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38660 ###
resetRule "SV-50461r2_rule"
if [[ -n $(rpm -qa | grep -i '^net-snmp-\d') ]]; then
        zero "$rule" "grep 'v1\|v2c\|com2sec' /etc/snmp/snmpd.conf | grep -v '^\s*#'" "Verified the snmpd service must only use version 3 or newer, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the snmpd service is NOT restricted to use version 3 or newer, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        na "$rule" "rpm -qa | grep -i '^net-snmp-\d'" "Verified the snmp package is not installed, therefore the reference STIG is Not Applicable. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38663 ###
resetRule "SV-50464r1_rule"
if [[ -n $(rpm -V audit | grep '^.M') ]]; then
	output=""
	rpms=$(rpm -V audit | grep '^.M' | awk -F ' ' '{print $2}')
	for file in $rpms; do 
		if [ $(stat --printf='%a' $file | tail -c3) -lt $(rpm -qf --queryformat '%{FILEMODES:octal}' $file | tail -c3) ]; then 
			$nothing
		else
			testFail=true		
			output+="$file ;"
		fi 
	done

	if [[ $(echo $testFail) == true ]]; then
  		fail "$rule" "echo $output" "The files listed were found to be more permissive then the default rpm permissions, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	else
  		pass "$rule" "rpm -V audit | grep '^.M' | awk -F ' ' '{print $2}'" "Verified all files returned are less permissive then the default rpm permissions, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	fi

	unset testFail
	unset paths
	unset output
else
	pass "$rule" "rpm -V audit | grep '^.M' | awk -F ' ' '{print $2}'" "Verified rpm did not find any discrepancies within the default rpm permissions, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-38664 ###
resetRule "SV-50465r1_rule"
zero "$rule" "rpm -V audit | grep '^.....U'" "Verified the system package management tool must verify ownership on all files and directories associated with the audit package,  therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system package management tool does NOT verify ownership on all files and directories associated with the audit package, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38665 ###
resetRule "SV-50466r1_rule"
zero "$rule" "rpm -V audit | grep '^......G'" "Verified the system package management tool must verify ownership on all files and directories associated with the audit package,  therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system package management tool does NOT verify ownership on all files and directories associated with the audit package, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38667 ###
resetRule "SV-50468r3_rule"
if [[ -n "$(rpm -qa | grep MFEhiplsm)" ]]; then
        #McAfee HIPS installed
        if [[ -n "$(ps -ef | grep -i 'hipclient')" ]]; then
                #it's an active process
                na "$rule" "echo 'McAFEE HIPS is installed and active. This check is not applicable
                '; ps -ef | grep -i 'hipclient'" "McAFEE HIPS is installed and active"
        else
                #installed but inactive
                if [[ -n "$(sestatus | grep -i 'SELinux status:' | grep -i 'enabled')" ]]; then
                        nonzero "$rule" "sestatus | grep -Ei 'Loaded Policy Name:|Policy from config file:' | grep -i 'targeted'" "Verified the operating system has enabled the SELinux targeted policy, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system has NOT enabled the SELinux targeted policy, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
                else
                        fail "$rule" "sestatus | grep -i '^\s*SELinux status:\s*enabled'" "SELinux is not enabled"
                fi
        fi
else
        #not installed
        if [[ -n "$(sestatus | grep -i 'SELinux status:' | grep -i 'enabled')" ]]; then
                nonzero "$rule" "sestatus | grep -Ei 'Loaded Policy Name:|Policy from config file:' | grep -i 'targeted'" "Verified the operating system has enabled the SELinux targeted policy, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system has NOT enabled the SELinux targeted policy, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
        else
                fail "$rule" "sestatus | grep -i '^\s*SELinux status:\s*enabled'" "SELinux is not enabled"
        fi
fi

### V-38668 ###
resetRule "SV-50469r4_rule"
nonzero "$rule" "grep 'authpriv.notice' /etc/init/control-alt-delete.override | grep -v '^\s*#' | grep logger" "Verified the x86 Ctrl-Alt-Delete key sequence IS disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the x86 Ctrl-Alt-Delete key sequence is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." 

### V-38669 ###
resetRule "SV-50470r1_rule"
nonzero "$rule" "service postfix status | grep 'is running'" "Verified the postfix service IS enabled for mail delivery,  therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the postfix service is NOT enabled for mail delivery,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38670 ###
resetRule "SV-50471r2_rule"
nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep '\-\-check'" "Verified the operating system must detect unauthorized changes to software and information, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT detect unauthorized changes to software and information, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38671 ###
resetRule "SV-50472r1_rule"
nonzero "$rule" "rpm -q sendmail | grep 'not installed'" "Verified the sendmail package IS removed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the sendmail package is NOT removed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38672 ###
resetRule "SV-50473r2_rule"
nonzero "$rule" "chkconfig \"netconsole\" --list | grep -v on" "Verified the netconsole service IS disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the netconsole service is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38673 ###
resetRule "SV-50474r2_rule"
nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep '\-\-check'" "Verified the operating system must detect unauthorized changes to software and information, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT detect unauthorized changes to software and information, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38674 ###
resetRule "SV-50475r1_rule"
nonzero "$rule" "grep initdefault /etc/inittab | grep -v '^\s*#' | grep 3" "Verified X Windows is NOT enabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified X Windows IS enabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38675 ###
resetRule "SV-50476r2_rule"
nonzero "$rule" "grep core /etc/security/limits.conf /etc/security/limits.d/*.conf | grep -v '^/s*#' | grep '* hard core 0'" "Verified process core dumps IS disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified process core dumps is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38676 ###
resetRule "SV-50477r2_rule"
nonzero "$rule" "rpm -qi xorg-x11-server-common | grep 'not installed'" "Verified the xorg-x11-server-common (X Windows) package is NOT installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the xorg-x11-server-common (X Windows) package IS installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38677 ###
resetRule "SV-50478r1_rule"
zero "$rule" "grep insecure_locks /etc/exports" "Verified the NFS server must not have the insecure file locking option enabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the NFS server DOES have the insecure file locking option enabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38678 ###
resetRule "SV-50479r2_rule"
nonzero "$rule" "grep space_left /etc/audit/auditd.conf | grep -v '^\s*#' | grep '^\s*space_left\s*=' | grep '\d*'" "Verified the audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38679 ###
resetRule "SV-50480r4_rule"
output=""
ifs=$(ls /etc/sysconfig/network-scripts/ifcfg-* | grep -v '\.' | grep -v 'lo')
for i in $ifs; do
	if [[ -n $(grep -i bootproto $i | grep -v '^\s*#' | grep -i 'none') ]]; then
		$nothing
	else
		testFail=true
		output+="$i ;"
	fi
done

if [[ $(echo $testFail) == true ]]; then
	fail "$rule" "echo $output" "The interfaces listed have bootproto set to a value other then none, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        pass "$rule" "ls /etc/sysconfig/network-scripts/ifcfg-* | grep -v '\.' | grep -v 'lo'" "Verified all interfaces are using bootproto none, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset output
unset testFail

### V-38680 ###
resetRule "SV-50481r1_rule"
mailuser=$(grep action_mail_acct /etc/audit/auditd.conf | grep -v '^\s*#' | awk -F '=' '{print $2}')
nonzero "$rule" "grep $(echo $mailuser) /etc/aliases | grep '.mil'" "Verified the audit system identifies staff members to receive notifications of audit log storage volume capacity issues, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT identify staff members to receive notifications of audit log storage volume capacity issues, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

unset mailuser

### V-38681 ###
resetRule "SV-50482r2_rule"
zero "$rule" "pwck -r | grep 'no group'" "Verified all GIDs referenced in /etc/passwd IS defined in /etc/group, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all GIDs referenced in /etc/passwd is NOT defined in /etc/group, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38682 ###
resetRule "SV-50483r6_rule"
if [[ -n $(grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true" | grep -v "^\s*#") && -n $(grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true" | grep -v "^\s*#") ]]; then
	pass "$rule" "grep -r 'bluetooth\|net-pf-31' /etc/modprobe.conf /etc/modprobe.d | grep -i '/bin/true' | grep -v '^\s*#'" "Verified bluetooth kernel IS disabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep -r 'bluetooth\|net-pf-31' /etc/modprobe.conf /etc/modprobe.d | grep -i '/bin/true' | grep -v '^\s*#'" "Verified bluetooth kernel is NOT disabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38683 ###
resetRule "SV-50484r1_rule"
zero "$rule" "pwck -rq" "Verified all accounts on the system must have unique user or account names, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all accounts on the do NOT have unique user or account names, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38684 ###
resetRule "SV-50485r2_rule"
nonzero "$rule" "grep 'maxlogins\s*\d*' /etc/security/limits.conf /etc/security/limits.d/*.conf | grep -v '#' | awk -F ' ' '\$4 <= 10'" "Verified the system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38686 ###
resetRule "SV-50487r2_rule"
nonzero "$rule" "iptables -nvL | grep -i forward | grep DROP" "Verified the systems local firewall implements a deny-all, allow-by-exception policy for forwarded packets, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the systems local firewall does NOT implement a deny-all, allow-by-exception policy for forwarded packets, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38687 ###
resetRule "SV-50488r3_rule"
nonzero "$rule" "rpm -q libreswan | grep 'libreswan-'" "Verified the system must provide VPN connectivity for communications over untrusted networks, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT provide VPN connectivity for communications over untrusted networks, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38688 ###
resetRule "SV-50489r3_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
        na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        nonzero "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable | grep true" "Verified a login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified a login banner is NOT displayed immediately prior to, or as part of, graphical desktop environment login prompts, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38689 ###
resetRule "SV-50490r5_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
        na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	if [[ -n "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text | grep 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.' | grep 'By using this IS (which includes any device attached to this IS), you consent to the following conditions:' | grep '-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.' | grep '-At any time, the USG may inspect and seize data stored on this IS.' | grep '-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.' | grep '-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.' | grep '-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'" ]]; then
        	pass "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text | sed 's/&//g'" "Verified the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
        	nr "$rule" "cat /etc/issue" "Banner will need to be manual verified"
	fi
fi

### V-38691 ###
resetRule "SV-50492r2_rule"
zero "$rule" "chkconfig \"bluetooth\" --list" "Verified the Bluetooth service IS disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Bluetooth service is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38692 ###
resetRule "SV-50493r1_rule"
nonzero "$rule" "grep 'INACTIVE' /etc/default/useradd | grep -v '^\s*#' | awk -F '=' '\$2 <= 35'" "Verified accounts must be locked upon 35 days of inactivity, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified accounts are NOT locked upon 35 days of inactivity, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38693 ###
resetRule "SV-50494r4_rule"
if [[ -n $(grep pam_cracklib /etc/pam.d/system-auth | grep -Eo 'maxrepeat\s*=[1-3]') && -n $(grep pam_cracklib /etc/pam.d/password-auth | grep -Eo 'maxrepeat\s*=[1-3]') ]]; then
	pass "$rule" "grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system must require passwords to contain no more than three consecutive repeating characters,  therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth" "Verified the system does NOT require passwords to contain no more than three consecutive repeating characters,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38694 ###
resetRule "SV-50495r1_rule"
nonzero "$rule" "grep 'INACTIVE' /etc/default/useradd | grep -v '^\s*#' | awk -F '=' '\$2 <= 35'" "Verified accounts must be locked upon 35 days of inactivity, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified accounts are NOT locked upon 35 days of inactivity, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38695 ###
resetRule "SV-50496r2_rule"
nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep '\-\-check'" "Verified the operating system must detect unauthorized changes to software and information, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT detect unauthorized changes to software and information, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38696 ###
resetRule "SV-50497r2_rule"
nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep '\-\-check'" "Verified the operating system must detect unauthorized changes to software and information, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT detect unauthorized changes to software and information, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38697 ###
resetRule "SV-50498r2_rule"
zero "$rule" "find / -xdev -type d -perm -002 \! -perm -1000" "Verified the sticky bit IS set on all public directories, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the sticky bit is NOT set on all public directories, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38698 ###
resetRule "SV-50499r2_rule"
nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep '\-\-check'" "Verified the operating system must detect unauthorized changes to software and information, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT detect unauthorized changes to software and information, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38699 ###
resetRule "SV-50500r2_rule"
zero "$rule" "find / -xdev -type d -perm -0002 -uid +499 -print" "Verified all public directories must be owned by a system account, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all public directories are NOT owned by a system account, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38700 ###
resetRule "SV-50501r2_rule"
nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep '\-\-check'" "Verified the operating system must detect unauthorized changes to software and information, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT detect unauthorized changes to software and information, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-38701 ###
resetRule "SV-50502r2_rule"
if [[ -z $(rpm -qa | grep -i tftp) ]]; then
	na "$rule" "rpm -qa | grep -i tftp" "Verified the "tftp" package is not installed, therefore the reference STIG is not Applicable"
else
	nonzero "$rule" "grep 'server_args' /etc/xinetd.d/tftp | grep -v '^\s*#' | grep '\-s'" "Verified the TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system,  therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the TFTP daemon does NOT operate in secure mode which provides access only to a single directory on the host file system,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-38702 ###
resetRule "SV-50503r2_rule"
if [[ -z $(rpm -qa | grep -i vsftpd) ]]; then
        na "$rule" "rpm -qa | grep -i vsftpd" "Verified the "vsftpd" package is not installed, therefore the reference STIG is not Applicable"
else
        nonzero "$rule" "grep xferlog_enable /etc/vsftpd/vsftpd.conf | grep -v '^\s*#' | grep -i yes" "Verified the FTP daemon IS configured for logging or verbose mode,  therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the FTP daemon is NOT configured for logging or verbose mode,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-43150 ###
resetRule "SV-55880r2_rule"
if [[ -z $(rpm -qa | grep GConf2) ]]; then
        na "$rule" "rpm -qa | grep GConf2" "Verified GConf2 package is not installed, therefore the reference STIG is NOT Applicable. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
        nonzero "$rule" "gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/disable_user_list | grep true" "Verified the login user list IS disabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the login user list is NOT disabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-51337 ###
resetRule "SV-65547r2_rule"
zero "$rule" "grep 'selinux=0' /boot/grub/grub.conf" "Verified the system must use a Linux Security Module at boot time, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a Linux Security Module at boot time, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-51363 ###
resetRule "SV-65573r1_rule"
nonzero "$rule" "grep -i 'SELINUX=' /etc/selinux/config | grep -v '^\s*#' | grep -i enforcing" "Verified the system must use a Linux Security Module configured to enforce limits on system services, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a Linux Security Module configured to enforce limits on system services, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-51369 ###
resetRule "SV-65579r1_rule"
nonzero "$rule" "grep -i 'SELINUXTYPE=' /etc/selinux/config | grep -v '^\s*#' | grep -i targeted" "Verified the system must use a Linux Security Module configured to limit the privileges of system services, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a Linux Security Module configured to limit the privileges of system services, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-51379 ###
resetRule "SV-65589r1_rule"
zero "$rule" "ls -RZ /dev | grep unlabeled_t" "Verified all device files must be monitored by the system Linux Security Module, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all device files are NOT monitored by the system Linux Security Module, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-51391 ###
resetRule "SV-65601r1_rule"
aidedir=$(grep DBDIR /etc/aide.conf | head -1 | awk '{print $NF}')
aidefile=$(grep 'database\s*=' /etc/aide.conf | awk -F/ '{print $NF}')

if [[ -f $aidedir/$aidefile ]]; then
	pass "$rule" "ls -l $aidedir/$aidefile" "Verified a file integrity baseline IS created, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "ls -l $aidedir/$aidefile" "Verified a file integrity baseline is NOT created, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-51875 ###
resetRule "SV-66089r2_rule"
nonzero "$rule" "grep pam_lastlog.so /etc/pam.d/system-auth | grep showfailed | grep -v silent" "Verified the operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system, upon successful logon/access, does NOT display to the user the number of unsuccessful logon/access attempts since the last successful logon/access, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-54381 ###
resetRule "SV-68627r3_rule"
nonzero "$rule" "grep admin_space_left_action /etc/audit/auditd.conf | grep -v '^\s*#' | grep -i 'single\|syslog\|suspend\|halt'" "Verified the audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT switch the system to single-user mode when available audit storage volume becomes dangerously low, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-57569 ###
resetRule "SV-71919r1_rule"
nonzero "$rule" "grep '\s/tmp' /etc/fstab | grep noexec" "Verified the noexec option IS added to the /tmp partition, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the noexec option is NOT added to the /tmp partition, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-58901 ###
resetRule "SV-73331r2_rule"
zero "$rule" "grep '^[^#]*NOPASSWD\|^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*" "Verified the sudo command requires authentication, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the sudo command does NOT require authentication, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72817 ###
resetRule "SV-87461r1_rule"
zero "$rule" "iwconfig" "Verified wireless network adapters are disabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified wireless network adapters are NOT disabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81441 ###
resetRule "SV-96155r2_rule"
nonzero "$rule" "grep -w \"adjtimex\" /etc/audit/audit.rules | grep 'b32\|b64' | grep -v "^\s*#" | wc -l | grep 2" "Verified the audit system IS configured to audit all attempts to alter system time through adjtimex, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system is NOT configured to audit all attempts to alter system time through adjtimex, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81443 ###
resetRule "SV-96157r1_rule"
nonzero "$rule" "/opt/isec/ens/threatprevention/bin/isectpdControl.sh status | grep '/running'" "Verified the Red Hat Enterprise Linux operating system must have an anti-virus solution installed, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT have an anti-virus solution installed, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81449 ###
resetRule "SV-96163r1_rule"
nonzero "$rule" "cat /etc/fstab | grep /dev/shm | grep noexec | grep -v '^\s*#'" "Verified the Red Hat Enterprise Linux operating system must mount /dev/shm with the noexec option, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT mount /dev/shm with the noexec option, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81445 ###
resetRule "SV-96159r1_rule"
nonzero "$rule" "cat /etc/fstab | grep /dev/shm | grep nodev | grep -v '^\s*#'" "Verified the Red Hat Enterprise Linux operating system must mount /dev/shm with the nodev option, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT mount /dev/shm with the nodev option, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81447 ###
resetRule "SV-96161r1_rule"
nonzero "$rule" "cat /etc/fstab | grep /dev/shm | grep nosuid | grep -v '^\s*#'" "Verified the Red Hat Enterprise Linux operating system must mount /dev/shm with the nosuid option, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT mount /dev/shm with the nosuid option, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-97229 ###
resetRule "SV-106367r1_rule"
nonzero "$rule" "cat /proc/sys/crypto/fips_enabled | grep 1" "Verified the Red Hat Enterprise Linux operating system must implement NIST FIPS-validated cryptography, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT implement NIST FIPS-validated cryptography, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-97231 ###
resetRule "SV-106369r1_rule"
nonzero "$rule" "grep -i macs /etc/ssh/sshd_config | grep -v '^#' | grep -i 'hmac-sha2-256.*hmac-sha2-512\|hmac-sha2-512.*hmac-sha2-256'" "Verified the SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon is NOT configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### End Checks ###
echo "End of Checks" >> /dev/tty

############### .ckl Footer ###############
# This Creates the necessary Footer for the output file to be .ckl compliant
echo "		</iSTIG>" >> $RESULTS
echo "	</STIGS>" >> $RESULTS
echo "</CHECKLIST>" >> $RESULTS
############### End .ckl Footer ##########

echo "" >> /dev/tty
echo "Script has finished" >> /dev/tty
exit
