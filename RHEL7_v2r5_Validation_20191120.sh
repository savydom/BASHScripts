#!/bin/bash
#
# RHEL 7 Content based on the RHEL7 V2R4 STIG
#
# Set current Version/Release # for this STIG Checklist script
cklVersion="V2R5"

#Set unclean variable. If set to 1, special characters won't be converted to the XML equivalent
if [[ "$(echo $1 | grep [Uu][Nn][Cc][Ll][Ee][Aa][Nn])" ]] || [[ "$(echo $2 | grep [Uu][Nn][Cc][Ll][Ee][Aa][Nn])" ]]; then
	unclean=1
fi

# We want to redirect all output (stdout and stderr to /tmp/RHEL_Lockdown.log
# Setup file descriptor 3 to point to stdout, we can use this if we need to output to the console
tempOut="/tmp/Validation_RHEL7_${cklVersion}.log"
exec 3>&1
exec 1>$tempOut 2>&1

# Create the result file
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESULTS="$DIR/Validation_RHEL7_${cklVersion}_Results.$HOSTNAME.$(date +%F_%H.%M)_XCCDF.ckl"

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
echo "					<SID_DATA>Red Hat Enterprise Linux 7 Security Technical Implementation Guide</SID_DATA>" >> $RESULTS
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

### V-71849 | RHEL-07-010010 ###
resetRule "SV-86473r4_rule"
nr "$rule" "$(for i in $(rpm -Va | egrep -i '^\.[M|U|G|.]{8}' | cut -d ' ' -f4,5);do for j in $(rpm -qf $i);do rpm -ql $j --dump | cut -d ' ' -f1,5,6,7 | grep $i;done;done)" "Check only. Usually the findings from this output are all either configuration files/logs (and therefore NOT system files or commands) or have STIG-related rights that are more restrictive than the vendor values. Format shows the default value followed by the actual settings on the server. If any non-system file or command is more permissive than the default permissions, this is a finding. If any not owned by the default owner or is not a member of the default group and is not documented with the Information System Security Officer (ISSO), this is a finding. Standard Verbiage: Verified the file permissions, ownership, and group membership of system files and commands match the vendor values, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-71855 | RHEL-07-010020 ###
resetRule "SV-86479r4_rule"
nr "$rule" "rpm -Va | grep '^..5'" "Check only. Verify the findings from this output contain no system files or binaries. Standard Verbiage: Verified the cryptographic hash of system files and commands match vendor values, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-71859 | RHEL-07-010030 ###
resetRule "SV-86483r4_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i 'banner-message-enable=true' /etc/dconf/db/local.d/* | grep -v '^#'" "Gnome is installed and warner banner is set correctly per the STIG" "Gnome is installed and warner banner is NOT set correctly per the STIG"
fi

### V-71861 | RHEL-07-010040 ###
resetRule "SV-86485r4_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
        na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
elif [[ -n "grep -i 'banner-message-text' /etc/dconf/db/local.d/* | grep -i 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.' | grep -i 'By using this IS (which includes any device attached to this IS), you consent to the following conditions:' | grep -i '-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.' | grep -i '-At any time, the USG may inspect and seize data stored on this IS.' | grep -i '-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.' | grep -i '-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.' | grep -i '-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'" ]]; then
	pass "$rule" "grep -i 'banner-message-text' /etc/dconf/db/local.d/*" "Gnome is installed and banner message is configured per the STIG"
else
	nr "$rule" "echo 'Manual review of banner text required.
	'; grep -i 'banner-message-text' /etc/dconf/db/local.d/*" "Gnome is installed, however, banner message will need to be manual verified"
fi

### V-71863 | RHEL-07-010050 ###
resetRule "SV-86487r3_rule"
if [[ -n "cat /etc/issue | grep 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.' | grep 'By using this IS (which includes any device attached to this IS), you consent to the following conditions:' | grep '-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.' | grep '-At any time, the USG may inspect and seize data stored on this IS.' | grep '-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.' | grep '-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.' | grep '-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'" ]]; then
	pass "$rule" "cat /etc/issue" "Verified the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nr "$rule" "cat /etc/issue" "Banner will need to be manual verified"
fi

### V-71891 | RHEL-07-010060 ###
resetRule "SV-86515r6_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i '^\s*lock-enabled' /etc/dconf/db/local.d/* | grep true" "GNOME is installed and lock enabled has been configured per the STIG" "GNOME is installed and lock enabled has NOT been configured per the STIG"
fi

### V-71893 | RHEL-07-010070 ###
resetRule "SV-86517r5_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i '^\s*idle-delay' /etc/dconf/db/local.d/* | awk -F '=' '\$2 >=900'" "GNOME is installed and idle delay has been configured per the STIG" "GNOME is installed and idle delay has NOT been configured per the STIG"
fi

### V-71895 | RHEL-07-010080 ###
# rule removed from STIG v2r2
#resetRule="SV-86519r4_rule"
#if [[ -z "$(yum list installed | grep gnome)" ]]; then
#	na "$rule" "yum list installed | grep gnome"
#else
#	nonzero "$rule" "egrep -i 'idle-delay' /etc/dconf/db/local.d/locks/* | grep screensaver"
#fi

### V-71897 | RHEL-07-010090 ###
##Works manually, but if it doesn't work automatically, print out $package and mark as NR
resetRule "SV-86521r3_rule"
nonzero "$rule" "rpm -q screen$'\n'rpm -q tmux | grep -iv 'not installed'" "Verified the operating system has the screen package installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT have the screen package installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71899 | RHEL-07-010100 ###
resetRule "SV-86523r5_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i '^\s*idle-activation-enabled=true' /etc/dconf/db/local.d/*" "GNOME is installed and idle timeout has been configured per the STIG" "GNOME is installed and idle timeout has NOT been configured per the STIG"
fi

### V-71901 | RHEL-07-010110 ###
resetRule "SV-86525r3_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -Ei '^\s*lock-delay=uint32\s+[1-5]' /etc/dconf/db/local.d/*" "GNOME is installed and verified a lock delay has been configured per the STIG" "GNOME is installed and verified a lock delay has NOT been configured per the STIG"
fi

### V-71903 | RHEL-07-010120 ###
resetRule "SV-86527r3_rule"
nonzero "$rule" "egrep -i '^\s*ucredit\s*=\s*-' /etc/security/pwquality.conf | grep -v '^#'" "Verified that when passwords are changed or new passwords are established, the new password must contain at least one upper-case character, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified that when passwords are changed or new passwords are established, the new password does NOT contain at least one upper-case character, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71905 | RHEL-07-010130 ###
resetRule "SV-86529r5_rule"
nonzero "$rule" "egrep -i '^\s*lcredit\s*=\s*-' /etc/security/pwquality.conf | grep -v '^#'" "Verified that when passwords are changed or new passwords are established, the new password must contain at least one lower-case character, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified that when passwords are changed or new passwords are established, the new password does NOT contain at least one lower-case character, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71907 | RHEL-07-010140 ###
resetRule "SV-86531r3_rule"
nonzero "$rule" "egrep -i '^\s*dcredit\s*=\s*-' /etc/security/pwquality.conf | grep -v '^#'" "Verified that when passwords are changed or new passwords are assigned, the new password must contain at least one numeric character, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified that when passwords are changed or new passwords are assigned, the new password does NOT contain at least one numeric character, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71909 | RHEL-07-010150 ###
resetRule "SV-86533r2_rule"
nonzero "$rule" "egrep -i '^\s*ocredit\s*=\s*-' /etc/security/pwquality.conf | grep -v '^#'" "Verifited that when passwords are changed or new passwords are assigned, the new password must contain at least one special character, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verifited that when passwords are changed or new passwords are assigned, the new password does NOT contain at least one special character, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71911 | RHEL-07-010160 ###
resetRule "SV-86535r2_rule"
nonzero "$rule" "egrep -i '^\s*difok' /etc/security/pwquality.conf |  grep -v '^#' | awk -F '=*' '\$2 >=8'" "Verified that when passwords are changed a minimum of eight of the total number of characters must be changed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified that when passwords are changed a minimum of eight of the total number of characters is NOT changed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71913 | RHEL-07-010170 ###
resetRule "SV-86537r2_rule"
nonzero "$rule" "egrep -i '^\s*minclass' /etc/security/pwquality.conf |  grep -v '^#' | awk -F '=*' '\$2 >=4'" "Verified that when passwords are changed a minimum of four character classes must be changed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified that when passwords are changed a minimum of four character classes is NOT changed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71915 | RHEL-07-010180 ###
resetRule "SV-86539r3_rule"
nonzero "$rule" "egrep -i '^\s*maxrepeat' /etc/security/pwquality.conf |  grep -v '^#' | awk -F '=*' '\$2 >0 && \$2 <4'" "Verified that when passwords are changed the number of repeating consecutive characters must not be more than three characters, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified that when passwords are changed the number of repeating consecutive characters is NOT more than three characters, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71917 | RHEL-07-010190 ###
resetRule "SV-86541r2_rule"
nonzero "$rule" "egrep -i '^\s*maxclassrepeat' /etc/security/pwquality.conf |  grep -v '^#' | awk -F '=*' '\$2 >0 && \$2 <=4'" "Verified that when passwords are changed the number of repeating characters of the same character class must not be more than four characters, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified that when passwords are changed the number of repeating characters of the same character class is NOT be more than four characters, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71919 | RHEL-07-010200 ###
resetRule "SV-86543r3_rule"
if [[ -z "$(egrep -i '^\s*password' /etc/pam.d/system-auth /etc/pam.d/password-auth |  egrep -e 'md5|sha256|bigcrypt|blowfish')" ]]; then
	nonzero "$rule" "egrep -i '^\s*password' /etc/pam.d/system-auth /etc/pam.d/password-auth| egrep -i 'sha512'" "Verified the PAM system service is configured to store only encrypted representations of passwords, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the PAM system service is NOT configured to store only encrypted representations of passwords, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	fail "$rule" "egrep -e 'md5|sha256|bigcrypt|blowfish' /etc/pam.d/system-auth /etc/pam.d/password-auth" "PAM password encryptions has not been configured correctly"
fi

### V-71921 | RHEL-07-010210 ###
resetRule "SV-86545r2_rule"
if [[ -z "$(egrep -i '^\s*encrypt' /etc/login.defs|  egrep -e 'des|md5|sha256')" ]]; then
	nonzero "$rule" "egrep -i '^s*encrypt' /etc/login.defs | egrep -i 'sha512'" "Verified the shadow file is configured to store only encrypted representations of passwords, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the shadow file is NOT configured to store only encrypted representations of passwords, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	fail "$rule" "egrep -e 'des|md5|sha256' /etc/login.defs" "login.defs has not been configured per the STIG"
fi

### V-71923 | RHEL-07-010220 ###
resetRule "SV-86547r3_rule"
if [[ -z "$(grep -iB 20 \"^\s*crypt_style\s*=\s*sha512\" /etc/libuser.conf | grep -v  '^#' | grep -v '^$' | awk '/crypt/ || /defaults/' | grep '\[defaults\]')" ]]; then
	nonzero "$rule" "grep -iB 20 \"^\s*crypt_style\s*=\s*sha512\" /etc/libuser.conf | grep -v  '^#' | grep -v '^$' | awk '/crypt/ || /defaults/'" "Verified user and group account administration utilities are configured to store only encrypted representations of passwords, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified user and group account administration utilities are NOT configured to store only encrypted representations of passwords, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	#Manual inspection of rule to ensure that the crypt_style = sha512 setting exists AND is in the [defaults] region
	nr "$rule" "grep -iB 20 \"^\s*crypt_style\s*=\s*sha512\" /etc/libuser.conf | grep -v  '^#' | grep -v '^$'" "Manual inspection of rule to ensure that the crypt_style = sha512 setting exists AND is in the [defaults] region"
fi

### V-71925 | RHEL-07-010230 ###
resetRule "SV-86549r2_rule"
nonzero "$rule" "egrep '^\s*PASS_MIN_DAYS' /etc/login.defs | grep -v '^#' | awk '\$2 >=1'" "Verified passwords for new users are restricted to a 24 hours/1 day minimum lifetime, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified passwords for new users are NOT restricted to a 24 hours/1 day minimum lifetime, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71927 | RHEL-07-010240 ###
## Manual inspection of output needed as "If any results are returned that are not associated with a system account, this is a finding."
resetRule "SV-86551r2_rule"
nr "$rule" "awk -F: '\$4 < 1 {print \$1}' /etc/shadow" "Check only. Verify all returned results that do not have a "1" on them are associated with system accounts. Standard Verbiage: Verified passwords are restricted to a 24 hours/1 day minimum lifetime, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-71929 | RHEL-07-010250 ###
resetRule "SV-86553r2_rule"
nonzero "$rule" "egrep '^\s*PASS_MAX_DAYS' /etc/login.defs | grep -v '^#' | awk '\$2 <=60'" "Verified passwords for new users are restricted to a 60-day maximum lifetime, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified passwords for new users are NOT restricted to a 60-day maximum lifetime, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71931 | RHEL-07-010260 ###
## Manual inspection of output needed as "If any results are returned that are not associated with a system account, this is a finding."
resetRule "SV-86555r3_rule"
nr "$rule" "awk -F: '\$5 >60 {print \$1}' /etc/shadow" "Verify all returned results with a number higher than 60 are associated with system accounts. Standard Verbiage: Verified existing passwords are restricted to a 60-day maximum lifetime, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-71933 | RHEL-07-010270 ###
resetRule "SV-86557r3_rule"
nonzero "$rule" "egrep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth | egrep -i 'pam_pwhistory.so' | awk -F '=' '\$2 >= 5 {print;}'" "Verified passwords must be prohibited from reuse for a minimum of five generations, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified passwords are NOT prohibited from reuse for a minimum of five generations, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71935 | RHEL-07-010280 ###
resetRule "SV-86559r2_rule"
nonzero "$rule" "egrep -i '^\s*minlen' /etc/security/pwquality.conf |  grep -v '^#' | awk -F '=*' '\$2 >=15'" "Verified passwords are a minimum of 15 characters in length, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified passwords are NOT a minimum of 15 characters in length, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71937 | RHEL-07-010290 ###
resetRule "SV-86561r3_rule"
zero "$rule" "egrep -i nullok /etc/pam.d/system-auth-ac /etc/pam.d/password-auth" "Verified the system does not have accounts configured with blank or null passwords, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES have accounts configured with blank or null passwords, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71939 | RHEL-07-010300 ###
resetRule "SV-86563r3_rule"
nonzero "$rule" "grep -i \"PermitEmptyPasswords\" /etc/ssh/sshd_config | egrep -i \"no|#P\"" "Verified the SSH daemon does not allow authentication using an empty password, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon DOES allow authentication using an empty password, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71941 | RHEL-07-010310 ###
resetRule "SV-86565r2_rule"
nonzero "$rule" "egrep -i '^\s*inactive' /etc/default/useradd |  grep -v '^#' | grep -i '0'" "Verified the operating system disables account identifiers (individuals, groups, roles, and devices) if the password expires, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT disable account identifiers (individuals, groups, roles, and devices) if the password expires, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71943 | RHEL-07-010320 ###
resetRule "SV-86567r5_rule"
echo "Check $rule"
countpw="$(grep -Ewc '^auth.*pam_faillock.so.*unlock_time=.*' /etc/pam.d/password-auth | grep -v '^#')"
countsys="$(grep -Ewc '^auth.*pam_faillock.so.*unlock_time=*' /etc/pam.d/system-auth | grep -v '^#')"

if [[( $countpw<2 || $countsys <2)]]; then
	fail "$rule" "less than 2 auth lines found with pam.faillock.so in either system-auth or password-auth"
else
	for i in $( grep -Ew '^auth.*pam_faillock.so.*unlock_time=.*' /etc/pam.d/password-auth | grep -v '^#' | awk -F 'unlock_time=' '{print $2}' ); do 
		if [[ ($i=0 || $i>=900) ]]; then
			echo "PW ($i=0 || $i>=900)"
		else
			echo "PW ($i>0 && $i<900)"
			if [[ -z "$(grep -E '^auth.*unlocktime=never' /etc/pam.d/password-auth)" ]]; then
				fail "$rule" "unlock_time lines in password-auth found not set to never, 0, or >900"
				break
			else
				echo "PW ($i=never)"
			fi
		fi
		
		countpw=$(($countpw-1))
		
		if [[ ($countpw == 0) ]]; then
			break
		else
			continue
		fi
	done
	
	for i in $(grep -Ew '^auth.*pam_faillock.so.*unlock_time=.*' /etc/pam.d/system-auth | grep -v '^#' | awk -F 'unlock_time=' '{print $2}'); do 
		if [[ $i=0 || $i>=900 ]]; then
			echo "Sys ($i=0 || $i>=900)"
		else
			echo "Sys ($i>0 && $i<900)"
			if [[ -z "$(grep -E '^auth.*unlocktime=never' /etc/pam.d/system-auth)" ]]; then
				fail "$rule" "unlock_time lines in system-auth found not set to never, 0, or >900"
				break
			else
				echo "Sys ($i=never)"
			fi
		fi
		
		countsys=$(($countsys-1))
		
		if [[ ($countsys==0) ]]; then
			pass "$rule" "grep pam_faillock.so /etc/pam.d/system-auth" "Verified accounts subject to three unsuccessful login attempts within 15 minutes are locked for the maximum configurable period, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
			break
		else
			continue
		fi
	done
fi

### V-71945 | RHEL-07-010330 ###
resetRule "SV-86569r4_rule"
nonzero "$rule" "grep 'pam_faillock.so.*even_deny_root' /etc/pam.d/password-auth /etc/pam.d/system-auth | grep -v '^#' | wc -l |  awk -F ' ' '\$1 >=4'" "Verified if three unsuccessful root logon attempts within 15 minutes occur the associated account will be locked, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified if three unsuccessful root logon attempts within 15 minutes occur the associated account will NOT be locked, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71947 | RHEL-07-010340 ###
resetRule "SV-86571r3_rule"
set +H
zero "$rule" "egrep \"^[^#]*NOPASSWD\" /etc/sudoers /etc/sudoers.d/*" "Please note that accounts/groups connecting to the system that will use sudo use key authentication and not passwords, and, per the Check Content, for those accounts/groups this STIG item is Not Applicable. The local accounts, such as those in the eng group, should be the only ones that need the NOPASSWD tag removed from them. Standard Verbiage: Verified users must provide a password for privilege escalation, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Please note that accounts/groups connecting to the system that will use sudo use key authentication and not passwords, and, per the Check Content, for those accounts/groups this STIG item is Not Applicable. The local accounts, such as those in the eng group, should be the only ones that need the NOPASSWD tag removed from them. Standard Verbiage: Verified users must provide a password for privilege escalation, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
set -H

### V-71949 | RHEL-07-010350 ###
resetRule "SV-86573r3_rule"
set +H
zero "$rule" "egrep \"^[^#]*!authenticate\" /etc/sudoers /etc/sudoers.d/*" "Verified users must re-authenticate for privilege escalation, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified users do NOT re-authenticate for privilege escalation, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
set -H

### V-71951 | RHEL-07-010430 ###
resetRule "SV-86575r2_rule"
nonzero "$rule" "egrep -i '^\s*fail_delay' /etc/login.defs |  grep -v '^#' | awk -F ' ' '\$2 >=4'" "Verified the delay between logon prompts following a failed console logon attempt are at least four seconds, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the delay between logon prompts following a failed console logon attempt is NOT at least four seconds, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71953 | RHEL-07-010440 ###
resetRule "SV-86577r2_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i '^\s*automaticloginenable=false' /etc/gdm/custom.conf* | grep -v '^#'" "GNOME is installed and automatic login has been disabled" "GNOME is installed and automatic login has NOT been disabled"
fi

### V-71955 | RHEL-07-010450 ###
resetRule "SV-86579r3_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i '^\s*timedloginenable=false' /etc/gdm/custom.conf* | grep -v '^#'" "GNOME is installed and timed login has been disabled" "GNOME is installed and timed login has NOT been disabled"
fi

### V-71957 | RHEL-07-010460 ###
resetRule "SV-86581r3_rule"
nonzero "$rule" "grep -i '^\s*PermitUserEnvironment no' /etc/ssh/sshd_config | grep -v '^#' " "Verified the operating system does not allow users to override SSH environment variables, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system DOES allow users to override SSH environment variables, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71959 | RHEL-07-010470 ###
resetRule "SV-86583r3_rule"
nonzero "$rule" "grep -i '^\s*HostbasedAuthentication no' /etc/ssh/sshd_config | grep -v '^#' " "Verified the operating system does not allow a non-certificate trusted host SSH logon to the system, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system DOES allow a non-certificate trusted host SSH logon to the system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71961 | RHEL-07-010480 ###
resetRule "SV-86585r6_rule"
if [[ -d /sys/firmware/efi ]]; then
	#Using EFI/UEFI
	na "$rule" "EFI/UEFI in use" "EFI/UEFI in use"
else
		#Using BIOS
	if [[ -n "$(echo "$RHELverNumb" | grep -Eo '7.[2-9]')" ]]; then
		na "$rule" "$HOSTNAME is running RHEL $RHELverNumb. This requirement is Not Applicable." "Verified the systems is running RHEL 7.2 or newer, therefore this is Not Applicable."
	else
		nonzero "$rule" "grep -Ei 'password_pbkdf2\s+root' /boot/grub2/grub.cfg" "Grub password has been configured" "Grub password has NOT been configured"
	fi	
fi

### V-71963 | RHEL-07-010490 ###
resetRule "SV-86587r4_rule"
if [[ -d /sys/firmware/efi ]]; then
	#Using EFI/UEFI
	if [[ -n "$(echo "$RHELverNumb" | grep -Eo '7.[2-9]')" ]]; then
		na "$rule" "echo \"Redhat Version: $RHELverNumb\"" "Verified the systems is running RHEL 7.2 or newer, therefore this is Not Applicable."
	else	
		nonzero "$rule" "grep -i '^\s*password_pbkdf2\s+root' /boot/efi/EFI/redhat/grub.cfg" "Grub password has been configured" "Grub password has NOT been configured"
	fi
else
	#Using BIOS
	na "$rule" "echo 'System is using BIOS: this check is NA.
	'; ls -l /sys/firmware/efi" "Verified the system uses BIOS, therefore this is Not Applicable."
fi

### V-71965 | RHEL-07-010500 ###
resetRule "SV-86589r2_rule"
if [[ -n "$(authconfig --test | grep -i '^\s*pam_pkcs11 is enabled')" ]]; then
	if [[ -z "$(authconfig --test | grep -i '^\s*smartcard module = \n')" ]]; then
		zero "$rule" "authconfig --test | grep -i '^\s*smartcard removal action = \n'" "Smartcard authentication has been configured per the STIG" "Smartcard authentication has NOT been configured per the STIG"
	else
		fail "$rule" "authconfig --test | grep -i '^\s*smartcard module = \n'" 'Check Only. Open Finding. Standard Verbiage: Smartcard and smartcard removal actions are not blank. This server is a VM which does not, and cannot, have a smartcard reader installed onto it. Instead authentication to the system is achieved either through the VMWare console (only used for local admistrative access and locked down through mulitple layers of rights and privildeges as well as being locked to smartcard passthrough authentication itself, therefore providing multiple layers of multi-factor authentication) or through ssh. We are currently working on a process for utilizing key authentication through a smartcard or the use of Kerberos tickets to ensure multi-factor authentication to the server. Commentary sent 4/4/17 to DISA explaining how we are at a loss as to how this would even be possible to implement on a virtual server. The settings in question require a smartcard reader that is physically connected to the server (which is accessed through a PAM module library), which is simply not possible on a VM. We could implement or require Token authentication through SSH, which could be from the smartcard token or possibly through the use of a Kerberos ticket created by smartcard authentication done on the originating system (for our site that would be through Citrix or a local workstation that is smartcard authenticated to an AD domain, whether through SSH from there or to the VMWare console.) DISAs response (Brian Snodgrass, 4/4/17): "RHEL-07-010500 has been required by USCYBERCOM for several years and the STIG Signing authority is no longer allowing UNIX/Linux operating system STIGs to not include how to deploy the capability. If you cannot implement smartcards your Authorizing Official will have to accept the risk." Based on this response we are leaving this item open but we expect our efforts to implement passthrough PKI or Kerberos authentication methods will provide mitigating factors for this item. Follow-up sent to DISA (Mr. Snodgrass) on 4/4/17 as follows: "Just one more comment on the below, if you dont mind: You wrote: "RHEL-07-010500 has been required by USCYBERCOM for several years and the STIG Signing authority is no longer allowing UNIX/Linux operating system STIGs to not include how to deploy the capability. If you cannot implement smartcards your Authorizing Official will have to accept the risk." I think my suggestion here is that the check, as currently written, locks in a single solution for smartcard authentication, one that requires a physical card-reader attached to the system in question. Perfectly implementable for workstations, for example, but on a virtual server thats not possible. Instead we have to utilize other methods, such as forcing only key authentication through SSH (or for sites with web servers you can set up smartcard authentication that way, but that is handled by the appropriate application STIG rather than the OS STIG anyway). So, for example, some kind of check that might add the following text: ---  For systems which do not have the ability to include hardware smart card readers and the only access is through SSH, multifactor authentication usage can be checked with the following: # grep -I PasswordAuthentication /etc/ssh/sshd_config -- PasswordAuthentication no If the "PasswordAuthentication" setting is missing, commented out, or not set to "no", this is a finding. --- Arguably that could be a separate STIG item on its own and arguably configuring and using GSSAPI for Kerberos authentication would also be an acceptable replacement for this (although a couple of other STIG items do discourage that method by requiring those item not be configured "unless needed"), in which case simply replacing the final sentence in the Check Content, if at all possible, would be very helpful in dealing with auditors: "If smartcard authentication is disabled or the smartcard and smartcard removal actions are blank, or there is no other approved, verified method for enforcing multifactor authentication documented with the ISSO, this is a finding." That kind of wording is similar to allowing sites the flexibility to use Splunk instead of rsyslog, for example. I know it may be a long shot asking for that, but even that kind of simple wording change goes a LONG way to how the DoN has decided we need to strictly implement the STIG "guidelines", unfortunately." DISAs response (Brian Snodgrass, 4/4/17): "Ill take your comments into consideration for the requirement. The one thing that you have to remember about UNIX/Linux STIGs is that there are several different ways to meet some requirements - log rotation using splunk/rsyslog is just one example. I couldnt put splunk in as a way to meet the requirement(s) as the Red Hat rep that I was working with would object that its not a core Red Hat operating system application. A lot of the political nature of this STIG came down to those kinds of discussions. In several cases I am collecting input from the field to modify requirements so that when the Red Hat rep makes the statement that Ive made a change we did not agree on I can make my argument as to why I changed the check/fix."'

	fi
else
	fail "$rule" "authconfig --test | grep -i '^\s*pam_pkcs11 is enabled'" 'Check Only. Open Finding. Standard Verbiage: Smartcard and smartcard removal actions are not blank. This server is a VM which does not, and cannot, have a smartcard reader installed onto it. Instead authentication to the system is achieved either through the VMWare console (only used for local admistrative access and locked down through mulitple layers of rights and privildeges as well as being locked to smartcard passthrough authentication itself, therefore providing multiple layers of multi-factor authentication) or through ssh. We are currently working on a process for utilizing key authentication through a smartcard or the use of Kerberos tickets to ensure multi-factor authentication to the server. Commentary sent 4/4/17 to DISA explaining how we are at a loss as to how this would even be possible to implement on a virtual server. The settings in question require a smartcard reader that is physically connected to the server (which is accessed through a PAM module library), which is simply not possible on a VM. We could implement or require Token authentication through SSH, which could be from the smartcard token or possibly through the use of a Kerberos ticket created by smartcard authentication done on the originating system (for our site that would be through Citrix or a local workstation that is smartcard authenticated to an AD domain, whether through SSH from there or to the VMWare console.) DISAs response (Brian Snodgrass, 4/4/17): "RHEL-07-010500 has been required by USCYBERCOM for several years and the STIG Signing authority is no longer allowing UNIX/Linux operating system STIGs to not include how to deploy the capability. If you cannot implement smartcards your Authorizing Official will have to accept the risk." Based on this response we are leaving this item open but we expect our efforts to implement passthrough PKI or Kerberos authentication methods will provide mitigating factors for this item. Follow-up sent to DISA (Mr. Snodgrass) on 4/4/17 as follows: "Just one more comment on the below, if you dont mind: You wrote: "RHEL-07-010500 has been required by USCYBERCOM for several years and the STIG Signing authority is no longer allowing UNIX/Linux operating system STIGs to not include how to deploy the capability. If you cannot implement smartcards your Authorizing Official will have to accept the risk." I think my suggestion here is that the check, as currently written, locks in a single solution for smartcard authentication, one that requires a physical card-reader attached to the system in question. Perfectly implementable for workstations, for example, but on a virtual server thats not possible. Instead we have to utilize other methods, such as forcing only key authentication through SSH (or for sites with web servers you can set up smartcard authentication that way, but that is handled by the appropriate application STIG rather than the OS STIG anyway). So, for example, some kind of check that might add the following text: ---  For systems which do not have the ability to include hardware smart card readers and the only access is through SSH, multifactor authentication usage can be checked with the following: # grep -I PasswordAuthentication /etc/ssh/sshd_config -- PasswordAuthentication no If the "PasswordAuthentication" setting is missing, commented out, or not set to "no", this is a finding. --- Arguably that could be a separate STIG item on its own and arguably configuring and using GSSAPI for Kerberos authentication would also be an acceptable replacement for this (although a couple of other STIG items do discourage that method by requiring those item not be configured "unless needed"), in which case simply replacing the final sentence in the Check Content, if at all possible, would be very helpful in dealing with auditors: "If smartcard authentication is disabled or the smartcard and smartcard removal actions are blank, or there is no other approved, verified method for enforcing multifactor authentication documented with the ISSO, this is a finding." That kind of wording is similar to allowing sites the flexibility to use Splunk instead of rsyslog, for example. I know it may be a long shot asking for that, but even that kind of simple wording change goes a LONG way to how the DoN has decided we need to strictly implement the STIG "guidelines", unfortunately." DISAs response (Brian Snodgrass, 4/4/17): "Ill take your comments into consideration for the requirement. The one thing that you have to remember about UNIX/Linux STIGs is that there are several different ways to meet some requirements - log rotation using splunk/rsyslog is just one example. I couldnt put splunk in as a way to meet the requirement(s) as the Red Hat rep that I was working with would object that its not a core Red Hat operating system application. A lot of the political nature of this STIG came down to those kinds of discussions. In several cases I am collecting input from the field to modify requirements so that when the Red Hat rep makes the statement that Ive made a change we did not agree on I can make my argument as to why I changed the check/fix."'
fi


### V-71967 | RHEL-07-020000 ###
resetRule "SV-86591r2_rule"
zero "$rule" "rpm -q rsh-server | grep -iv \"package.*is not installed\"" "Verified the rsh-server package is not installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rsh-server package IS installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71969 | RHEL-07-020010 ###
resetRule "SV-86593r2_rule"
zero "$rule" "rpm -q ypserv | grep -iv \"package.*is not installed\"" "Verified the ypserv package is not installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the ypserv package IS installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71971 | RHEL-07-020020 ###
# Manual inspection - requires analyst to reconcile users against a local site list.
resetRule "SV-86595r2_rule"
nr "$rule" "semanage login -l" "Verify that all administrators are mapped to the "sysadm_u" or "staff_u" users role and that all authorized non-administrative users are mapped to the "user_u" role. Standard Verbiage: Verified the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-71973 | RHEL-07-020030 ###
# Manual inspection - Tools other than AIDE are permitted per STIG text. Aide is only used as an example.
# nonzero "RHEL-07-020130_rule" "grep aide /etc/crontab /etc/cron.*/* | egrep \"[0-9]*\s[0-9]*\s\*\s\*\s[0-7]|[0-9]*\s[0-9]*\s\*\s\*\s\*|[0-9]*\s\*\s\*\s\*\s\*\" | grep -v ^#"
resetRule "SV-86597r2_rule"
if [[ -n "$(yum list installed | grep aide)" ]]; then
	nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep '\-\-check' | awk -F ':' '{print $1}' | grep -v monthly | grep -v '^#'" "Verified a file integrity tool verifies the baseline operating system configuration at least weekly, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified a file integrity tool does NOT verify the baseline operating system configuration at least weekly, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	nr "$rule" "echo 'Manual inspection required.
	'; yum list installed | grep aide"
fi

### V-71975 | RHEL-07-020040 ###
# Manual inspection - Tools other than AIDE are permitted per STIG text. Aide is only used as an example.
resetRule "SV-86599r2_rule"
if [[ -n "$(yum list installed | grep aide)" ]]; then
#AIDE installed, check crontab script file
	nonzero "$rule" "grep aide /etc/crontab /etc/cron.*/* /var/spool/cron/root | grep 'mail' | grep -v '^#'" "Verified designated personnel are notified if baseline configurations are changed in an unauthorized manner, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified designated personnel are NOT notified if baseline configurations are changed in an unauthorized manner, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	#AIDE is not installed. Manual review required.
	nr "$rule" "yum list installed | grep aide"
fi

### V-71977 | RHEL-07-020050 ###
resetRule "SV-86601r2_rule"
nonzero "$rule" "grep \"^gpgcheck\s*=\s*1\" /etc/yum.conf | grep -v '^#'" "Verified the operating system prevents the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71979 | RHEL-07-020060 ###
resetRule "SV-86603r2_rule"
nonzero "$rule" "grep \"^localpkg_gpgcheck\s*=\s*1\" /etc/yum.conf | grep -v '^#'" "Verified the operating system prevents the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71981 | RHEL-07-020070 ###
#Removed in v2r1
#resetRule="SV-86605r2_rule"
#nonzero "$rule" "grep \"^repo_gpgcheck=\s*1\" /etc/yum.conf | grep -v '^#' "

### V-71983 | RHEL-07-020100 ###
# May need to make this manual - if HBSS is configured on the system w/ DCM and DLP the check is NA
# alternatively, if the check check below fails, the local ISSO can document as permissable.
resetRule "SV-86607r4_rule"
nonzero "$rule" "grep -i 'blacklist usb-storage\|install usb-storage /bin/true' /etc/modprobe.d/blacklist.conf /etc/modprobe.d/usb-storage.conf | grep -v '^#' | wc -l | awk '\$0 > 1'" "Verified USB mass storage is disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified USB mass storage is NOT disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71985 | RHEL-07-020110 ###
# May need to make this manual if the check check below fails, the local ISSO can document as permissable.
resetRule "SV-86609r2_rule"
if [[ -z "$(systemctl status autofs | grep running)" ]]; then
	pass "$rule" "systemctl status autofs" "Verified the Red Hat Enterprise Linux operating system disables the file system automounter unless required, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	pass "$rule" "systemctl status autofs" "autofs status is set to active, however it is documented with the Information System Security Officer (ISSO) that this is an operational requirement, therefore the reference STIG is not a finding.  Engineer did NOT apply a change."
fi

### V-71987 | RHEL-07-020200 ###
resetRule "SV-86611r2_rule"
nonzero "$rule" "grep -i '^\s*clean_requirements_on_remove' /etc/yum.conf | grep -v '^#' | egrep -i '1|true|yes'" "Verified the operating system removes all software components after updated versions have been installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT remove all software components after updated versions have been installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71989 | RHEL-07-020210 ###
# May need to make this manual, if HBSS or HIPS is active this is NA.
resetRule "SV-86613r3_rule"
if [[ -n "$(rpm -qa | grep MFEhiplsm)" ]]; then
	#McAfee HIPS installed
	if [[ -n "$(ps -ef | grep -i 'hipclient')" ]]; then
		#it's an active process
		na "$rule" "echo 'McAFEE HIPS is installed and active. This check is not applicable
		'; ps -ef | grep -i 'hipclient'" "McAFEE HIPS is installed and active. This check is not applicable"
	else
		#installed but inactive
		nonzero "$rule" "getenforce | grep -i enforcing" "Verified the operating system has enabled SELinux, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT have SELinux enabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
else
	#not installed
	nonzero "$rule" "getenforce | grep -i enforcing" "Verified the operating system has enabled SELinux, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT have SELinux enabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-71991 | RHEL-07-020220 ###
# May need to make this manual, if HBSS or HIPS is active this is NA.
resetRule "SV-86615r5_rule"
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

### V-71993 | RHEL-07-020230 ###
#NOTE, this will not give results. Find a way to escalate
# so that this is not blocked.
resetRule "SV-86617r5_rule"
nonzero "$rule" "systemctl status ctrl-alt-del.target | grep dead" "Verified the x86 Ctrl-Alt-Delete key sequence is disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the x86 Ctrl-Alt-Delete key sequence is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71995 | RHEL-07-020240 ###
resetRule "SV-86619r2_rule"
zero "$rule" "grep -i umask /etc/login.defs | grep -v ^# | grep -iv \"umask\s*077\"" "Verified the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT define default permissions for all authenticated users in such a way that the user can only read and modify their own files, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-71997 | RHEL-07-020250 ###
resetRule "SV-86621r5_rule"
case "$RHELverNumb" in
	'7.9'|'7.8'|'7.7')
		pass "$rule" "RHEL Version $RHELverNumb is not EoL" "Verified the operating system is a supported release, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		;;
	'7.6')
		if [[ "$(date +'%Y%m%d')" -gt "20201031" ]]; then
			fail "$rule" "RHEL Version $RHELverNumb is EoL"
		else
			pass "$rule" "RHEL Version $RHELverNumb is not EoL" "Verified the operating system is a supported release, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		fi	
		;;
	'7.5')
		if [[ "$(date +'%Y%m%d')" -gt "2020430" ]]; then
			fail "$rule" "RHEL Version $RHELverNumb is EoL"
		else
			pass "$rule" "RHEL Version $RHELverNumb is not EoL" "Verified the operating system is a supported release, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		fi	
		;;
	'7.4')
		if [[ "$(date +'%Y%m%d')" -gt "20190831" ]]; then
			fail "$rule" "RHEL Version $RHELverNumb is EoL"
		else
			pass "$rule" "RHEL Version $RHELverNumb is not EoL" "Verified the operating system is a supported release, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		fi	
		;;		
	*)
		fail "$rule" "RHEL Version $RHELverNumb is EoL"
		;;
esac
		

### V-71999 | RHEL-07-020260 ###
# Manual inspection - will need to lookup if returned results are at supported versions.
resetRule "SV-86623r4_rule"
nr "$rule" "echo '#Manual Inspection Required
'; yum history list;" "Verify the latest patches were applied within the last 4 weeks. Standard Verbiage: Verified vendor packaged system security patches and updates are installed and up to date, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-72001 | RHEL-07-020270 ###
# Manual inspection - will need to lookup listed accounts against local ISSO List
resetRule "SV-86625r2_rule"
nr "$rule" "echo '#Manual Inspection Required
'; cat /etc/passwd;" "Verify the accounts on the system match the provided documentation or are accounts that support an authorized system function. Standard Verbiage: Verified the system does not have unnecessary accounts, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-72003 | RHEL-07-020300 ###
resetRule "SV-86627r2_rule"
zero "$rule" "pwck -rq | grep -i 'no group'" "Verified all Group Identifiers (GIDs) referenced in the /etc/passwd file are defined in the /etc/group file, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all Group Identifiers (GIDs) referenced in the /etc/passwd file are NOT defined in the /etc/group file, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72005 | RHEL-07-020310 ###
resetRule "SV-86629r2_rule"
zero "$rule" "awk -F: '(\$3 == 0) {print}' /etc/passwd | grep -v '^root'" "Verified the root account isthe only account having unrestricted access to the system, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the root account is NOT the only account having unrestricted access to the system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72007 | RHEL-07-020320 ###
resetRule "SV-86631r3_rule"
zero "$rule" "find / -fstype xfs -nouser" "Verified all files and directories have a valid owner, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all files and directories do NOT have a valid owner, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72009 | RHEL-07-020330 ###
resetRule "SV-86633r3_rule"
zero "$rule" "find / -fstype xfs -nogroup" "Verified all files and directories have a valid group owner, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all files and directories do NOT have a valid group owner, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72011 | RHEL-07-020600 ###
# PEER REVIEW NEEDED
# This mini script does the following 
# 1 - initalize counter set to the number of interactive users
#		ASSUMPTION: Interactive users are those whose shell is not set to nologin, false, sync, shutdown or halt
# 2 - creates a for loop, based on the number of interactive users detected
# 3 - the user's home directory is checked to ensure it exists
# 3a -	if it does not exist, the loop is broken and a fail result is generated
# 3b - if it exists, decrease the counter by 1, and continue
# 4 - check to see if the counter has gotten to 0
# 4a - if counter has reached 0, the loop is broken and a pass result is generated
# 4b - if count has not reached 0, start next iteration

resetRule "SV-86635r2_rule"
echo "Check $rule"
count="$(cut -d: -f 1,6,7 /etc/passwd | grep -vic 'nologin\|false\|sync\|shutdown\|halt\|splunk')"
for i in $(cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '{print $2}'); do 
	if [[ ! -e "$i" ]]; then 
		fail "$rule" "echo \"\$(echo \$i)  does not exist \""
		break
	else
		count=$(($count-1))
	fi

	if [[ ("$count" == "0") ]]; then
		pass "$rule" "cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt' | awk -F: '{print \$2}'" "Verified all local interactive users have a home directory assigned in the /etc/passwd file, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done
	
### V-72013 | RHEL-07-020610 ###
resetRule "SV-86637r2_rule"
nonzero "$rule" "grep -i '^\s*create_home' /etc/login.defs | grep -v '^#' | grep -i yes" "Verified all local interactive user accounts, upon creation, are assigned a home directory, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all local interactive user accounts, upon creation, are NOT assigned a home directory, therefore the reference STIG IS a finding."

### V-72015 | RHEL-07-020620 ###
# Note - 020620 and 020640 appear (to me) to be checking the same thing; but with a different
# first step in the check (020620 starts with pwck -r, but then goes and validates /etc/passwd as in 20640). 
# I've resused the same script for both.

resetRule "SV-86639r2_rule"
echo "Check $rule"
count="$(cut -d: -f 1,6,7 /etc/passwd | grep -vic 'nologin\|false\|sync\|shutdown\|halt\|splunk')"
for i in $(cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '{print $2}'); do 
	if [[ ! -e "$i" ]]; then 
		fail "$rule" "echo '\$i \" does not exist\" '"
		break
	else
		count=$(($count-1))
	fi

	if [[ ("$count" == "0") ]]; then
		pass "$rule" "cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '{print \$2}'" "Verified all local interactive user home directories defined in the /etc/passwd file exist, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done

### V-72017 | RHEL-07-020630 ###
resetRule "SV-86641r3_rule"
echo "Check $rule"
count="$(cut -d: -f 1,6,7 /etc/passwd | grep -vic 'nologin\|false\|sync\|shutdown\|halt\|splunk')"
for i in $(cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '{print $2}'); do 
	if [[ -n "$(stat -c '%n %a' $i |  awk '$2 > 750 {print}')" ]]; then 
		fail "$rule" "stat -c '%n %a' $i  "
		break
	else
		count=$(($count-1))
	fi

	if [[ ("$count" == "0") ]]; then
		pass "$rule" "cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '{print \$2}'" "Verified all local interactive user home directories have mode 0750 or less permissive, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done

### V-72019 | RHEL-07-020640 ###
resetRule "SV-86643r5_rule"
echo "Check $rule"
count="$(cut -d: -f 1,6,7 /etc/passwd | grep -vic 'nologin\|false\|sync\|shutdown\|halt\|splunk')"
for i in $(cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '{print $1 ":" $2}'); do 
	OWNER=$(echo $i | awk -F: '{print $1}')
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
				
	if [[ "$OWNER" != $(stat -c %U "$HOMEDIR") ]]; then 
		fail "$rule" $i 
		break
	else
		count=$(($count-1))
	fi

	if [[ ("$count" == "0") ]]; then
		pass "$rule" "Each interactive user owns their own home directory" "Verified all local interactive user home directories are owned by their respective users, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done

### V-72021 | RHEL-07-020650 ###
resetRule "SV-86645r5_rule"
echo "Check $rule"
count="$(cut -d: -f 1,6,7 /etc/passwd | grep -vic 'nologin\|false\|sync\|shutdown\|halt\|splunk')"
for i in $(cut -d: -f 1,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '{print $1 ":" $2}'); do 
	OWNER=$(echo $i | awk -F: '{print $1}')
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
				
	if [[ $(id -g "$OWNER") != $(stat -c %g "$HOMEDIR") ]]; then 
		fail "$rule" $i 
		break
	else
		count=$(($count-1))
	fi

	if [[ ("$count" == "0") ]]; then
		pass "$rule" "Each interactive user home dir is gowned by its respective user" "Verified all local interactive user home directories are group-owned by the home directory owners primary group, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done


### V-72023 | RHEL-07-020660### 
resetRule "SV-86647r2_rule"
echo "Check $rule"
declare -A output
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do 
	OWNER=$(echo $i | awk -F: '{print $1}')
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
				
	count2="$(find "$HOMEDIR" -print | xargs stat -c '%U' | wc -l)"
	for c in $(find "$HOMEDIR" -print | xargs stat -c '%U%n'); do
		if [[ "$OWNER" != "$(echo $c | awk -F"/" '{print $1}')" ]]; then
			output="$output $(echo $c | sed 's/\//:\//')"
			fail "$rule" "$(echo ${output[@]})" "Any files listed are not owned by the owner of the listed home directory. To be complaint the ownership will need to be changed on those files. Verified the Red Hat Enterprise Linux operating system is NOT configured so that all files and directories contained in local interactive user home directories are owned by the owner of the home directory, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was made."
			#break
		else
			count2=$(($count2-1))
		fi
				
		if [[ ("$count2" == "0") ]]; then
			count=$(($count-1))
			break
		else
			continue
		fi
	done
		
	if [[ ("$count" == "0") ]]; then
		pass "$rule" "All files and directories within the local, interactive users' home directories are owned by that user." "Verified all files and directories contained in local interactive user home directories are owned by the owner of the home directory, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done

unset output

### V-72025 | RHEL-07-020670 ###
resetRule "SV-86649r2_rule"
echo "Check $rule"
declare -A output
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do 
	OWNER=$(echo $i | awk -F: '{print $1}')
        GROUP=$(groups $OWNER | awk -F: '{print $2}' | awk '{$1=$1};1')
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
				
	count2="$(find "$HOMEDIR" -print | xargs stat -c '%G' | wc -l)"
	for c in $(find "$HOMEDIR" -print | xargs stat -c '%G%n'); do
		if [[ "$GROUP" != "$(echo $c | awk -F"/" '{print $1}')" ]]; then
			output="$output $(echo $c | sed 's/\//:\//')"
			fail "$rule" "$(echo ${output[@]})" "Any files listed are not group owned by the primary group of the listed home directory user. To be complaint the ownership will need to be changed on those files. Verified the Red Hat Enterprise Linux operating system is NOT configured so that all files and directories contained in local interactive user home directories are owned by the owner of the home directory, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was made."
			#break
		else
			count2=$(($count2-1))
		fi
				
		if [[ ("$count2" == "0") ]]; then
			count=$(($count-1))
			break
		else
			continue
		fi
	done
		
	if [[ ("$count" == "0") ]]; then
		pass "$rule" "All files and directories within the local, interactive users' home directories are group owned by that user's group." "Verified all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done

unset output

### V-72027 | RHEL-07-020680 ###
resetRule "SV-86651r2_rule"
echo "Check $rule"
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do 
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
	
	if [[ -n "$(find "$HOMEDIR" -type f | xargs stat -c '%a:%n' | grep -v '\.' )" ]]; then
		count2="$(find "$HOMEDIR" -type f | xargs stat -c '%a:%n' | grep -v '\.' | wc -l)"
	
	
		for c in $(find "$HOMEDIR" -type f | xargs stat -c '%a:%n' | grep -v '\.' ); do
		
			if [[ "$c" > 750  ]]; then
				fail "$rule" "$(find "$HOMEDIR" -type f | xargs stat -c '%a:%n' | grep -v '\.')"
				break
			else
				count2=$(($count2-1))
			fi
			
			if [[ ("$count2" == "0") ]]; then
				count=$(($count-1))
				break
			else
				continue
			fi
		done
	else
		count=$(($count-1))
	fi
		
		
	if [[ ("$count" == "0") ]]; then
		pass "$rule" "All files and directories within the local, interactive users' home directories mode 0750 or less." "Verified all files and directories contained in local interactive user home directories have mode 0750 or less permissive, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done
	

### V-72029 | RHEL-07-020690 ###
resetRule "SV-86653r3_rule"
echo "Check $rule"
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do 
	OWNER=$(echo $i | awk -F: '{print $1}')
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
	
	if [[ -n "$(find "$HOMEDIR" -type f | xargs stat -c '%n' )" ]]; then
		count2="$(find "$HOMEDIR" -type f | xargs stat -c '%n' | wc -l)"
	
		for c in $(find "$HOMEDIR" -type f | xargs stat -c '%U' ); do
			if [[ "$c" != "$OWNER" ]] && [[ "$c" != "root" ]] ; then
				fail "$rule" "$(find "$HOMEDIR" -type f | xargs stat -c '%n:%U')"
				break
			else
				count2=$(($count2-1))
			fi
			
			if [[ ("$count2" == "0") ]]; then
				count=$(($count-1))
				break
			else
				continue
			fi
		done
	else
		count=$(($count-1))
	fi
		
		
	if [[ ("$count" == "0") ]]; then
		pass "$rule" "Verify that all initialization files in the listed directories (ls -la ./.*) for local interactive users are owned by the user or root. Standard verbiage: Verified all local initialization files for interactive users are owned by the home directory user or root, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verify that all initialization files in the listed directories (ls -la ./.*) for local interactive users are owned by the user or root. Standard verbiage: Verified all local initialization files for interactive users are owned by the home directory user or root, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done


### V-72031 | RHEL-07-020700 ###
resetRule "SV-86655r4_rule"
echo "Check $rule"
declare -A output
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do
        OWNER=$(echo $i | awk -F: '{print $1}')
        GROUP=$(groups $OWNER | awk -F: '{print $2}' | awk '{$1=$1};1')
        HOMEDIR=$(echo $i | awk -F: '{print $2}')

        if [[ -n "$(find "$HOMEDIR" -type f | xargs stat -c '%n' )" ]]; then
                count2="$(find "$HOMEDIR" -name ".*" -type f | xargs stat -c '%G' | wc -l)"

                for c in $(find "$HOMEDIR" -name ".*" -print | xargs stat -c '%G%n' ); do
                        if [[ "$GROUP" != "$(echo $c | awk -F"/" '{print $1}')" ]] ; then
                                output="$output $(echo $c | sed 's/\//:\//')"
                                fail "$rule" "$(echo ${output[@]})" "Any files listed permissions are not set to minimum STIG requirement. To be complaint the permissions will need to be changed on those files."
                                break
                        else
                                count2=$(($count2-1))
                        fi

                        if [[ ("$count2" == "0") ]]; then
                                count=$(($count-1))
                                break
                        else
                                continue
                        fi
                done
        else
                count=$(($count-1))
        fi


        if [[ ("$count" == "0") ]]; then
                pass "$rule" "All local initialization files and directories within the local, interactive users' home directories are group owned by that user's group." "Verify that all local initialization files in local interactive users' home directories (ls -la ./.*) are group-owned by that user's primary group. Standard verbiage: Verified local initialization files for local interactive users are group-owned by the users primary group or root, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
                break
        else
                continue
        fi
done

unset output

### V-72033 | RHEL-07-020710 ###
resetRule "SV-86657r3_rule"
echo "Check $rule"
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do 
	OWNER=$(echo $i | awk -F: '{print $1}')
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
	
	if [[ -n "$(find "$HOMEDIR" -name ".*" -type f | xargs stat -c '%n' )" ]]; then
		count2="$(find "$HOMEDIR" -name ".*" -type f | xargs stat -c '%n' | wc -l)"
	
		for c in $(find "$HOMEDIR" -name ".*" -type f | xargs stat -c '%a' ); do
			if [[ "$c" >740 ]]; then
				fail "$rule" "$(echo $c)" "Any files listed permissions are not set to minimum STIG requirement. To be complaint the permissions will need to be changed on those files."
				break
			else
				count2=$(($count2-1))
			fi
			
			if [[ ("$count2" == "0") ]]; then
				count=$(($count-1))
				break
			else
				continue
			fi
		done
	else
		count=$(($count-1))
	fi
		
		
	if [[ ("$count" == "0") ]]; then
		pass "$rule" "Verify that all initialization files in the listed directories (ls -la ./.*) for local interactive users have mode 0740 or less permissive. Standard verbiage: Verified all local initialization files have mode 0740 or less permissive, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verify that all initialization files in the listed directories (ls -la ./.*) for local interactive users have mode 0740 or less permissive. Standard verbiage: Verified all local initialization files have mode 0740 or less permissive, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done


### V-72035 | RHEL-07-020720 ###
resetRule "SV-86659r4_rule"
echo "Check $rule"
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do 
	OWNER=$(echo $i | awk -F: '{print $1}')
	HOMEDIR=$(echo $i | awk -F: '{print $2}')
	
	if [[ -n "$(find "$HOMEDIR" -type f)" ]]; then
		count2="$(find "$HOMEDIR" -type f -name ".*" | wc -l)"
	
		for c in $(find "$HOMEDIR" -type f -name ".*"); do
			if [[ -n $(grep -i PATH $c | grep -vi HOME | grep -vi export) ]]; then
				fail "$rule" "grep -i PATH \$c | grep -vi HOME | grep -vi export; echo \"above paths are not in users home dir\""
				break
			else
				count2=$(($count2-1))
			fi
			
			if [[ ("$count2" == "0") ]]; then
				count=$(($count-1))
				break
			else
				continue
			fi
		done
	else
		count=$(($count-1))
	fi
		
		
	if [[ ("$count" == "0") ]]; then
		pass "$rule" "No local users' initalization files contained a Path statement" "NOTE: All default PATH statements will inevitably contain \$PATH in them (as the listed Check Content example does). We expect this to mean that the system \$PATH variable that is being passed down is acceptable usage in this context. This also serves as the further documentation required in the Discussion check especially since the discussion is even further limited to looking only for the existence of the current working directory on the PATH list (an empty entry, such as a leading or trailing colon or two consecutive colons) which none of our PATH variables contain. Standard verbiage: Verified all local interactive user initialization files executable search paths contain only paths that resolve to the users home directory, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done

### V-72037 | RHEL-07-020730 ###
resetRule "SV-86661r2_rule"
zero "$rule" "find / -name '.*' -perm -002 -type f 2> /dev/null | grep -Ev '^/sys|^/proc'" "Verified local initialization files do not execute world-writable programs, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified local initialization files HAVE execute world-writable programs, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72039 | RHEL-07-020900 ###
resetRule "SV-86663r2_rule"
if [[ -z "$(find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n")" ]]; then
	zero "$rule" "find /dev -context *:unlabeled_t:* \\( -type c -o -type b \\) -printf \"%p %Z\\n\"" "Verified all system device files are correctly labeled to prevent unauthorized modification, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all system device files are NOT correctly labeled to prevent unauthorized modification, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	echo "$rule"
	fail "$rule" "find /dev -context *:device_t:* \\( -type c -o -type b \\) -printf \"%p %Z\\n\""
fi

### V-72041 | RHEL-07-021000 ###
resetRule "SV-86665r4_rule"
echo "Check $rule"
count="$(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $3}' | wc -l )"
for i in $(cut -d: -f 1,3,6,7 /etc/passwd | grep -vi 'nologin\|false\|sync\|shutdown\|halt\|splunk' | awk -F: '$2 >=1000 {print $1 ":" $3}'); do 
	HOMEDIR="/"
	HOMEDIR+=$(echo $i | cut -d "/" -f2)
	
	echo $i
		echo $HOMEDIR
		
	if [[ -z "$(cat /etc/fstab | grep -i "$HOMEDIR" | grep -i nosuid)" ]]; then 
		fail "$rule" $i 
		break
	else
		count=$(($count-1))
	fi

	if [[ ("$count" == "0") ]]; then
		pass "$rule" "No  user home directories found in fstab without nosuid set" "Verified files systems that contain user home directories are mounted to prevent files with the setuid and setgid bit set from being executed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
		break
	else
		continue
	fi
done 

### V-72043 | RHEL-07-021010 ###
# Manual inspection - based on SA set up of usb mount points.
resetRule "SV-86667r2_rule"
nr "$rule" "echo 'Manual inspection required based on SA set-up of usb mount points.
'; cat /etc/fstab;" "If any listed mount points are for removeable media this is a finding. Otherwise it can be closed as Not a Finding. Standard verbiage: Verified files systems that are used with removable media (of which we have none) are mounted to prevent files with the setuid and setgid bit set from being executed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-72045 | RHEL-07-021020 ###
resetRule "SV-86669r2_rule"
#zero "$rule" "grep nfs /etc/fstab | grep -vi nosetuid"
zero "$rule" "grep nfs /etc/fstab | grep -vi nosuid" "Verified files systems that are being imported via Network File System (NFS) are mounted to prevent files with the setuid and setgid bit set from being executed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified files systems that are being imported via Network File System (NFS) are NOT mounted to prevent files with the setuid and setgid bit set from being executed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72047 | RHEL-07-021030 ###
resetRule "SV-86671r4_rule"
zero "$rule" "find / -xdev -perm -002 -type d -fstype xfs -exec ls -lLd {} \; | awk '(\$4 !~ 'root' || 'sys' || 'bin' )' " "Verified all world-writable directories are group-owned by root, sys, bin, or an application group, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all world-writable directories are NOT group-owned by root, sys, bin, or an application group, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72049 | RHEL-07-021040 ###
# Manual inspection - requires inspection of all files within multiple directories.
# and a comparison against ISSO documentation.
#nr "SV-86673r2_rule" "#Manual inspection required"
resetRule "SV-86673r2_rule"
if [[ -z "$(grep -i '^[^#]*umask' /home/*/.* 2> /dev/null)" ]]; then
	zero "$rule" "grep -i '^[^#]*umask' /home/*/.* 2> /dev/null" "Verified the umask is set to 077 for all local interactive user accounts, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the umask is NOT set to 077 for some local interactive user accounts, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	nr "$rule" "grep -i umask /home/*/.*" "manual verification required"
fi

### V-72051 | RHEL-07-021100 ###
# PEER REVIEW NEEDED
# Might need to make this manual, while the script is somewhat valid - there are a few
# variables that might make it come up with a false fail frequently. 1: RSYLOG is not
# an exclusively permitted logging tool. 2: The check allows a  *.* to log all facilities
# as a valid configuration; but, there could be a situation where cron.* is set after *.* -
# which this script would pass, but  but is a STIG finding. 
resetRule "SV-86675r2_rule"
if [[ -z "$(grep -i '^\s*cron' /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep -v '^#')" ]]; then
	nonzero "$rule" "grep '\*.\* /var/log/messages' /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep -v '^#'" "Verified cron logging has been implemented, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified cron logging has NOT been implemented, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	nonzero "$rule" "grep -i '^\s*cron' /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep -v '^#' " "Verified cron logging has been implemented, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified cron logging has NOT been implemented, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72053 | RHEL-07-021110 ###
resetRule "SV-86677r3_rule"
if [[ -n "$(ls -al /etc/cron.allow)" ]]; then
	nonzero "$rule" "ls -al /etc/cron.allow | awk '\$3 ~ root' " "Verified the cron.allow file exists and is owned by root, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the cron.allow file exists and is NOT owned by root, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na	"$rule" "ls -al /etc/cron.allow" "cron.allow does not exist. This check is NA"
fi

### V-72055 | RHEL-07-021120 ###
resetRule "SV-86679r2_rule"
if [[ -n "$(ls -al /etc/cron.allow)" ]]; then
	nonzero "$rule" "ls -al /etc/cron.allow | awk '\$4 ~ root' " "Verified the cron.allow file exists and is owned by root, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the cron.allow file exists and is NOT owned by root, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na	"$rule" "ls -al /etc/cron.allow" "cron.allow does not exist. This check is NA"
fi

### V-72057 | RHEL-07-021300 ###
# May need to make this manual if the check check below fails, the local ISSO can document as permissable.
resetRule "SV-86681r2_rule"
if [[ -z "$(systemctl status kdump.service | grep -i 'Active: active')" ]]; then
	pass "$rule" "systemctl status kdump.service" "Verified that kernel core dumps are disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nr "$rule" "kdump service is active. If this is not documented with the ISSO, this is a finding."
fi

### V-72059 | RHEL-07-021310 ###
# PEER REVIEW NEEDED
# The RHEL 7 STIG logic is slightly different than the RHEL 6 logic but essentially has the same outcome. 
# One key difference is that the RHEL 7 assumes that the home directories may not actually be named /home
# and includes a pre-check to determine the home director(y/ies). In the TSOA sphere, we may be able to keep 
# the old logic, but we may want to consider whether to manually pull out the home directory and then 
# run this check with the variable input.
resetRule "SV-86683r2_rule"
nonzero "$rule" "mount | grep 'on /home'" "Verified a separate file system is used for user home directories (such as /home or an equivalent, which in our case is /export/home), therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified a separate file system is NOT used for user home directories (such as /home or an equivalent, which in our case is /export/home), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72061 | RHEL-07-021320 ###
resetRule "SV-86685r2_rule"
nonzero "$rule" "mount | grep 'on /var'" "Verified the system uses a separate file system for /var, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use a separate file system for /var, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72063 | RHEL-07-021330 ###
resetRule "SV-86687r6_rule"
if [[ -z "$(grep /var/log/audit /etc/fstab)" ]]; then
	fail "$rule" "grep /var/log/audit /etc/fstab"
else
	nonzero "$rule" "mount | grep -i 'on /var/log/audit'" "Verified the system uses /var/log/audit for the system audit data path, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT use /var/log/audit for the system audit data path, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72065 | RHEL-07-021340 ###
resetRule "SV-86689r3_rule"
if [[ -n "$(systemctl is-enabled tmp.mount | grep -i '^enabled')" ]]; then
	pass "$rule" "systemctl is-enabled tmp.mount | grep -i '^enabled'" "Verified the system usesa separate file system for /tmp, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
elif [[ -n "$(mount | grep /tmp)" ]]; then
	pass "$rule" "mount | grep /tmp" "Verified the system usesa separate file system for /tmp, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nr "$rule" "grep -i /tmp /etc/fstab"
fi

### V-72067 | RHEL-07-021350 ###
resetRule "SV-86691r4_rule"
nonzero "$rule" "cat /proc/sys/crypto/fips_enabled | grep 1" "Verified the Red Hat Enterprise Linux operating system implements NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72069 | RHEL-07-021600 ###
resetRule "SV-86693r3_rule"
flag=$(grep '^/bin\|^/sbin' /etc/aide.conf | grep -v "^#" | awk -F' ' '{print $2}')
testFail=false
for i in $flag; do
  if [[ -z $(grep $i /etc/aide.conf | grep acl | grep -v "^#") ]]; then
        if [[ -n $(grep $i /etc/aide.conf | grep -v "^#") ]]; then
                if [[ -n $(grep NORMAL /etc/aide.conf | grep = | grep -v '^#') ]]; then
                        flag2=$(grep NORMAL /etc/aide.conf | grep = | grep -v '^#' | awk -F '=' '{print $2}')
                        if [[ -n $(grep $flag2 /etc/aide.conf | grep -v "^#" | grep acl) ]]; then
                                nothing
                        else
                                testFail=true
                        fi
                else
                        testFail=true
                fi
        else
                testFail=true
        fi
  else
        $nothing
  fi
done

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "grep acl /etc/aide.conf | grep -v \"^#\"" "Verified the file integrity tool is NOT configured to verify Access Control Lists (ACLs), therefore the reference STIG IS a finding."
else
  pass "$rule" "grep acl /etc/aide.conf | grep -v \"^#\"" "Verified the file integrity tool is configured to verify Access Control Lists (ACLs), therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail

### V-72071 ###
resetRule "SV-86695r3_rule"
flag=$(grep '^/bin\|^/sbin' /etc/aide.conf | grep -v "^#" | awk -F' ' '{print $2}')
testFail=false
for i in $flag; do
  if [[ -z $(grep $i /etc/aide.conf | grep xattrs | grep -v "^#") ]]; then
        if [[ -n $(grep $i /etc/aide.conf | grep -v "^#") ]]; then
                if [[ -n $(grep NORMAL /etc/aide.conf | grep = | grep -v '^#') ]]; then
                        flag2=$(grep NORMAL /etc/aide.conf | grep = | grep -v '^#' | awk -F '=' '{print $2}')
                        if [[ -n $(grep $flag2 /etc/aide.conf | grep -v "^#" | grep xattrs) ]]; then
                                nothing
                        else
                                testFail=true
                        fi
                else
                        testFail=true
                fi
        else
                testFail=true
        fi
  else
        $nothing
  fi
done

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "grep xattrs /etc/aide.conf | grep -v \"^#\"" "Verified the file integrity tool is NOT configured to verify extended attributes, therefore the reference STIG IS a finding."
else
  pass "$rule" "grep xattrs /etc/aide.conf | grep -v \"^#\"" "Verified the file integrity tool is configured to verify extended attributes, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail

### V-72073 ###
resetRule "SV-86697r3_rule"
flag=$(grep '^/bin\|^/sbin' /etc/aide.conf | grep -v "^#" | awk -F' ' '{print $2}')
testFail=false
for i in $flag; do
  if [[ -z $(grep $i /etc/aide.conf | grep sha512 | grep -v "^#") ]]; then
        if [[ -n $(grep $i /etc/aide.conf | grep -v "^#") ]]; then
                if [[ -n $(grep NORMAL /etc/aide.conf | grep = | grep -v '^#') ]]; then
                        flag2=$(grep NORMAL /etc/aide.conf | grep = | grep -v '^#' | awk -F '=' '{print $2}')
                        if [[ -n $(grep $flag2 /etc/aide.conf | grep -v "^#" | grep sha512) ]]; then
                                nothing
                        else
                                testFail=true
                        fi
                else
                        testFail=true
                fi
        else
                testFail=true
        fi
  else
        $nothing
  fi
done

if [[ $(echo $testFail) == true ]]; then
  fail "$rule" "grep sha512 /etc/aide.conf | grep -v \"^#\"" "Verified the Red Hat Enterprise Linux operating system does NOT use a file integrity tool that is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories, therefore the reference STIG IS a finding."
else
  pass "$rule" "grep sha512 /etc/aide.conf | grep -v \"^#\"" "Verified the Red Hat Enterprise Linux operating system must use a file integrity tool that is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

unset testFail

### V-72075 | RHEL-07-021700 ###
resetRule "SV-86699r2_rule"
zero "$rule" "grep 'set root' /boot/grub2/grub.cfg | grep -v hd0" "Removeable media not found in grub loader only hd0 was returned" but rather "Verified the Red Hat Enterprise Linux operating system must not allow removable media to be used as the boot loader unless approved, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system ALLOWS removable media to be used as the boot loader unless approved, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72077 | RHEL-07-021710 ###
resetRule "SV-86701r2_rule"
zero "$rule" "rpm -q telnet-server | grep -iv 'package.*is not installed'" "Verified the telnet-server package is not installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the telnet-server package IS installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72079 | RHEL-07-030000 ###
resetRule "SV-86703r3_rule"
nonzero "$rule" "systemctl is-active auditd.service | grep -i '^active'" "Verified auditing is configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified auditing is NOT configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events, therefore the reference STIG IS a finding. Setting was incorrect by default and/or no change was necessary."

### V-72081 | RHEL-07-030010 ###
# There is some additional, manual, logic needed that looks to be outside of
# what this script framework can handle. e.g. built in CAT downgrades. Going to 
# leave the logic active for the CAT I finding, upon manual re-review the team can
# figure out what the real CAT should be.
#
#Current DISA check text is incorrect, checks for "fail" in the grep, but is requiring a check of "flag" which
# does not align with the results of the fix text. Our logic is verified accurate.
resetRule "SV-86705r4_rule"
nonzero "$rule" "auditctl -s | grep 'failure 1'" "The audit daemon must be restarted for the changes to take effect. The value of "failure" is set to "1", the system is configured to only send information to the kernel log regarding the failure. The availability concern for our systems is documented and there is monitoring of the kernel log. Standard Verbiage: Verified the operating system does not shut down upon audit processing failure because availability is an overriding concern. The system is configured to send information to the kernel log regarding the failuer and does alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure and there is monitoring of the kernel log, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "The audit daemon must be restarted for the changes to take effect. The value of "failure" is set to "1", the system is configured to only send information to the kernel log regarding the failure. The availability concern for our systems is documented and there is monitoring of the kernel log. Standard Verbiage: Verified the operating system does not shut down upon audit processing failure because availability is an overriding concern. The system is NOT configured to send information to the kernel log regarding the failuer and does alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure and there is monitoring of the kernel log, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72083 | RHEL-07-030300 ###
resetRule "SV-86707r2_rule"
nonzero "$rule" "/opt/splunkforwarder/bin/splunk btool deploymentclient list | grep targetUri | grep -v '^#'" "Verified the operating system off-loads audit records onto a different system or media from the system being audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT off-load audit records onto a different system or media from the system being audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72085 | RHEL-07-030310 ###
resetRule "SV-86709r2_rule"
nonzero "$rule" "grep -i '^\s*enable_krb5' /etc/audisp/audisp-remote.conf | grep -v '^#' | grep -i yes" "Verified the operating system encrypts the transfer of audit records off-loaded onto a different system or media from the system being audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72087 | RHEL-07-030320 ###
resetRule "SV-86711r3_rule"
	nonzero "$rule" "grep -i disk_full_action /etc/audisp/audisp-remote.conf | grep -v '^#' | egrep -i 'syslog|single|halt'" "Verified the audit system takes appropriate action when the audit storage volume is full, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT take appropriate action when the audit storage volume is full, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72089 | RHEL-07-030330 ###
resetRule "SV-86713r4_rule"
alloc=$(lsblk | grep /audit | head -1 | awk -F' ' '{print $5}' | sed 's/[^0-9]//g' | awk '{ byte =$1 *1024; print byte }')
quart=$(lsblk | grep /audit | head -1 | awk -F' ' '{print $5}' | sed 's/[^0-9]//g' | awk '{ byte =$1 *1024; print byte }' | awk '{ byte =$1 *.75; print byte }')
if [[ $(expr $alloc - $quart) == $(grep -iw space_left /etc/audit/auditd.conf | sed 's/[^0-9]//g') ]]; then
   pass "$rule" "grep -iw space_left /etc/audit/auditd.conf" "Verified the operating system immediately notifies the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
   fail "$rule" "grep -iw space_left /etc/audit/auditd.conf; echo $(expr $alloc - $quart); echo \"needs to be set to this value\"" "Verified the operating system immediately DOES NOT notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity, therefore the reference STIG IS a finding."
w space_left /etc/audit/auditd.confelse
fi

### V-72091 | RHEL-07-030340 ###
resetRule "SV-86715r2_rule"
nonzero "$rule" "grep -i '^s*space_left_action' /etc/audit/auditd.conf | grep -v '^#' | grep -i email" "Verified the operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72093 | RHEL-07-030350 ###
# We may need to make this manual, other site designated security account accounts would be acceptable
resetRule "SV-86717r3_rule"
nonzero "$rule" "grep -i '^\s*action_mail_acct' /etc/audit/auditd.conf | grep -v '^#' | grep root" "Verified the operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72095 | RHEL-07-030360 ###
resetRule "SV-86719r7_rule"
if [[ -z "$(grep -iw execve /etc/audit/audit.rules | grep -v '^#' | grep setgid | grep 'b32\|b64' | wc -l | grep 2)" ]]; then
	fail "$rule" "grep -iw execve /etc/audit/audit.rules"
else
	nonzero "$rule" "grep -iw execve /etc/audit/audit.rules | grep -v '^#' | grep setuid | grep 'b32\|b64' | wc -l | grep 2" "Verified all privileged function executions are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all privileged function executions are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72097 | RHEL-07-030370 ###
resetRule "SV-86721r5_rule"
nonzero "$rule" "grep -iw chown /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the chown command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the chown command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72099 | RHEL-07-030380 ###
resetRule "SV-86723r5_rule"
nonzero "$rule" "grep -iw fchown /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the fchown command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the fchown command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72101 | RHEL-07-030390 ###
resetRule "SV-86725r5_rule"
nonzero "$rule" "grep -iw lchown /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the lchown command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the lchown command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72103 | RHEL-07-030400 ###
resetRule "SV-86727r5_rule"
nonzero "$rule" "grep -iw fchownat /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the fchownat command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the fchownat command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72105 | RHEL-07-030410 ###
resetRule "SV-86729r5_rule"
nonzero "$rule" "grep -iw chmod /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the chmod command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the chmod command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72107 | RHEL-07-030420 ###
resetRule "SV-86731r5_rule"
nonzero "$rule" "grep -iw fchmod /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the fchmod command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the fchmod command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72109 | RHEL-07-030430 ###
resetRule "SV-86733r5_rule"
nonzero "$rule" "grep -iw fchmodat /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the chmodat command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the chmodat command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72111 | RHEL-07-030440 ###
resetRule "SV-86735r5_rule"
nonzero "$rule" "grep -iw setxattr /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the setxattr command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the setxattr command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72113 | RHEL-07-030450 ###
resetRule "SV-86737r5_rule"
nonzero "$rule" "grep -iw fsetxattr /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the fsetxattr command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the fsetxattr command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72115 | RHEL-07-030460 ###
resetRule "SV-86739r5_rule"
nonzero "$rule" "grep -iw lsetxattr /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the lsetxattr command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the lsetxattr command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72117 | RHEL-07-030470 ###
resetRule "SV-86741r5_rule"
nonzero "$rule" "grep -iw removexattr /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the removexattr command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the removexattr command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72119 | RHEL-07-030480 ###
resetRule "SV-86743r5_rule"
nonzero "$rule" "grep -iw fremovexattr /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the fremovexattr command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the fremovexattr command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72121 | RHEL-07-030490 ###
resetRule "SV-86745r5_rule"
nonzero "$rule" "grep -iw lremovexattr /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the lremovexattr command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the lremovexattr command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72123 | RHEL-07-030500 ###
resetRule "SV-86747r5_rule"
nonzero "$rule" "grep -iw creat /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 4" "Verified all uses of the creat command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the creat command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72125 | RHEL-07-030510 ###
resetRule "SV-86749r5_rule"
nonzero "$rule" "grep -iw open /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 4" "Verified all uses of the open command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the open command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72127 | RHEL-07-030520 ###
resetRule "SV-86751r5_rule"
nonzero "$rule" "grep -iw openat /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 4" "Verified all uses of the openat command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the openat command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72129 | RHEL-07-030530 ###
resetRule "SV-86753r5_rule"
nonzero "$rule" "grep -iw open_by_handle_at /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 4" "Verified all uses of the open_by_handle_at command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the open_by_handle_at command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72131 | RHEL-07-030540 ###
resetRule "SV-86755r5_rule"
nonzero "$rule" "grep -iw truncate /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 4" "Verified all uses of the truncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the truncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72133 | RHEL-07-030550 ###
resetRule "SV-86757r5_rule"
nonzero "$rule" "grep -iw ftruncate /etc/audit/audit.rules  | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 4" "Verified all uses of the ftruncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ftruncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72135 | RHEL-07-030560 ###
resetRule "SV-86759r4_rule"
nonzero "$rule" "grep -i /usr/sbin/semanage /etc/audit/audit.rules  | grep -v '^#' | grep \"\-a always,exit \-F path=/usr/sbin/semanage\"" "Verified all uses of the semanage command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the semanage command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72137 | RHEL-07-030570 ###
resetRule "SV-86761r4_rule"
nonzero "$rule" "grep -i /usr/sbin/setsebool /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the setsebool command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the setsebool command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72139 | RHEL-07-030580 ###
resetRule "SV-86763r4_rule"
nonzero "$rule" "grep -iw /usr/bin/chcon /etc/audit/audit.rules | grep -v '^#'" "Verified all uses of the chcon command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the chcon command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72141 | RHEL-07-030590 ###
resetRule "SV-86765r5_rule"
nonzero "$rule" "grep -i /usr/sbin/setfiles /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the setfiles command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the setfiles command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72143 | RHEL-07-030600 ###
#Removed in v2r1
#resetRule="SV-86767r3_rule"
#nonzero "$rule" "grep -i /var/log/tallylog /etc/audit/audit.rules  | grep -v '^#'"

### V-72145 | RHEL-07-030610 ###
resetRule "SV-86769r4_rule"
nonzero "$rule" "grep -i /var/run/faillock /etc/audit/audit.rules  | grep -v '^#'" "Verified the operating system generates audit records for all successful/unsuccessful account access count events, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generate audit records for all successful/unsuccessful account access count events, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72147 | RHEL-07-030620 ###
resetRule "SV-86771r3_rule"
nonzero "$rule" "grep -i /var/log/lastlog /etc/audit/audit.rules  | grep -v '^#'" "Verified the operating system generates audit records for all successful account access events, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generate audit records for all successful account access events, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72149 | RHEL-07-030630 ###
resetRule "SV-86773r5_rule"
nonzero "$rule" "grep -i /usr/bin/passwd /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the passwd command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the passwd command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72151 | RHEL-07-030640 ###
resetRule "SV-86775r5_rule"
nonzero "$rule" "grep -i /sbin/unix_chkpwd /etc/audit/audit.rules  | grep -v '^\s*#'" "Verified all uses of the unix_chkpwd command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the unix_chkpwd command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72153 | RHEL-07-030650 ###
resetRule "SV-86777r5_rule"
nonzero "$rule" "grep -i /usr/bin/gpasswd /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the gpasswd command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the gpasswd command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72155 | RHEL-07-030660 ###
resetRule "SV-86779r5_rule"
nonzero "$rule" "grep -i /usr/bin/chage /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the chage command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the chage command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72157 | RHEL-07-030670 ###
resetRule "SV-86781r5_rule"
nonzero "$rule" "grep -i /usr/sbin/userhelper /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the userhelper command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the userhelper command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72159 | RHEL-07-030680 ###
resetRule "SV-86783r5_rule"
nonzero "$rule" "grep -i /bin/su /etc/audit/audit.rules  | grep -v '^\s*#'" "Verified all uses of the su command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the su command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72161 | RHEL-07-030690 ###
resetRule "SV-86785r4_rule"
nonzero "$rule" "grep -iw /usr/bin/sudo /etc/audit/audit.rules | grep -v '^#'" "Verified all uses of the sudo command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the sudo command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72163 | RHEL-07-030700 ###
resetRule "SV-86787r5_rule"
if [[ -n "$(grep -i '/etc/sudoers' /etc/audit/audit.rules | grep -v '^#' | egrep -i '\-w /etc/sudoers \-p wa \-k privileged-actions' )" ]]; then
	nonzero "$rule" "grep -i '/etc/sudoers.d/' /etc/audit/audit.rules  | grep -v '^#' | grep -i '\-w /etc/sudoers.d/ \-p wa \-k privileged-actions'" "Verified all uses of the sudoers command is audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the sudoers command is NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	echo "Check $rule"
	fail "$rule" "grep -i /etc/sudoers /etc/audit/audit.rules  | grep -v '^#' | grep -i '\-w /etc/sudoers \-p wa \-k privileged-actions'"
fi	

### V-72165 | RHEL-07-030710 ###
resetRule "SV-86789r4_rule"
nonzero "$rule" "grep -i /usr/bin/newgrp /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the newgrp command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the newgrp command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72167 | RHEL-07-030720 ###
resetRule "SV-86791r4_rule"
nonzero "$rule" "grep -i /usr/bin/chsh /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the chsh command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the chsh command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72169 | RHEL-07-030730 ###
#resetRule "SV-86793r5_rule"
#removed in v2r1
#nonzero "$rule" "grep -i /bin/sudoedit /etc/audit/audit.rules  | grep -v '^#'"

### V-72171 | RHEL-07-030740 ###
resetRule "SV-86795r7_rule"
nonzero "$rule" "grep -iw mount /etc/audit/audit.rules | grep -v '^\s*#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the ftruncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ftruncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72173 | RHEL-07-030750 ###
resetRule "SV-86797r5_rule"
nonzero "$rule" "grep -iw /usr/bin/umount /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the umount command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the umount command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." 

### V-72175 | RHEL-07-030760 ###
resetRule "SV-86799r4_rule"
nonzero "$rule" "grep -iw /usr/sbin/postdrop /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the postdrop command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the postdrop command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72177 | RHEL-07-030770 ###
resetRule "SV-86801r3_rule"
nonzero "$rule" "grep -iw /usr/sbin/postqueue /etc/audit/audit.rules | grep -v '^#'" "Verified all uses of the postqueue command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the postqueue command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72179 | RHEL-07-030780 ###
resetRule "SV-86803r3_rule"
nonzero "$rule" "grep -iw /usr/libexec/openssh/ssh-keysign /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the ssh-keysign command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ssh-keysign command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72181 | SV-86805r3_rule | RHEL-07-030790 ###
#Check depreciated in v1r2 
#nonzero "SV-86805r3_rule" "grep -i /usr/libexec/pt_chown /etc/audit/audit.rules | grep -v '^#'"

### V-72183 | RHEL-07-030800 ###
resetRule "SV-86807r3_rule"
nonzero "$rule" "grep -iw /usr/bin/crontab /etc/audit/audit.rules | grep -v '^#'" "Verified all uses of the crontab command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the crontab command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72185 | RHEL-07-030810 ###
resetRule "SV-86809r4_rule"
nonzero "$rule" "grep -iw /usr/sbin/pam_timestamp_check /etc/audit/audit.rules  | grep -v '^#'" "Verified all uses of the pam_timestamp_check command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the pam_timestamp_check command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72187 | RHEL-07-030820 ###
resetRule "SV-86811r5_rule"
nonzero "$rule" "grep -iw init_module /etc/audit/audit.rules  | grep -v '^\s*#' | grep -i \"\-a always,exit \-F arch=.* \-S init_module\" | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the init_module command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the init_module command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72189 | RHEL-07-030830 ###
resetRule "SV-86813r5_rule"
nonzero "$rule" "grep -iw delete_module /etc/audit/audit.rules  | grep -v '^\s*#' | grep -i \"\-a always,exit \-F arch=.* \-S delete_module\" | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the delete_module command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the delete_module command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72191 | RHEL-07-030840 ###
resetRule "SV-86815r5_rule"
nonzero "$rule" "grep -i kmod /etc/audit/audit.rules  | grep -v '^#' | grep -i \"\-w /usr/bin/kmod \-p x \-F auid!=4294967295\"" "Verified all uses of the insmod command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the insmod command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72193 | SV-86817r4_rule | RHEL-07-030850 ###
#removed in v2r1
#nonzero "SV-86817r4_rule" "grep -i rmmod /etc/audit/audit.rules  | grep -v '^#' | grep -i \"\-w /sbin/rmmod \-p x \-F auid!=4294967295\""

### V-72195 | SV-86819r4_rule | RHEL-07-030860 ###
#removed in v2r1
#nonzero "SV-86819r4_rule" "grep -i modprobe /etc/audit/audit.rules  | grep -v '^#' | grep -i \"\-w /sbin/modprobe \-p x \-F auid!=4294967295\""

### V-72197 | RHEL-07-030870 ###
resetRule "SV-86821r5_rule"
nonzero "$rule" "grep -i /etc/passwd /etc/group /etc/audit/audit.rules  | grep -v '^#'" "Verified the operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72199 | RHEL-07-030880 ###
resetRule "SV-86823r5_rule"
nonzero "$rule" "grep -iw rename /etc/audit/audit.rules | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the ftruncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ftruncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72201 | RHEL-07-030890 ###
resetRule "SV-86825r5_rule"
nonzero "$rule" "grep -iw renameat /etc/audit/audit.rules | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the ftruncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ftruncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72203 | RHEL-07-030900 ###
resetRule "SV-86827r5_rule"
nonzero "$rule" "grep -iw rmdir /etc/audit/audit.rules | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the ftruncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ftruncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72205 | RHEL-07-030910 ###
resetRule "SV-86829r5_rule"
nonzero "$rule" "grep -iw unlink /etc/audit/audit.rules | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the ftruncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ftruncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72207 | RHEL-07-030920 ###
resetRule "SV-86831r5_rule"
nonzero "$rule" "grep -iw unlinkat /etc/audit/audit.rules | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the ftruncate command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the ftruncate command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72209 | RHEL-07-031000 ###
resetRule "SV-86833r2_rule"
zero "$rule" "grep 'disabled' /opt/splunkforwarder/etc/apps/Splunk_TA_nix_base/local/inputs.conf | grep -v '0\|false'" "Verified the operating system immediately notifies the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT immediately notifies the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72211 | RHEL-07-031010 ###
resetRule "SV-86835r2_rule"
if [[ -z "$(grep imtcp /etc/rsyslog.conf | grep -v '^#')" ]]; then
	if [[ -z "$(grep imudp /etc/rsyslog.conf | grep -v '^#' )" ]]; then
		zero "$rule" "grep imrelp /etc/rsyslog.conf | grep -v '^#' " "Verified the rsyslog daemon does not accept log messages from other servers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rsyslog daemon DOES accept log messages from other servers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	else
		result "$rule" "grep imudp /etc/rsyslog.conf | grep -v '^#'" "Verified the rsyslog daemon does not accept log messages from other servers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	fi
else
	result "$rule" "grep imtcp /etc/rsyslog.conf | grep -v '^#'" "Verified the rsyslog daemon does not accept log messages from other servers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-72213 | RHEL-07-032000 ###
resetRule "SV-86837r3_rule"
echo "Check $rule"
nonzero "$rule" "/opt/isec/ens/threatprevention/bin/isectpdControl.sh status | grep active" "Verified the Red Hat Enterprise Linux operating system must be configured so that all network connections associated with SSH traffic terminate after a period of inactivity, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system is NOT configured so that all network connections associated with SSH traffic terminate after a period of inactivity, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72215 | RHEL-07-032010 ###
#removed v2r1
#resetRule "SV-86839r3_rule"
#if [[ -n "$(systemctl is-active nails | grep '^active')" ]]; then
#	if [[ -n "$(find /opt/NAI/LinuxShield/engine/dat -name '*.conf')" ]]; then
#		zero "$rule" "find /opt/NAI/LinuxShield/engine/dat/ -name '*.conf -mtime +7 -type f"
#	else
#		echo "$rule"
#		fail "$rule" "No DAT files found in /opt/NAI/LinuxShield/engine/dat/"
#	fi
#elif [[ -n "$(systemctl is-active clamav-daemon.socket | grep '^active')" ]]; then
#	if [[ -n "$( find /var/lib/clamav -name '*.cvd' )" ]]; then
#		zero "$rule" "find /var/lib/clamav/ -name '*.cvd' -mtime +7 -type f"
#	else
#		echo "Check $rule"
#		fail "$rule" "No CVD files found in /var/lib/clamav/"
#	fi
#else
#	echo "Check $rule"
#	fail "$rule" "Determined that nails and clamav-daemon.socket not running. Check with SA to determine if other AV is in use, and then validate date."
#fi

### V-72217 | RHEL-07-040000 ###
resetRule "SV-86841r3_rule"
nonzero "$rule" "grep -i 'maxlogins' /etc/security/limits.conf | grep -v '^#' | awk '\$4 <=10 {print\$4}' " "Verified the operating system limits the number of concurrent sessions to 10 for all accounts and/or account types, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT limit the number of concurrent sessions to 10 for all accounts and/or account types, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72219 | RHEL-07-040100 ###
# Manual - Requires comparison with documented PPS CAL
resetRule "SV-86843r2_rule"
nr "$rule" "echo '#Manual Inspection Required.
'; firewall-cmd --list-all;" "Manual Check only. Verify the listed services on the listed interfaces are properly documented. See https://dl.cyber.mil/ppsm/pdf/CAL_by_Port.pdf for DISA baseline standard. Standard verbiage: Verified the host is configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-72221 | RHEL-07-040110 ###
# Currently only checks the default config file. STIG Specifies that alternate output of
# 'ps -ef | grep sshd ' would indicate a different active daemon, and thus alternate ciper
# suite. I think the below rule will be valid 99% of the time, but may be suceptable to error.
resetRule "SV-86845r3_rule"
nonzero "$rule" "egrep -i '^\s*ciphers.*aes128-ctr|^\s*Ciphers.*aes192-ctr|^\s*Ciphers.*aes256-ctr' /etc/ssh/sshd_config | grep -v cbc; #The Cipher-Block Chaining (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plain text attacks and must not be used." "Verified a FIPS 140-2 approved cryptographic algorithm is used for SSH communications, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified a FIPS 140-2 approved cryptographic algorithm is NOT used for SSH communications, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72223 | RHEL-07-040160 ###
resetRule "SV-86847r4_rule"
nonzero "$rule" "grep -iE '^\s*tmout\s*=\s*(600|[1-5][0-9][0-9])\s*\$|^\s*tmout\s*=\s*[0-9]{1,2}\s*\$' /etc/profile.d/*" "Verified all network connections associated with a communication session are terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all network connections associated with a communication session are NOT terminated at the end of the session or after 10 minutes of inactivity from the user at a command prompt, except to fulfill documented and validated mission requirements, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72225 | RHEL-07-040170 ###
# The STIG language for this check has evolved slightly, in that it first cheks that the SSH banner
# is configured to point to /etc/issue. However, the check makes the next step to validate that /etc/issue
# has been configured correctly. This is check RHEL-07-010030, which we've left manual. Not sure
# if we should keep this as an active check, or make it manual.
resetRule "SV-86849r4_rule"
nonzero "$rule" "grep -iE '^\s*banner\s+/etc/issue|^\s*banner\s*=\s*/etc/issue' /etc/ssh/sshd_config" "Verified the Standard Mandatory DoD Notice and Consent Banner is displayed immediately prior to, or as part of, remote access logon prompts, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Standard Mandatory DoD Notice and Consent Banner is NOT displayed immediately prior to, or as part of, remote access logon prompts, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72227 | RHEL-07-040180 ###
resetRule "SV-86851r4_rule"
nonzero "$rule" "grep -i start_tls /etc/sssd/sssd.conf | grep -v '^#' | grep true" "Verified the operating system implements cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72229 | RHEL-07-040190 ###
resetRule "SV-86853r4_rule"
nonzero "$rule" "grep -i tls_reqcert /etc/sssd/sssd.conf | grep -v '^#' | grep demand" "Verified the operating system implements cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72231 | RHEL-07-040200 ###
resetRule "SV-86855r4_rule"
nonzero "$rule" "grep -i tls_cacert /etc/sssd/sssd.conf | grep -v '^#' | grep 'ca-bundle.crt\|cacert.pem'" "Verified the operating system implements cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) communications, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72233 | RHEL-07-040300 ###
resetRule "SV-86857r3_rule"
if [[ -n "$(rpm -q openssh-server | grep -iv 'package.*is not installed')" ]]; then
	nonzero "$rule" "rpm -q openssh-clients | grep -iv 'package.*is not installed'" "Verified all networked systems have SSH installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all networked systems does NOT have SSH installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	nonzero "$rule" "rpm -q openssh-server | grep -iv 'package.*is not installed'" "Verified all networked systems have SSH installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all networked systems does NOT have SSH installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72235 | RHEL-07-040310 ###
resetRule "SV-86859r3_rule"
nonzero "$rule" "systemctl is-active sshd | grep '^active'" "Verified all networked systems use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all networked systems does NOT use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72237 | RHEL-07-040320 ###
resetRule "SV-86861r4_rule"
nonzero "$rule" "grep -Ei '^\s*clientaliveinterval\s+600\s*$|^\s*clientaliveinterval\s+[1-5][0-9][0-9]\s*$|^\s*clientaliveinterval\s+[1-9][0-9]\s*$|^\s*clientaliveinterval\s+[1-9]\s*$' /etc/ssh/sshd_config" "Verified all network connections associated with SSH traffic terminate at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all network connections associated with SSH traffic do NOT terminate at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72239 | RHEL-07-040330 ###
resetRule "SV-86863r4_rule"
if [[ -z "$(echo "$RHELverNumb" | grep -Eo '7.[4-9]')" ]]; then
	nonzero "$rule" "grep -i '^RhostsRSAAuthentication' /etc/ssh/sshd_config | grep -v '^#' | grep -i no" "RSAAuth has been configured per the STIG" "RSAAuth has NOT been configured per the STIG"
else
	na "$rule" "$HOSTNAME is running RHEL $RHELverNumb. This requirement is Not Applicable." "Verified the system is Red Hat release 7.4 or newer, therefore this requirement is Not Applicable."
fi


### V-72241 | RHEL-07-040340 ###
resetRule "SV-86865r4_rule"
nonzero "$rule" "grep -Ei '^\s*clientalivecountmax\s+0' /etc/ssh/sshd_config" "Verified ClientAliveCountMax has been set to 0" "Verified ClientAliveCountMax has NOT been set to 0"


### V-72243 | RHEL-07-040350 ###
resetRule "SV-86867r3_rule"
nonzero "$rule" "grep -i '^IgnoreRhosts' /etc/ssh/sshd_config | grep -v '^#' | grep yes" "Verified the SSH daemon does not allow authentication using rhosts authentication, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon does NOT allow authentication using rhosts authentication, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72245 | RHEL-07-040360 ###
resetRule "SV-86869r3_rule"
nonzero  "$rule" "grep -i '^printlastlog' /etc/ssh/sshd_config | grep -v '^#' | grep -i yes" "Verified the system displays the date and time of the last successful account logon upon an SSH logon, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT display the date and time of the last successful account logon upon an SSH logon, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72247 | RHEL-07-040370 ###
resetRule "SV-86871r3_rule"
nonzero  "$rule" "grep -i '^PermitRootLogin' /etc/ssh/sshd_config | grep -v '^#' | grep -i no" "Verified the system does not permit direct logons to the root account using remote access via SSH, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES permit direct logons to the root account using remote access via SSH, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72249 | RHEL-07-040380 ###
resetRule "SV-86873r3_rule"
nonzero "$rule" "grep -i '^IgnoreUserKnownHosts' /etc/ssh/sshd_config | grep -v '^#' | grep yes" "Verified the SSH daemon does not allow authentication using known hosts authentication, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon DOES allow authentication using known hosts authentication, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72251 | RHEL-07-040390 ###
#rule subtly changed from checking that Protocol 2 is configured, to checking that ONLY Protocol 2 is in use.
resetRule "SV-86875r4_rule"
if [[ -z "$(echo "$RHELverNumb" | grep -Eo '7.[4-9]')" ]]; then
#	nonzero "$rule" "grep -Ei '^\s*protocol\s+2' /etc/ssh/sshd_config"
	zero "$rule" "grep -Ei '^\s*protocol' /etc/ssh/sshd_config | grep -v '^#' | grep -v '2'" "Protocol has been configured per the STIG" "Protocol has NOT been configured per the STIG"
else
	na "$rule" "$HOSTNAME is running RHEL $RHELverNumb. This requirement is Not Applicable." "Verified the system is Red Hat release 7.4 or newer, therefore this requirement is Not Applicable."
fi

### V-72253 | RHEL-07-040400 ###
resetRule "SV-86877r3_rule"
nonzero "$rule" "grep -i macs /etc/ssh/sshd_config | grep -v '^#' | grep -i 'hmac-sha2-256.*hmac-sha2-512\|hmac-sha2-512.*hmac-sha2-256'" "Verified the SSH daemon is configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon is NOT configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72255 | RHEL-07-040410 ###
# Check content from DISA leaves question  as to whether the test should be against only the files
# under /etc/ssh/  (as explicitly stated in step 2 of the check), or if it should be run against all
# .pub files found on the system (as searched for in step 1 of the check). Going to write this check
# assuming all .pub files need to be tested - otherwise why would we be searching for them in the first
# step?
resetRule "SV-86879r2_rule"
zero "$rule" "for i in \$(find / -name '*.pub' -fstype xfs); do echo \$(stat -c '%n %a' \$i | awk '\$2 > 644 {print}'); done;" "Verified the SSH public host key files have mode 0644 or less permissive, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH public host key files does NOT have mode 0644 or less permissive, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72257 | RHEL-07-040420 ###
resetRule "SV-86881r3_rule"
zero "$rule" "for i in \$(find / -name '*ssh_host*key'); do echo \$(stat -c '%n %a' \$i | awk '\$2 > 640 {print}'); done;" "Verified the SSH private host key files have mode 0600 or less permissive, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH private host key files does NOT have mode 0600 or less permissive, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72259 | RHEL-07-040430 ###
resetRule "SV-86883r3_rule"
nonzero "$rule" "grep -i '^\s*gssapiauth' /etc/ssh/sshd_config | grep -v '^#' | grep no" "Verified the SSH daemon does not permit Generic Security Service Application Program Interface (GSSAPI) authentication, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon DOES permit Generic Security Service Application Program Interface (GSSAPI) authentication, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72261 | RHEL-07-040440 ###
resetRule "SV-86885r3_rule"
nonzero "$rule" "grep -i '^\s*kerberosauth' /etc/ssh/sshd_config | grep -v '^#' | grep no" "Verified the SSH daemon does not permit Kerberos authentication, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon DOES permit Kerberos authentication, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72263 | RHEL-07-040450 ###
resetRule "SV-86887r3_rule"
nonzero "$rule" "grep -i '^\s*strictmodes' /etc/ssh/sshd_config | grep -v '^#' | grep yes" "Verified the SSH daemon performs strict mode checking of home directory configuration files, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon does NOT perform strict mode checking of home directory configuration files, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72265 | RHEL-07-040460 ###
resetRule "SV-86889r3_rule"
nonzero "$rule" "grep -i '^\s*UsePrivilegeSeparation' /etc/ssh/sshd_config | grep -v '^#' | grep 'yes\|sandbox'" "Verified the SSH daemon uses privilege separation, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon does NOT use privilege separation, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72267 | RHEL-07-040470 ###
resetRule "SV-86891r3_rule"
nonzero "$rule" "grep -i '^\s*compression' /etc/ssh/sshd_config | grep -v '^#' | grep 'no\|delayed'" "Verified the SSH daemon must not allow compression or must only allow compression after successful authentication, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the SSH daemon ALLOWS compression or must only allow compression after successful authentication, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72269 | RHEL-07-040500 ###
resetRule "SV-86893r4_rule"
if [[ -n "$(ps -ef | grep '^ntp')" ]]; then
	if [[ -e "/etc/ntp.conf" ]]; then
		nonzero "$rule" "grep maxpoll /etc/ntp.conf | grep -v '^#' | grep -v 17 " "Verified the operating system does, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)." "Verified the operating system does NOT, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
	else
		echo "Check $rule"
		fail "$rule" "/etc/ntp.conf does not exist"
	fi
else
	echo "Check $rule"
	fail "$rule" "ps -ef | grep '^ntp'"
fi

### V-72273 | RHEL-07-040520 ###
resetRule "SV-86897r2_rule"
if [[ -n "$(rpm -q firewalld | grep -iv 'package.*is not installed')" ]]; then
	if [[ -n "$(systemctl status firewalld | grep -i 'Loaded: loaded')" ]]; then
		if [[ -n "$(systemctl is-active firewalld | grep -i 'active')" ]]; then
			nonzero "$rule" "firewall-cmd --state | grep running" "Verified the operating system has enabled an application firewall, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT have an application firewall enabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
		else
			fail "$rule" "systemctl is-active firewalld | grep -i 'active'"
		fi
	else
		echo "Check $rule"
		fail "$rule" "systemctl status firewalld | grep -i 'loaded: loaded\'"
	fi
else
	nr "$rule" "rpm -q firewalld | grep -iv 'package.*is not installed'"
fi

### V-72275 | RHEL-07-040530 ###
resetRule "SV-86899r4_rule"
nonzero "$rule" "grep pam_lastlog /etc/pam.d/postlogin | grep -v '^#' | grep -v silent" "Verified the Red Hat Enterprise Linux operating system displays the date and time of the last successful account logon upon logon, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT display the date and time of the last successful account logon upon logon, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72277 | RHEL-07-040540 ###
resetRule "SV-86901r2_rule"
zero "$rule" "find / -name '*.shosts'" "Verified there are no .shosts files on the system, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified there IS no .shosts files on the system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72279 | RHEL-07-040550 ###
resetRule "SV-86903r2_rule"
zero "$rule" "find / -name 'shosts.quiv'" "Verified there are no shosts.equiv files on the system, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified there IS shosts.equiv files on the system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72281 | RHEL-07-040600 ###
resetRule "SV-86905r2_rule"
if [[ -z "$(grep -i hosts  /etc/nsswitch.conf | grep -v '^#' | grep dns)" ]]; then
	echo "Check $rule"
	if [[ -s "(/etc/resolv.conf)" ]]; then
		result "$rule" "fail" "cat /etc/resolve.conf" 
	else
		result "$rule" "pass" "cat /etc/resolve.conf" "Verified for systems using DNS resolution, at least two name servers are configured, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	fi
else
	nonzero "$rule" "grep -c nameserver /etc/resolv.conf | grep -v '^#' | awk '\$0 >=2'" "Verified for systems using DNS resolution, at least two name servers are configured, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified for systems using DNS resolution, at least two name servers are NOT configured, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-72283 | RHEL-07-040610 ###
resetRule "SV-86907r2_rule"
if [[ -z "$(grep 'net.ipv4.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
	fail "$rule" "grep 'net.ipv4.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.conf.all.accept_source_route = 0'" "Verified the system does not forward Internet Protocol version 4 (IPv4) source-routed packets, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES forward Internet Protocol version 4 (IPv4) source-routed packets, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72285 | RHEL-07-040620 ###
resetRule "SV-86909r2_rule"
if [[ -z "$(grep 'net.ipv4.conf.default.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
	fail "$rule" "grep 'net.ipv4.conf.default.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.conf.default.accept_source_route = 0'" "Verified the system does not forward Internet Protocol version 4 (IPv4) source-routed packets by default, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES forward Internet Protocol version 4 (IPv4) source-routed packets by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72287 | RHEL-07-040630 ###
resetRule "SV-86911r2_rule"
if [[ -z "$(grep 'net.ipv4.icmp_echo_ignore_broadcasts' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 1 )" ]]; then
	fail "$rule" "grep 'net.ipv4.icmp_echo_ignore_broadcasts' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 1"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.icmp_echo_ignore_broadcasts = 1'" "Verified the system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72289 | RHEL-07-040640 ###
resetRule "SV-86913r3_rule"
if [[ -z "$(grep 'net.ipv4.conf.default.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
	fail "$rule" "grep 'net.ipv4.conf.default.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.conf.default.accept_redirects = 0'" "Verified the system ignores Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi


### V-72291 | RHEL-07-040650 ###
resetRule "SV-86915r4_rule"
if [[ -z "$(grep 'net.ipv4.conf.default.send_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
	fail "$rule" "grep 'net.ipv4.conf.default.send_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.conf.default.send_redirects = 0'" "Verified the system does not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72293 | RHEL-07-040660 ###
resetRule "SV-86917r3_rule"
if [[ -z "$(grep 'net.ipv4.conf.all.send_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
	fail "$rule" "grep 'net.ipv4.conf.all.send_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.conf.all.send_redirects = 0'" "Verified the system does not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72295 | RHEL-07-040670 ###
resetRule "SV-86919r2_rule"
zero "$rule" "ip link | grep -i promisc" "Verified network interfaces are not in promiscuous mode, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified network interfaces are IN promiscuous mode, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72297 | RHEL-07-040680 ###
resetRule "SV-86921r3_rule"
if [[ -n "$(rpm -q postfix| grep  -i 'not installed')" ]]; then
	na "$rule" "rpm -q postfix " "postfix is not installed"
else
	nonzero "$rule" "postconf -n smtpd_client_restrictions  | grep -i 'permit_mynetworks\s*,\s*reject'" "Verified the system is configured to prevent unrestricted mail relaying, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system is NOT configured to prevent unrestricted mail relaying, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72299 | RHEL-07-040690 ###
resetRule "SV-86923r3_rule"
nonzero "$rule" "rpm -q vsftpd | grep -iE '^\s*package.*is\s+not\s+installed'" "Verified a File Transfer Protocol (FTP) server package is not installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified a File Transfer Protocol (FTP) server package IS installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72301 | RHEL-07-040700 ###
resetRule "SV-86925r2_rule"
nonzero "$rule" "rpm -q tftp-server | grep 'not installed'" "Verified the Trivial File Transfer Protocol (TFTP) server package is not installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Trivial File Transfer Protocol (TFTP) server package IS installed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72303 | RHEL-07-040710 ###
resetRule "SV-86927r4_rule"
nonzero "$rule" "grep -iE '^\s*x11Forwarding\s+yes' /etc/ssh/sshd_config" "Verified remote X connections for interactive users are encrypted, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified remote X connections for interactive users are NOT encrypted, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72305 | RHEL-07-040720 ###
resetRule "SV-86929r3_rule"
if [[ -n "$(rpm -q tftpd | grep  -i 'not installed')" ]]; then
	na "$rule" "rpm -q tftpd | grep  -i 'not installed'" "Verified a TFTP server is not installed, making this Not Applicable."
else
	nonzero "$rule" "grep 'server_args' /etc/xinetd.d/tftp | grep -v '^#' | grep -i '\-s' | grep -i '/var/lib/tftpboot'" "Serverargs have been configured per the STIG" "Serverargs have NOT been configured per the STIG"
fi

### V-72307 | RHEL-07-040730 ###
# We could probably make this manual since its more a documentation check, but I've left it
# in so that it can automatically mark it as a pass if x windows is not installed
resetRule "SV-86931r4_rule"
if [[ -z "$(rpm -qa | grep xorg | grep server | grep common)" ]]; then
	pass "$rule" "rpm -qa | grep xorg | grep server | grep common" "The X Windows Client System is documented as an operational requirement for our servers. However this is only the client but this check will shows as a finding since the package xorg-x11-server-utils has the test "server" in the name. This is NOT X Windows Server, only a utility required by the Client applicaiton, specifically the client package of xorg-x11-init has it as a dependency. Since this is NOT the actual X Windows Server package we are listing this as Not a Finding.Standard Verbiage: Verified an X Windows display manager is not installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nr "$rule" "echo 'Manual check of documentation required as X Windows System is installed.
	'; rpm -qa | grep xorg | grep server | grep common"
fi

### V-72309 | RHEL-07-040740 ###
resetRule "SV-86933r2_rule"
if [[ -z "$(grep 'net.ipv4.ip_forward' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
	fail "$rule" "grep 'net.ipv4.ip_forward' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.ip_forward = 0'" "Verified the system is not performing packet forwarding, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system IS performing packet forwarding, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72311 | RHEL-07-040750 ###
resetRule "SV-86935r4_rule"
if [[ -n "$(cat /etc/fstab | grep nfs | grep -v '#')" ]]; then
	if [[ -n "$(grep nfs /etc/fstab | grep -v '^#' | grep 'krb5:krb5i:krb5p')" ]]; then
		zero "$rule" "grep nfs /etc/fstab | grep -v '^#' | grep 'sec=sys'" "Verified the Network File System (NFS) is configured to use AUTH_GSS, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Network File System (NFS) is NOT configured to use AUTH_GSS, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	else
		echo "$rule"
		fail "$rule" "grep nfs /etc/fstab | grep -v '^#' | grep 'krb5:krb5i:krb5p'" "The Red Hat Enterprise Linux operating system is NOT configured so that the Network File System (NFS) is configured to use RPCSEC_GSS."
	fi
else
	na "$rule" "cat /etc/fstab | grep nfs"
fi

### V-72313 | RHEL-07-040800 ###
resetRule "SV-86937r2_rule"
if [[ -f "/etc/snmp/snmpd.conf" ]]; then
	zero "$rule" "grep -i 'public\|private' /etc/snmp/snmpd.conf | grep -v '^\s*#'" "Verified SNMP community strings are changed from the default, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified SNMP community strings are NOT changed from the default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "ls -al /etc/snmp/snmpd.conf" "The /etc/snmp/snmpd.conf file does not exist, therefore this is Not Applicable."
fi

### V-72315 | RHEL-07-040810 ###
resetRule "SV-86939r3_rule"
echo "Check $rule"
if [[ -n "$(rpm -q firewalld | grep -iv 'package.*is not installed')" ]]; then
	if [[ -n "$(systemctl is-active firewalld | grep active)" ]]; then
		nonzero "$rule" "firewall-cmd --get-default-zone | awk '{system(\"firewall-cmd --list-all --zone=\$1\")}' | grep -viw 'services: '" "Verified the system access control program is configured to grant or deny system access to specific hosts and services, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system access control program is NOT configured to grant or deny system access to specific hosts and services, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	else
		if [[ -s "(/etc/hosts.allow)" ]] && [[ -s "(/etc/hosts.deny)" ]]; then
			pass "$rule" "ls -al /etc/hosts.allow /etc/hosts.deny"
		else
			fail "$rule" "ls -al /etc/hosts.allow /etc/hosts.deny"
		fi
	fi
else
	if [[ -n "$(rpm -q tcpwrappers | grep -iv 'package.*is not installed')" ]]; then
		if [[ -s "(/etc/hosts.allow)" ]] && [[ -s "(/etc/hosts.deny)" ]]; then
			pass "$rule" "ls -al /etc/hosts.allow /etc/hosts.deny"
		else
			fail "$rule" "ls -al /etc/hosts.allow /etc/hosts.deny"
		fi
	else
		fail "$rule" "rpm -q firewalld tcpwrappers"
	fi
fi

### V-72317 | RHEL-07-040820 ###
resetRule "SV-86941r2_rule"
if [[ -n "$(rpm -q liberswan| grep -iv 'package.*is not installed')" ]]; then
	if [[ -n "$(systemctl is-active ipsec | grep active)" ]]; then
		zero "$rule" "grep -iw '^.conn' /etc/ipsec.conf /etc.upsec.d/*.conf | grep -v '^#'" "Verified the system does not have unauthorized IP tunnels configured, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system DOES have unauthorized IP tunnels configured, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	else
		echo "Check $rule"
		pass "$rule" "systemctl is-active ipsec | grep active" "Verified the system does not have unauthorized IP tunnels configured, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	fi
else
	echo "Check $rule"
	pass "$rule" "rpm -q liberswan| grep -iv 'package.*is not installed'" "Verified the system does not have unauthorized IP tunnels configured, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-72319 | RHEL-07-040830 ###
resetRule "SV-86943r2_rule"
if [[ -z "$(grep 'net.ipv6.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#')" ]]; then
	#ipv6 is not enabled. This check is NA
	na "$rule" "echo 'IPV6 is not enabled.
	'; grep 'net.ipv6.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#';" "Verified IPv6 is not enabled and the key does not exist, therefore this is Not Applicable."
else
	#key exists, continue check.
	if [[ -z "$(grep 'net.ipv6.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
		fail "$rule" "grep 'net.ipv6.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#'; echo ' 
		'; grep 'net.ipv6.conf.all.accept_source_route' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0;"
	else	
		nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv6.conf.all.accept_source_route\s*=\s*0'" "IPV6 is configured" "IPV6 is NOT configured"
	fi
fi

### V-72417 | RHEL-07-041001 ###
resetRule "SV-87041r4_rule"
if [[ -n "$(rpm -q esc | grep -v 'not installed')" ]]; then
	if [[ -n "$(rpm -q pam_pkcs11 | grep -v 'not installed')" ]]; then
		pass "$rule" "rpm -q esc pam_pkcs11" "Verified the operating system has the required packages for multifactor authentication installed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "rpm -q esc pam_pkcs11"	
	fi
else
	fail "$rule" "rpm -q esc pam_pkcs11"
fi

### V-72427 | RHEL-07-041002 ###
resetRule "SV-87051r4_rule"
nonzero "$rule" "grep '^\s*services\s*=.*pam' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf" "Verified the operating system implements multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM), therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT implement multifactor authentication for access to privileged accounts via pluggable authentication modules (PAM), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-72433 | RHEL-07-041003 ###
resetRule "SV-87057r5_rule"
echo "Check $rule"
if [[ -n "$(grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -v '^\s*#')" ]]; then
        if [[ "$(grep -v '^\s*#' /etc/pam_pkcs11/pam_pkcs11.conf | egrep -c cert_policy)" != "$(grep -v '^\s*#' /etc/pam_pkcs11/pam_pkcs11.conf | egrep -c 'cert_policy.*ocsp_on')" ]]; then
                fail "$rule" "grep -i 'cert_policy.*ocsp' /etc/pam_pkcs11/pam_pkcs11.conf"
        else
                pass "$rule" "grep -i 'cert_policy.*ocsp' /etc/pam_pkcs11/pam_pkcs11.conf" "Verified the operating system implements certificate status checking for PKI authentication, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
        fi
else
        fail "$rule" "grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf| grep -v '^#' | awk ' \$0 >=3 {print \$0}' "
fi

### V-72435 | SV-87059r3_rule | RHEL-07-041004 ###
# if [[ -n "$(authconfig --test | grep -i 'pam_pkcs11 is enabled')" ]]; then
	# if [[ -z "$(authconfig --test | grep -i 'smartcard module = \n')" ]]; then
		# zero "SV-87059r3_rule" "authconfig --test | grep -i 'smartcard removal action = \n""' "
	# else
		# result "SV-87059r3_rule" "fail" "authconfig --test | grep -i 'smartcard module = \n'"
	# fi
# else
	# result "SV-87059r3_rule" "fail" "authconfig --test | grep -i 'pam_pkcs11 is enabled =\n'"
# fi


### V-73155 | RHEL-07-010081 ###
resetRule "SV-87807r4_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i '^\s*/org/gnome/desktop/screensaver/lock-delay' /etc/dconf/db/local.d/locks/*" "GNOME is installed and lock delay has been configured" "GNOME is installed and lock delay has NOT been configured"
fi

### V-73157 | RHEL-07-010082 ###
resetRule "SV-87809r4_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "egrep -i '^\s*/org/gnome/desktop/session/idle-delay' /etc/dconf/db/local.d/locks/*" "GNOME is installed an idle delay has been configured" "GNOME is installed an idle delay has NOT been configured"
fi

### V-73159 | RHEL-07-010119 ###
resetRule "SV-87811r4_rule"
nonzero "$rule" "grep pam_pwquality /etc/pam.d/system-auth | grep -v '^#' | grep retry=3" "Verified when passwords are changed or new passwords are established, pwquality is used, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified when passwords are changed or new passwords are established, pwquality is NOT used, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-73161 | RHEL-07-021021 ###
resetRule "SV-87813r2_rule"
zero "$rule" "grep nfs /etc/fstab | grep -vi noexec" "Verified file systems that are being imported via Network File System (NFS) are mounted to prevent binary files from being executed, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified file systems that are being imported via Network File System (NFS) are NOT mounted to prevent binary files from being executed, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-73163 | RHEL-07-030321 ###
resetRule "SV-87815r3_rule"
nonzero "$rule" "grep -i network_failure_action /etc/audisp/audisp-remote.conf | grep -v '^#' | egrep -i 'syslog|single|halt'" "Verified the audit system takes appropriate action when there is an error sending audit records to a remote system, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT take appropriate action when there is an error sending audit records to a remote system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-73165 | RHEL-07-030871 ###
resetRule "SV-87817r3_rule"
nonzero "$rule" "grep -i /etc/group /etc/audit/audit.rules  | grep -v '^#'" "Verified the operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/group, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-73167 | RHEL-07-030872 ###
resetRule "SV-87819r4_rule"
nonzero "$rule" "grep -i /etc/gshadow /etc/audit/audit.rules  | grep -v '^#'" "Verified the operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-73171 | RHEL-07-030873 ###
resetRule "SV-87823r4_rule"
nonzero "$rule" "grep -i /etc/shadow /etc/audit/audit.rules  | grep -v '^#'" "Verified the operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-73173 | RHEL-07-030874 ####
resetRule "SV-87825r5_rule"
nonzero "$rule" "grep -i /etc/security/opasswd /etc/audit/audit.rules  | grep -v '^#'" "Verified the operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-73175 | | RHEL-07-040641 ###
resetRule "SV-87827r4_rule"
if [[ -z "$(grep 'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0 )" ]]; then
	fail "$rule" "grep 'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 0"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'net.ipv4.conf.all.accept_redirects = 0'" "Verified the system ignores Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-73177 | RHEL-07-041010 ###
resetRule "SV-87829r2_rule"
zero "$rule" "nmcli device | grep -i wifi" "Verified wireless network adapters are disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified wireless network adapters are NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-77819 | RHEL-07-010061 ###
resetRule "SV-92515r2_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
        na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
        nonzero "$rule" "grep -ir '^[^#]*enable-smartcard-authentication=true' /etc/dconf/db/local.d/*" "GNOME is installed and smart card authentication has been enabled" "GNOME is NOT installed and smart card authentication has been enabled"
fi


### V-77821 | RHEL-07-020101 ###
resetRule "SV-92517r3_rule"
nonzero "$rule" "grep -i 'blacklist dccp\|install dccp /bin/true' /etc/modprobe.d/blacklist.conf /etc/modprobe.d/dccp.conf | grep -v '^#' | wc -l | awk '\$0 > 1'" "Verified the Datagram Congestion Control Protocol (DCCP) kernel module is disabled, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Datagram Congestion Control Protocol (DCCP) kernel module is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-77823 | RHEL-07-010481 ###
resetRule "SV-92519r2_rule"
nonzero "$rule" "grep -i execstart /usr/lib/systemd/system/rescue.service | grep -i /usr/sbin/sulogin | grep -v '^#' " "Verified the operating system requires authentication upon booting into single-user and maintenance modes, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT require authentication upon booting into single-user and maintenance modes, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-77825 | RHEL-07-040201 ###
resetRule "SV-92521r2_rule"
if [[ -z "$(grep 'kernel.randomize_va_space' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 2 )" ]]; then
	fail "$rule" "grep 'grep kernel.randomize_va_space' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 2"
else	
	nonzero "$rule" "/sbin/sysctl -a | grep 'kernel.randomize_va_space = 2'" "Verified the operating system implements virtual address space randomization, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT implement virtual address space randomization, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-78995 | RHEL-07-010062 ######
#removed in r1v2, returned in v2r3 with some changes
resetRule "SV-93701r2_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
	na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
	nonzero "$rule" "grep -i '^[^#]*/org/gnome/desktop/screensaver/lock-enabled' /etc/dconf/db/*.d/locks/*" "GNOME is installed and lock-enabled has been configured" "GNOME is NOT installed and lock-enabled has been configured"
fi

### V-78997 | RHEL-07-010101 ###
resetRule "SV-93703r2_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
        na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
        nonzero "$rule" "grep -i '^[^#]*/org/gnome/desktop/screensaver/idle-activation-enabled' /etc/dconf/db/*.d/locks/*" "GNOME is installed and lock-enabled has been configured" "GNOME is installed and lock-enabled has NOT been configured"
fi

### V-78999 | RHEL-07-030819 ###
resetRule "SV-93705r3_rule"
nonzero "$rule" "grep -iw '^[^#]*create_module' /etc/audit/audit.rules | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the create_module command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the create_module command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-79001 | RHEL-07-030821 ###
resetRule "SV-93707r3_rule"
nonzero "$rule" "grep -iw finit_module /etc/audit/audit.rules | grep -v '^#' | grep 'b32\|b64' | wc -l | grep 2" "Verified all uses of the finit command are audited, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all uses of the finit command are NOT audited, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81003 | RHEL-07-010118 ###
resetRule "SV-95715r1_rule"
nonzero "$rule" "cat /etc/pam.d/passwd | grep -i substack | grep -i system-auth" "Verified the Red Hat Enterprise Linux operating system is configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system is NOT configured so that /etc/pam.d/passwd implements /etc/pam.d/system-auth when changing passwords, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81005 | RHEL-07-010482 ###
resetRule "SV-95717r1_rule"
if [[ -d /sys/firmware/efi ]]; then
	na "$rule" "EFI/UEFI in use'"
else
	if [[ -z "$(echo "$RHELverNumb" | grep -Eo '7.[2-9]')" ]]; then
		# RHEL running version prior to 7.2
		na "$rule" "$HOSTNAME is running RHEL $RHELverNumb. This requirement is Not Applicable." "Verified the Red Hat Enterprise Linux operating system is version 7.2 or newer with a Basic Input/Output System (BIOS) that requires authentication upon booting into single-user and maintenance modes, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else	
		if [[ -z "$(grep -iw grub2_password=grub.pbkdf2.sha512 /boot/grub2/user.cfg)" ]]; then
			fail "$rule" "grep -iw grub2_password=grub.pbkdf2.sha512 /boot/grub2/user.cfg" "The system does not require valid root authentication before it boots into single-user or maintenance mode"
		else
			nonzero "$rule" "grep -iw superusers= /boot/grub2/grub.cfg | grep root" "Verified the Red Hat Enterprise Linux operating systems version 7.2 or newer with a Basic Input/Output System (BIOS) requires authentication upon booting into single-user and maintenance modes, therefore the reference STIG is not a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating systems is NOT version 7.2 or newer with a Basic Input/Output System (BIOS) requires authentication upon booting into single-user and maintenance modes, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
		fi
	fi	
fi

### V-81007 |  RHEL-07-010491	 ###
resetRule "SV-95719r1_rule"
if [[ -d /sys/firmware/efi ]]; then
	if [[ -z "$(echo "$RHELverNumb" | grep -Eo '7.[2-9]')" ]]; then
		na "$rule" "$HOSTNAME is running RHEL $RHELverNumb. This requirement is Not Applicable." "Verified the Red Hat Enterprise Linux operating system is version 7.2 or newer with a Basic Input/Output System (BIOS) that requires authentication upon booting into single-user and maintenance modes, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else	
		if [[ -z "$(grep -iw grub2_password=grub.pbkdf2.sha512 /boot/efi/EFI/redhat/user.cfg)" ]]; then
			fail "$rule" "grep -iw grub2_password=grub.pbkdf2.sha512 /boot/efi/EFI/redhat/user.cfg"
		else
			nonzero "$rule" "grep -iw superusers= /boot/efi/EFI/redhat/user.cfg | grep root" "grub password has been configured" "grub password has NOT been configured"
		fi
	fi	
else
	na "$rule" "ls -al /sys/firmware/efi" "Verified the system uses BIOS, therefore this is Not Applicable."
fi

### V-81009 | RHEL-07-021022	 ###
resetRule "SV-95721r2_rule"
if [[ -z $(mount | grep "/dev/shm") ]]; then
        pass "$rule" "mount | grep \"/dev/shm\"" "Verified shm mount is not being used, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	if [[ -n "$(cat '/etc/fstab' | grep '/dev/shm' | grep -v 'nodev')" ]]; then	
		fail "$rule" "cat '/etc/fstab' | grep '/dev/shm' | grep -v 'nodev'"
	else
		nonzero "$rule" "mount | grep '/dev/shm' | grep 'nodev'" "Verified the Red Hat Enterprise Linux operating system mounts /dev/shm with the nodev option, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT mount /dev/shm with the nodev option, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
fi

### V-81011 | RHEL-07-021023 ###
resetRule "SV-95723r2_rule"
if [[ -z $(mount | grep "/dev/shm") ]]; then
        pass "$rule" "mount | grep \"/dev/shm\"" "Verified shm mount is not being used, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	if [[ -n "$(cat '/etc/fstab' | grep '/dev/shm' | grep -v 'nosuid')" ]]; then	
		fail "$rule" "cat '/etc/fstab' | grep '/dev/shm' | grep -v 'nosuid'"
	else
		nonzero "$rule" "mount | grep '/dev/shm' | grep 'nosuid'" "Verified the Red Hat Enterprise Linux operating system mounts /dev/shm with the nosuid option, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT mount /dev/shm with the nosuid option, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
fi

### V-81013 | RHEL-07-021023 ###
resetRule "SV-95725r2_rule"
if [[ -z $(mount | grep "/dev/shm") ]]; then
	pass "$rule" "mount | grep \"/dev/shm\"" "Verified shm mount is not being used, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	if [[ -n "$(cat '/etc/fstab' | grep '/dev/shm' | grep -v 'noexec')" ]]; then	
		fail "$rule" "cat '/etc/fstab' | grep '/dev/shm' | grep -v 'noexec'"
	else
		nonzero "$rule" "mount | grep '/dev/shm' | grep 'noexec'" "Verified the Red Hat Enterprise Linux operating system mounts /dev/shm with the noexec option, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT mount /dev/shm with the noexec option, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
fi

### V-81015 | RHEL-07-030200 ###
resetRule "SV-95727r1_rule"
nonzero "$rule" "grep active /etc/audisp/plugins.d/au-remote.conf | grep -v '^#' | egrep -i 'yes'" "Verified the Red Hat Enterprise Linux operating system is configured to use the au-remote plugin, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system is NOT configured to use the au-remote plugin, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-81017 | RHEL-07-030201 ###
resetRule "SV-95729r1_rule"
if [[ -z "$(grep direction /etc/audisp/plugins.d/au-remote.conf | grep out | grep -v '^#')" ]]; then
	fail "$rule" ""
else
	if [[ -z "$(grep path /etc/audisp/plugins.d/au-remote.conf | grep '/sbin/audisp-remote' | grep -v '^#')" ]]; then
		fail "$rule" ""
	else
		nonzero "$rule" "grep type /etc/audisp/plugins.d/au-remote.conf | grep always | grep -v '^#'" "Verified the Red Hat Enterprise Linux operating system configures the au-remote plugin to off-load audit logs using the audisp-remote daemon, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT configure the au-remote plugin to off-load audit logs using the audisp-remote daemon, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
fi

### V-81019 | RHEL-07-030210 ###
resetRule "SV-95731r1_rule"
nonzero "$rule" "grep -i overflow_action /etc/audisp/audispd.conf | grep -v '^#' | egrep -i 'syslog|single|halt'" "Verified the Red Hat Enterprise Linux operating system takes appropriate action when the audisp-remote buffer is full, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT appropriate action when the audisp-remote buffer is full, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

###  V-81021 | RHEL-07-030211 ###
resetRule "SV-95733r1_rule"
nonzero "$rule" "grep -i name_format /etc/audisp/audispd.conf | grep -v '^#' | egrep -i 'hostname|fqd|numeric'" "Verified the Red Hat Enterprise Linux operating system labels all off-loaded audit logs before sending them to the central log server, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT label all off-loaded audit logs before sending them to the central log server, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

###  V-92251 | RHEL-07-040611 ###
resetRule "SV-102353r1_rule"
if [[ -n "$(grep 'net.ipv4.conf.all.rp_filter' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 1)" ]] && [[ -z "$(grep 'net.ipv4.conf.all.rp_filter' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep -v 1)" ]]; then
	nonzero "$rule" "/sbin/sysctl -a | grep net.ipv4.conf.all.rp_filter | grep 1" "Verified the Red Hat Enterprise Linux operating system uses a reverse-path filter for IPv4 network traffic when possible on all interfaces, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT use a reverse-path filter for IPv4 network traffic when possible on all interfaces, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	fail "$rule" "grep 'net.ipv4.conf.all.rp_filter' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#'"
fi

###  V-92253 | RHEL-07-040612 ###
resetRule "SV-102355r1_rule"
if [[ -n "$(grep 'net.ipv4.conf.default.rp_filter' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep 1)" ]] && [[ -z "$(grep 'net.ipv4.conf.default.rp_filter' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#' | grep -v 1)" ]]; then
	nonzero "$rule" "/sbin/sysctl -a | grep net.ipv4.conf.default.rp_filter | grep 1" "Verified the Red Hat Enterprise Linux operating system uses a reverse-path filter for IPv4 network traffic when possible by default, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the Red Hat Enterprise Linux operating system does NOT use a reverse-path filter for IPv4 network traffic when possible by default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	fail "$rule" "grep 'net.ipv4.conf.default.rp_filter' /etc/sysctl.conf /etc/sysctl.d/* | grep -v '^#'"
fi

###  V-92255 | RHEL-07-020019 ###
resetRule "SV-102357r1_rule"
if [[ -n "$(rpm -qa | grep -i 'MFEhiplsm')" ]] && [[ -n "$(ps -ef | grep -i 'hipclient' | grep -vi 'grep')" ]]; then
	pass "$rule" "rpm -qa | grep -i 'MFEhiplsm'; ps -ef | grep -i 'hipclient';"
elif [[ -n "$(sestatus | grep -i enforcing)" ]]; then
	pass "$rule" "sestatus" "Verified the Red Hat Enterprise Linux operating system has a host-based intrusion detection tool installed, namely SELinux, and that the use of this is documented with and approved by the local Authorizing Official, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nr "$rule" "echo 'Manual check for HIPS installed and active on this OS as the preferred HIPS, McAfee HBSS, is not installed or active.'; rpm -qa | grep -i 'MFEhiplsm'; ps -ef | grep -i 'hipclient' | grep -vi 'grep';"
fi

### V-94843 | RHEL-07-020231 ######
resetRule "SV-104673r1_rule"
if [[ -z "$(yum list installed | grep gnome)" ]]; then
        na "$rule" "yum list installed | grep gnome" "Verified that the system does not have GNOME installed making this requirement Not Applicable."
else
        nonzero "$rule" "grep -i '^[^#]*org/gnome/settings-daemon/plugins/media-keys' /etc/dconf/db/*.d/00-disable-CAD | grep logout=''" "GNOME is installed and logout has been configured" "GNOME is installed and logout has NOT been configured"
fi


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
