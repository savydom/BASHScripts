#!/bin/bash
#
#
# Set current Version/Release # for this STIG Checklist script
cklVersion="V1R20"

#Set unclean variable. If set to 1, special characters won't be converted to the XML equivalent
if [[ "$(echo $1 | grep [Uu][Nn][Cc][Ll][Ee][Aa][Nn])" ]] || [[ "$(echo $2 | grep [Uu][Nn][Cc][Ll][Ee][Aa][Nn])" ]]; then
	unclean=1
fi

# We want to redirect all output (stdout and stderr to /tmp/RHEL_Lockdown.log
# Setup file descriptor 3 to point to stdout, we can use this if we need to output to the console
tempOut="/tmp/Validation_Sol11SPARC_${cklVersion}.log"
exec 3>&1
exec 1>$tempOut 2>&1

# Create the result file
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RESULTS="$DIR/Validation_Sol11SPARC_${cklVersion}_Results.$HOSTNAME.$(date +%F_%H.%M)_XCCDF.ckl"

############### Result Functions ###############

### Zero Test ###
#Accepted format: RuleID, Test
#If it should come back as zero and pass, use this function
#$1 Rule ID
#$2 Test Criteria
#$3 Passed variable (comment) variable
#$4 Failed variable (comment) variable
#$5 Visible Test Criteria
function zero() {
        echo "Check $1"
        comment=$3
        commentFail=$4
        result="$(eval $2)"
        if [[ -z "$result" ]]; then
           if [[ -z $5 ]]; then
             result "$1" "pass" "$2" "$result" "$comment"
           else
             result "$1" "pass" "$5" "$result" "$comment"
           fi
        else
           if [[ -z $5 ]]; then
             result "$1" "fail" "$2" "$result" "$commentFail"
           else
             result "$1" "fail" "$5" "$result" "$commentFail"
           fi
        fi
        unset result comment
}

### Non-Zero Test ###
#Accepted format: RuleID, Test
#If it should come back as non-zero and pass, use this function
#$1 Rule ID
#$2 Test Criteria
#$3 Passed variable (comment) variable
#$4 Failed variable (commnet) variable
#$5 Visible Test Criteria
function nonzero() {
        echo "Check $1"
        comment=$3
        commentFail=$4
        result="$(eval $2)"
        if [[ -n "$result" ]]; then
           if [[ -z $5 ]]; then
             result "$1" "pass" "$2" "$result" "$comment"
           else
             result "$1" "pass" "$5" "$result" "$comment"
           fi
        else
           if [[ -z $5 ]]; then
             result "$1" "fail" "$2" "$result" "$commentFail"
           else
             result "$1" "fail" "$5" "$result" "$commentFail"
           fi
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
	printf "	<FINDING_DETAILS># " >> $RESULTS
#If a 'clean' flag is given, results will clean XML special characters and make them XML appropriate
	if [[ $unclean -eq 1 ]]; then
		printf "$3\n" >> $RESULTS
		echo "" >> $RESULTS
		printf "$4\n" >> $RESULTS
	else
		printf "$3\n" | sed  's/\&/\&amp;/g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g' | sed "s/'/\&apos;/g" | sed 's/\"/\&quot;/g' >> $RESULTS
		echo "" >> $RESULTS
		printf "$4\n" | sed  's/\&/\&amp;/g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g' | sed "s/'/\&apos;/g" | sed 's/\"/\&quot;/g' >> $RESULTS
	fi
	echo "	</FINDING_DETAILS>" >> $RESULTS
	echo "	<COMMENTS>$(echo $5 | sed  's/\&/\&amp;/g' | sed 's/</\&lt;/g' | sed 's/>/\&gt;/g' | sed "s/'/\&apos;/g" | sed 's/\"/\&quot;/g')</COMMENTS>" >> $RESULTS
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

### get information about the SOLARIS version/configuration ###
SOLver=""
IPaddr=$(ifconfig -a | awk '($1=="inet"){print$2}' | awk -F. '($1!="0"&&$1!="127"&&$1!="addr:0"&&$1!="addr:127"){print$0}' | xargs -e"\n")
macAddr=$(echo $IPaddr | awk -F" " '{for(i=1;i<=NF;i++){print $i;}}' | xargs -i sh -c "netstat -pn | grep "{$1}" | grep SP | awk '{print\$5}'" | xargs -e"\n")
SOLverNumb=$(uname -v)

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
echo "		<HOST_FQDN>$SOLver</HOST_FQDN>" >> $RESULTS
echo "		<TECH_AREA>UNIX OS</TECH_AREA>" >> $RESULTS
echo "		<TARGET_KEY>2107</TARGET_KEY>" >> $RESULTS
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
echo "					<SID_DATA>Solaris 11 SPARC Security Technical Implementation Guide</SID_DATA>" >> $RESULTS
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

### V-47781 ###
resetRule "SV-60657r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified the audit system must produce records containing sufficient information to establish the identity of any user/subject associated with the event, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT produce records containing sufficient information to establish the identity of any user/subject associated with the event, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47783 ###
resetRule "SV-60659r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified the audit system must support an audit reduction capability, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT support an audit reduction capability, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47785 ###
resetRule "SV-60661r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified the audit system records must be able to be used by a report generation capability, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system records is NOT able to be used by a report generation capability, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47787 ###
resetRule "SV-60663r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified the operating system must provide the capability to automatically process audit records for events of interest based upon selectable, event criteria, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT provide the capability to automatically process audit records for events of interest based upon selectable, event criteria, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47789 ###
resetRule "SV-60665r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified the audit records must provide data for all auditable events defined at the organizational level for the organization-defined information system components, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit records does NOT provide data for all auditable events defined at the organizational level for the organization-defined information system components, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47791 ###
resetRule "SV-60667r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified the operating system must generate audit records for the selected list of auditable events as defined in DoD list of events, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT generate audit records for the selected list of auditable events as defined in DoD list of events, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47793 ###
resetRule "SV-60669r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified the operating system must support the capability to compile audit records from multiple components within the system into a system-wide (logical or physical) audit trail that is time-correlated to within organization-defined level of tolerance, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT support the capability to compile audit records from multiple components within the system into a system-wide (logical or physical) audit trail that is time-correlated to within organization-defined level of tolerance, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47795 ###
resetRule "SV-60671r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified audit records must include what type of events occurred, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified NOT, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47797 ###
resetRule "SV-60673r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified audit records must include when (date and time) the events occurred, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified audit records does NOT include when (date and time) the events occurred, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47799 ###
resetRule "SV-60675r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified audit records must include where the events occurred, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified audit records does NOT include where the events occurred, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47801 ###
resetRule "SV-60677r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified audit records must include the sources of the events that occurred, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified audit records does NOT include the sources of the events that occurred, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47803 ###
resetRule "SV-60679r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getcond | grep 'auditing'" "Verified audit records must include the outcome (success or failure) of the events that occurred, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified audit records does NOT include the outcome (success or failure) of the events that occurred, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47805 ###
resetRule "SV-60681r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
    if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'fd') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit file deletions (Flags:FD), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit file deletions (Flags:FD), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
    if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'fd') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit file deletions (Flags:FD), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit file deletions (Flags:FD), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47807 ###
resetRule "SV-60683r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
    if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'ps') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account creation (Flags:PS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account creation (Flags:PS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
    if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account creation (Flags:CUSA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account creation (Flags:CUSA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47809 ###
resetRule "SV-60685r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'ps') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account modification (Flags:PS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account modification (Flags:PS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then 
	if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account modification (Flags:CUSA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account modification (Flags:CUSA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47811 ###
resetRule "SV-60687r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'ps') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account disabling actions (Flags:PS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account disabling actions (Flags:PS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account disabling actions (Flags:CUSA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account disabling actions (Flags:CUSA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47813 ###
resetRule "SV-60689r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'ps') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account termination (Flags:PS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account termination (Flags:PS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi 
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit account termination (Flags:CUSA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit account termination (Flags:CUSA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  fi
else
  na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47815 ###
resetRule "SV-60691r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'as') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit security-relevant configuration changes (Flags:AS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit security-relevant configuration changes (Flags:AS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
pass "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit security-relevant configuration changes (Flags:CUSA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -t -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit security-relevant configuration changes (Flags:CUSA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47817 ###
resetRule "SV-60693r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'as') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
		pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit all administrative, privileged, and security actions (Flags:AS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit all administrative, privileged, and security actions (Flags:AS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
		pass "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit all administrative, privileged, and security actions (Flags:CUSA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit all administrative, privileged, and security actions (Flags:CUSA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47819 ###
resetRule "SV-60695r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
    if [[ -n $(auditconfig -getflags | grep active | cut -f2 -d= | grep 'lo') && -n $(auditconfig -getnaflags | grep active | cut -f2 -d= | grep 'na') && -n $(auditconfig -getnaflags | grep active | cut -f2 -d= | grep 'lo') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -getflags | grep active; auditconfig -getnaflags | grep active; auditconfig -getpolicy | grep argv" "Verified the audit system IS configured to audit login, logout, and session initiation (Flags:LO NAFlags:LO,NA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -getflags | grep active; auditconfig -getnaflags | grep active; auditconfig -getpolicy | grep argv" "Verified the audit system is NOT configured to audit login, logout, and session initiation (Flags:LO NAFlags:LO,NA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
    if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -t -getnaflags | cut -f2 -d= | grep 'na') && -n $(auditconfig -t -getnaflags | cut -f2 -d= | egrep '(cusa|lo)') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -getflags; auditconfig -getnaflags; auditconfig -getpolicy | grep active | grep argv" "Verified the audit system IS configured to audit login, logout, and session initiation (Flags:CUSA NAFlags:CUSA or LO,NA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -getflags; auditconfig -getnaflags; auditconfig -getpolicy | grep active | grep argv" "Verified the audit system is NOT configured to audit login, logout, and session initiation (Flags:CUSA NAFlags:CUSA or LO,NA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47821 ###
resetRule "SV-60697r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
    if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'fm') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit all discretionary access control permission modifications (Flags:FM), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit all discretionary access control permission modifications (Flags:FM), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
    if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'fm') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
	pass "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit all discretionary access control permission modifications (Flags:FM), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit all discretionary access control permission modifications (Flags:FM), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47823 ###
resetRule "SV-60699r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep 'as') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
		pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit loading and unloading of dynamic kernel modules (Flags:AS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit loading and unloading of dynamic kernel modules (Flags:AS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep 'cusa') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
		pass "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit loading and unloading of dynamic kernel modules (Flags:CUSA), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit loading and unloading of dynamic kernel modules (Flags:CUSA), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47825 ###
resetRule "SV-60701r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	if [[ -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep '-fa') && -n $(auditconfig -t -getflags | grep active | cut -f2 -d= | grep '-ps') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
		pass "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit failed attempts to access files and programs (Flags:-FA,-PS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "auditconfig -getflags | grep active; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit failed attempts to access files and programs (Flags:-FA,-PS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	if [[ -n $(auditconfig -t -getflags | cut -f2 -d= | grep '-fa') && -n $(auditconfig -t -getflags | cut -f2 -d= | grep '-ex') && -n $(auditconfig -t -getflags | cut -f2 -d= | grep '-ps') && -n $(auditconfig -getpolicy | grep active | grep argv) ]]; then
		pass "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system IS configured to audit failed attempts to access files and programs (Flags:-FA,-EX,-PS), therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "auditconfig -getflags; auditconfig -getpolicy | grep argv" "Verified audit system is NOT configured to audit failed attempts to access files and programs (Flags:-FA,-EX,-PS), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47827 ###
resetRule "SV-60703r2_rule"
#syslog=$(svcs system-log | awk -F':' '{print $2}' | sed '/^\s*$/d')
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(auditconfig -getplugin | grep audit_syslog | grep '(active)') ]]; then
	if [[ -n $(/etc/init.d/splunk status) ]]; then
pass "$rule" "auditconfig -getplugin | grep audit_syslog | grep '(active)'; /etc/init.d/splunk status" "Verified the operating system must protect against an individual falsely denying having performed a particular action. In order to do so the system must be configured to send audit records to a remote audit server. This server uses Splunkforwarder to accomplish this directive, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	elif [[ -n $(grep audit.notice /etc/syslog.conf | grep -v '^\s*#') ]]; then
pass "$rule" "auditconfig -getplugin | grep audit_syslog | grep '(active)'; grep audit.notice /etc/syslog.conf | grep -v '^\s*#'" "Verified the operating system must protect against an individual falsely denying having performed a particular action. In order to do so the system must be configured to send audit records to a remote audit server, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -getplugin | grep audit_syslog; /etc/init.d/splunk status; grep audit.notice /etc/syslog.conf | grep -v '^\s*#'" "Verified the operating system does NOT protect against an individual falsely denying having performed a particular action. In order to do so the system must be configured to send audit records to a remote audit server, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  else
	fail "$rule" "auditconfig -getplugin | grep audit_syslog; /etc/init.d/splunk status; grep audit.notice /etc/syslog.conf | grep -v '^\s*#'" "Verified the operating system does NOT protect against an individual falsely denying having performed a particular action. In order to do so the system must be configured to send audit records to a remote audit server, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47831 ###
resetRule "SV-60705r1_rule"
	zero  "$rule" "logins -S files | awk '{print\$1}' | grep -v root | xargs -i userattr audit_flags {$1}" "Verified the auditing system does NOT define a different auditing level for specific users, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Users listed had flags returned. Verified the auditing system defines a different auditing level for specific users, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47835 ###
resetRule "SV-60709r1_rule"
sendmailWarn=""
if [[ -n $(zonename | grep global) ]]; then
sendmailWarn=$(/usr/lib/sendmail -bv audit_warn 2>&1)
  if [[ $sendmailWarn != "" ]]; then
	nonzero "$rule" "echo \"$sendmailWarn\" | grep -v 'User unknown'" "Verified the audit system must alert the SA when the audit storage volume approaches its capacity, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT alert the SA when the audit storage volume approaches its capacity, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "/usr/lib/sendmail -bv audit_warn"
  else
	fail "$rule" "/usr/lib/sendmail -bv audit_warn" "Verified the audit system does NOT alert the SA when the audit storage volume approaches its capacity, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi
# Using sendmailWarn in 60717 and 60719
#unset sendmailWarn

### V-47837 ###
resetRule "SV-60711r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	zero "$rule" "auditconfig -getpolicy | grep active | grep perzone" "Verified the audit system must maintain a central audit trail for all zones, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT maintain a central audit trail for all zones, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47839 ###
resetRule "SV-60713r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getpolicy | grep active | grep zonename" "Verified the audit system must identify in which zone an event occurred, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT identify in which zone an event occurred, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47841 ###
resetRule "SV-60715r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	zero "$rule" "zoneadm list | grep -v global | xargs -i sh -c \"if [[ -n \"{$1}\" ]]; then zonecfg -z \"{$1}\" info | grep dev;fi\"" "Verified the systems physical devices must not be assigned to non-global zones, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the systems physical devices IS assigned to non-global zones, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "zoneadm list | grep -v global"
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47843 ###
resetRule "SV-60717r1_rule"
#sendmailWarn carried over from 60709
#sendmailWarn=""
if [[ -n $(zonename | grep global) ]]; then
#sendmailWarn=$(/usr/lib/sendmail -bv audit_warn 2>&1)
  if [[ $sendmailWarn != "" ]]; then
	nonzero "$rule" "echo \"$sendmailWarn\" | grep -v 'User unknown'" "Verified the audit system must alert the SA if there is any type of audit failure, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the audit system does NOT alert the SA if there is any type of audit failure, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "/usr/lib/sendmail -bv audit_warn"
  else
	fail "$rule" "/usr/lib/sendmail -bv audit_warn" "Verified the audit system does NOT alert the SA if there is any type of audit failure, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi
#unset sendmailWarn

### V-47845 ###
resetRule "SV-60719r1_rule"
#sendmailWarn carried over from previous item
#sendmailWarn=""
if [[ -n $(zonename | grep global) ]]; then
#sendmailWarn=$(/usr/lib/sendmail -bv audit_warn 2>&1)
  if [[ -n $(/usr/lib/sendmail -bv audit_warn) ]]; then
	nonzero "$rule" "echo \"$sendmailWarn\" | grep -v 'User unknown'" "Verified the OS must alert designated organizational officials in the event of an audit processing failure, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the OS does NOT alert designated organizational officials in the event of an audit processing failure, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "/usr/lib/sendmail -bv audit_warn"
  else
	fail "$rule" "/usr/lib/sendmail -bv audit_warn" "Verified the OS does NOT alert designated organizational officials in the event of an audit processing failure, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi
unset sendmailWarn

### V-47857 ###
resetRule "SV-60731r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(auditconfig -getplugin audit_binfile | awk -F';' '{print$4}' | awk -F'=' '{print$2}' | awk '$0>=2') ]]; then
    if [[ -n $(zfs get -H compression,quota,reservation $(df -h $(auditconfig -getplugin audit_binfile | awk -F';' '{print $2}' | awk -F'=' '{print $2}') | awk -F' ' '{print $1}' | tail -1) | egrep '(compression'.'off|quota'.'none|reservation'.'none)') ]]; then
	fail "$rule" "zfs get compression,quota,reservation $(df -h $(auditconfig -getplugin audit_binfile | awk -F';' '{print $2}' | awk -F'=' '{print $2}') | awk -F' ' '{print $1}' | tail -1)" "Verified the operating system does NOT allocate audit record storage capacity, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
	pass "$rule" "zfs get compression,quota,reservation $(df -h $(auditconfig -getplugin audit_binfile | awk -F';' '{print $2}' | awk -F'=' '{print $2}') | awk -F' ' '{print $1}' | tail -1)" "Verified the operating system does allocate audit record storage capacity, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    fi
  else
	fail "$rule" "auditconfig -getplugin audit_binfile" "Verified the operating system does NOT allocate audit record storage capacity, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47863 ###
resetRule "SV-60737r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(auditconfig -getpolicy | grep ahlt) && -z $(auditconfig -getpolicy | grep active | grep cnt) ]]; then
	pass "$rule" "auditconfig -getpolicy | grep ahlt; auditconfig -getpolicy | grep active | grep cnt" "Verified the operating system must shut down by default upon audit failure (unless availability is an overriding concern), the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	fail "$rule" "auditconfig -getpolicy | grep ahlt; auditconfig -getpolicy | grep active | grep cnt" "Verified the operating system does NOT shut down by default upon audit failure (unless availability is an overriding concern), the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47869 ###
resetRule "SV-60741r1_rule"
if [[ -n $(zonename | grep global) ]]; then
  auditDir=$(readlink -f $(auditconfig -getplugin audit_binfile | awk -F';' '{print$2}' | awk -F'=' '{print$2}' | sed '/^\s*$/d'))
  auditPerm=$(stat -c '%a' $auditDir)
	nonzero "$rule" "ls -ld $auditDir | awk '(\$3==\"root\"&&\$4==\"root\"){print}' && echo \"$auditPerm\" | awk '\$0<=640'" "Verified the operating system must protect audit information from unauthorized read access, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT protect audit information from unauthorized read access, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -ld $auditDir"
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi
#auditDir and auditPerm used in subsequent checks
#unset auditDir auditPerm

### V-47875 ###
resetRule "SV-60747r1_rule"
#auditDir and auditPerm from previous check used
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "ls -ld $auditDir | awk '(\$3==\"root\"&&\$4==\"root\"){print}' && echo \"$auditPerm\" | awk '\$0<=640'" "Verified the operating system must protect audit information from unauthorized modification, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT protect audit information from unauthorized modification, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -ld $auditDir"
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi
#auditDir and auditPerm used in subsequent checks

### V-47879 ###
resetRule "SV-60751r1_rule"
#auditDir and auditPerm from previous check used
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "ls -ld $auditDir | awk '(\$3==\"root\"&&\$4==\"root\"){print}' && echo \"$auditPerm\" | awk '\$0<=640'" "Verified the operating system must protect audit information from unauthorized deletion, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT protect audit information from unauthorized deletion, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -ld $auditDir"
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi
unset auditDir auditPerm

### V-47881 ###
resetRule "SV-60753r2_rule"
	nonzero "$rule" "pkg update -n | grep \"No updates available for this image\"; beadm list" "Verified the System packages must be up to date with the most recent vendor updates and security fixes, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the System packages is NOT up to date with the most recent vendor updates and security fixes, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47883 ###
resetRule "SV-60755r1_rule"
	nonzero "$rule" "pkg property | grep signature-policy | grep verify" "Verified the system must verify that package updates are digitally signed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT verify that package updates are digitally signed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47885 ###
resetRule "SV-60757r1_rule"
pkgverErr=""
if [[ -n $(pkg property | grep signature-policy | grep -i verify) ]]; then
  echo "Running PKG VERIFY, this may take a while" >> /dev/tty
  pkgverErr=$(pkg verify 2>/dev/null | sed '/[Ee][Rr][Rr][Oo][Rr]/ {;N;s/\n.*/&\\n/;}')
	zero "$rule" "$(echo \"$pkgverErr\")" "Verified the operating system protects audit tools from unauthorized access and is configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system protects audit tools from unauthorized access however, the system may not be configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg verify 2>/dev/null | grep -i Error"
else
	fail "$rule" "pkg property | grep signature-policy | grep -i verify" "Verified the operating system does NOT protect audit tools from unauthorized access, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-47887 ###
resetRule "SV-60759r1_rule"
if [[ -n $(pkg property | grep signature-policy | grep -i verify) ]]; then
	zero "$rule" "$(echo \"$pkgverErr\")" "Verified the operating system protects audit tools from unauthorized modification and is configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system protects audit tools from unauthorized modification however, the system may not be configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg verify 2>/dev/null | grep -i Error"
else
        fail "$rule" "pkg property | grep signature-policy | grep -i verify" "Verified the operating system does NOT protect audit tools from unauthorized access, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-47889 ###
resetRule "SV-60761r1_rule"
if [[ -n $(pkg property | grep signature-policy | grep -i verify) ]]; then
	zero "$rule" "$(echo \"$pkgverErr\")" "Verified the operating system protects audit tools from unauthorized deletion and is configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system protects audit tools from unauthorized deletion however, the system may not be configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg verify 2>/dev/null | grep -i Error"
else
        fail "$rule" "pkg property | grep signature-policy | grep -i verify" "Verified the operating system does NOT protect audit tools from unauthorized access, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-47891 ###
resetRule "SV-60763r1_rule"
if [[ -n $(pkg property | grep signature-policy | grep -i verify) ]]; then
	zero "$rule" "$(echo \"$pkgverErr\")" "Verified the operating system is configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system may not be configured with the vendor-provided files, permissions, and ownerships, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg verify 2>/dev/null | grep -i Error"
else
        fail "$rule" "pkg property | grep signature-policy | grep -i verify" "Verified the operating system does NOT protect audit tools from unauthorized access, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi
unset pkgverErr

### V-47893 ###
resetRule "SV-60765r1_rule"
	zero "$rule" "pkg list service/network/finger | grep '\d*'" "Verified the finger daemon package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the finger daemon package IS installed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list service/network/finger"

### V-47895 ###
resetRule "SV-60767r3_rule"
testFail=false
output=""
if [[ -n $(zoneadm list | grep -v global) ]]; then
	zones=$(zoneadm list | grep -v global)
	for i in $zones; do
	  if [[ -z $(zoneadm list -cv | grep $i | grep solaris-kz) ]]; then
 	    if [[ -n $(zonecfg -z $i info | grep limitpriv | grep default) ]]; then
		$nothing
	    else
		testFail=true
		output+="$i ; "
	    fi
	  fi
	done
	if [[ $testFail = "true" ]]; then
		fail "$rule" "$(echo $output); echo 'Zones listed have limitpriv not set to vendor defaults'" "Verified the limitpriv zone option is NOT set to the vendor default or less permissive, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	else
		pass "$rule" "zoneadm list -vi | grep -v global" "Verified the limitpriv zone option IS set to the vendor default or less permissive, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	fi
else
	pass "$rule" "zoneadm list -vi | grep -v global" "Verified non-global zones do not exist on the system, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi
unset testFail output

### V-47897 ###
resetRule "SV-60769r1_rule"
	zero "$rule" "pkg verify system/zones 2>/dev/null | grep -i Error" "Verified the /etc/zones directory, and its contents, have the vendor default owner, group, and permissions, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the /etc/zones directory, and its contents, do NOT have the vendor default owner, group, and permissions, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg verify system/zones"

### V-47899 ###
resetRule "SV-60771r1_rule"
	pass "$rule" "cat /etc/project | awk -F: '{print$2}' | xargs -i prctl -P -i project {$1}" "Verified the operating system manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial of service attacks, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-47901 ###
resetRule "SV-60773r1_rule"
	zero "$rule" "pkg list service/network/legacy-remote-utilities | grep '\d*'" "Verified the legacy remote network access utilities daemons is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the legacy remote network access utilities daemons IS installed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list service/network/legacy-remote-utilities"

### V-47903 ###
resetRule "SV-60775r1_rule"
	pass "$rule" "" "Verified the operating system identifies potentially security-relevant error conditions, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-47905 ###
resetRule "SV-60777r1_rule"
	zero "$rule" "pkg list service/network/nis | grep '\d*'" "Verified the NIS package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the NIS package IS installed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list service/network/nis"

### V-47907 ###
resetRule "SV-60779r1_rule"
	pass "$rule" "" "Verified the operating system verifies the correct operation of security functions in accordance with organization-defined conditions and in accordance with organization-defined frequency (if periodic verification), therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-47909 ###
resetRule "SV-60781r1_rule"
	zero "$rule" "pkg list communication/im/pidgin | grep '\d*'" "Verified the pidgin IM client package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the pidgin IM client package IS installed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list communication/im/pidgin"

### V-47911 ###
resetRule "SV-60783r1_rule"
	zero "$rule" "pkg list service/network/ftp | grep '\d*'" "Verified the FTP daemon package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the FTP daemon package IS installed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list service/network/ftp"

### V-47913 ###
resetRule "SV-60785r2_rule"
	zero "$rule" "pkg list service/network/tftp | grep '\d*'" "Verified the tFTP daemon package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the tFTP daemon package IS installed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list service/network/tftp"

### V-47915 ###
resetRule "SV-60787r2_rule"
	zero "$rule" "pkg list service/network/telnet | grep '\d*'" "Verified the telnet service daemon package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the telnet service daemon package IS installed, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list service/network/telnet"

### V-47917 ###
resetRule "SV-60789r2_rule"
	zero "$rule" "pkg list /service/network/uucp | grep '\d*'" "Verified the UUCP service daemon package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the UUCP service daemon package IS installed, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list /service/network/uucp"

### V-47919 ###
resetRule "SV-60791r2_rule"
	nonzero "$rule" "svcprop -p config/local_only network/rpc/bind | grep true" "Verified the rpcbind service IS configured for local only services unless organizationally defined, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rpcbind service is NOT configured for local only services unless organizationally defined, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "svcprop -p config/local_only network/rpc/bind"

### V-47921 ###
resetRule "SV-60793r1_rule"
	zero "$rule" "pkg list x11/server/xvnc | grep '\d*'" "Verified the VNC server package is NOT installed, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the VNC server package IS installed, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pkg list x11/server/xvnc"

### V-47923 ###
resetRule "SV-60795r1_rule"
if [[ -z $(pkg history -o finish,user,operation,command | grep '/usr/bin/packagemanager install') ]]; then
	pass "$rule" "pkg history -o finish,user,operation,command | grep '/usr/bin/packagemanager install'" "Verified the operating system must employ automated mechanisms, per organization-defined frequency, to detect the addition of unauthorized components/devices into the operating system, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	nr "$rule" "pkg history -o finish,user,operation,command | grep '/usr/bin/packagemanager install' | awk '{print\$NF}'" "Verified the operating system must employ automated mechanisms, per organization-defined frequency, to detect the addition of unauthorized components/devices into the operating system. If any Packagemanager installed software packages are listed, verify software packages installed are authorized"
fi

### V-47925 ###
resetRule "SV-60797r1_rule"
	nr "$rule" "pkg list" "Verified the operating system must be configured to provide essential capabilities. Verify all software packages installed are authorized."

### V-47927 ###
resetRule "SV-60799r1_rule"
	nr "$rule" "pkg list" "Verified the operating system must be configured to provide essential capabilities. Verify all software packages installed are authorized."

### V-47929 ###
resetRule "SV-60801r1_rule"
	zero "$rule" "svcprop -p options/tcp_listen svc:/application/x11/x11-server | grep true" "Verified the graphical login service either is disabled or doesn't exist, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the graphical login service either is NOT disabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "svcprop -p options/tcp_listen svc:/application/x11/x11-server"

### V-47931 ###
resetRule "SV-60803r1_rule"
	zero "$rule" "svcs -Ho state svc:/network/rpc/gss | grep online" "Verified generic Security Services (GSS) IS disabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified generic Security Services (GSS) is NOT disabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "svcs -Ho state svc:/network/rpc/gss"

### V-47933 ###
resetRule "SV-60805r1_rule"
	nr "$rule" "svcs -a | grep online" "Document all enabled services and disable any that are not required."

### V-47935 ###
resetRule "SV-60807r2_rule"
if [[ -n $(inetadm -p | grep tcp_wrappers | grep -i false) ]]; then
  if [[ (-f /etc/hosts.deny && -n $(grep -v '^#' /etc/hosts.deny)) && (-f /etc/hosts.allow && -n $(grep -v '^#' /etc/hosts.allow)) ]]; then
	fail "$rule" "inetadm -p | grep tcp_wrappers; egrep -v '\(^#|^\$|^\\s+\$\)' /etc/hosts.*" "Verified TCP Wrappers are NOT enabled and configured per site policy to only allow access by approved hosts and services. However hosts.allow and hosts.deny ARE configured correctly, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  else
	fail "$rule" "inetadm -p | grep tcp_wrappers; egrep -v '\(^#|^\$|^\\s+\$\)' /etc/hosts.*" "Verified TCP Wrappers are NOT enabled and configured per site policy to only allow access by approved hosts and services, and hosts.allow and/or hosts.deny are NOT configured correctly, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
  if [[ (-f /etc/hosts.deny && -n $(grep -v '^#' /etc/hosts.deny)) && (-f /etc/hosts.allow && -n $(grep -v '^#' /etc/hosts.allow)) ]]; then
	pass "$rule" "inetadm -p | grep tcp_wrappers; egrep -v '\(^#|^\$|^\\s+\$\)' /etc/hosts.*" "Verified TCP Wrappers IS enabled and configured per site policy to only allow access by approved hosts and services, and hosts.allow and hosts.deny ARE configured correctly, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	fail "$rule" "inetadm -p | grep tcp_wrappers; egrep -v '\(^#|^\$|^\\s+\$\)' /etc/hosts.*" "Verified TCP Wrappers IS enabled and configured per site policy to only allow access by approved hosts and services. However, hosts.allow and/or hosts.deny are NOT configured correctly, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-47937 ###
resetRule "SV-60809r1_rule"
	pass "$rule" "which pfedit" "Verified all manual editing of system-relevant files shall be done using the pfedit command, which logs changes made to the files, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-47939 ###
resetRule "SV-60811r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	zero "$rule" "svcs -Ho state svc:/system/filesystem/rmvolmgr:default | grep online" "Verified the operating system must disable information system functionality that provides the capability for automatic execution of code on mobile devices without user direction, the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT disable information system functionality that provides the capability for automatic execution of code on mobile devices without user direction, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "svcs -Ho state svc:/system/filesystem/rmvolmgr:default"
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47941 ###
resetRule "SV-60813r1_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(auditconfig -getplugin | grep audit_syslog | grep '(active)') ]]; then
	if [[ -n $(/etc/init.d/splunk status) ]]; then
pass "$rule" "auditconfig -getplugin | grep audit_syslog; /opt/splunkforwarder/bin/splunk btool deploymentclient list | grep targetUri | grep -v '^#'" "Verified the OS backs up audit records at least every seven days onto a different system or system component other than the system or component being audited. Audit logs are archived via Splunkforwarder service, per NSO requirement. 'system-log' is sending messages to local filesystems and specific messages to remote server for Splunkforwarder constantly, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	elif [[ -n $(grep audit.notice /etc/syslog.conf | grep -v '^\s*#') ]]; then
pass "$rule" "auditconfig -getplugin | grep audit_syslog; grep audit.notice /etc/syslog.conf | grep -v '^\s*#'" "Verified the OS backs up audit records at least every seven days onto a different system or system component other than the system or component being audited. 'system-log' is sending messages to local filesystems and specific messages to a remote server constantly, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
fail "$rule" "auditconfig -getplugin | grep audit_syslog; /etc/init.d/splunk status; grep audit.notice /etc/syslog.conf | grep -v '^\s*#'" "Verified the OS does NOT backup audit records at least every seven days onto a different system or system component other than the system or component being audited. 'system-log' is NOT sending messages to local filesystems and specific messages to a 	remote server constantly, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	fi
  else
	fail "$rule" "auditconfig -getplugin | grep audit_syslog; /etc/init.d/splunk status; grep audit.notice /etc/syslog.conf | grep -v '^\s*#'" "Verified the operating system does NOT backup audit records at least every seven days onto a different system or system component other than the system or component being audited. 'system-log' is NOT sending messages to local filesystems and specific messages to a  remote server constantly, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
        na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-47943 ###
resetRule "SV-60815r2_rule"
userString=$(logins -S files -ox | awk -F: '($1!="root"&&$8!="LK"&&$8!="NL"&&$11!="56"){print"User: "$1" Group: "$3" MaxDays: "$11}')
uinsString=$(echo "$userString" | awk '{print$2}' | xargs -i sh -c "if [[ -n \$(grep "{$1}" /etc/ssh/sshd_config | grep -v '^#') ]]; then echo \"User "{$1}" is allowed to login directly.\";fi")
ginsString=$(echo "$userString" | awk '{print$4}' | xargs -i sh -c "if [[ -n \$(grep "{$1}" /etc/ssh/sshd_config | grep -v '^#') ]]; then echo \"Group "{$1}" is allowed to login directly.\";fi")

if [[ $(grep '^MAXWEEKS=' /etc/default/passwd | awk -F'=' '{print$2}') -le 8 ]]; then
  if [[ -z $uinsString && -z $ginsString ]]; then
	pass "$rule" "grep \"^MAXWEEKS\" /etc/default/passwd; echo \"\$userString\"; echo \"\$uinsString\"; echo \"\$ginsString\" | uniq" "Verified user passwords must be changed at least every 56 days, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	fail "$rule" "grep \"^MAXWEEKS\" /etc/default/passwd; echo \"\$userString\"; echo \"\$uinsString\"; echo \"\$ginsString\" | uniq" "Verified user passwords must be changed at least every 56 days, however User accounts listed are set other than 56 days; also listed are these users/groups that can login directly, therefore the reference STIG IS a finding. Please verify the user accounts listed, require to have an expiration other than 56 days and also whether they should be able to login directly. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
  if [[ -z $uinsString && -z $ginsString ]]; then
	fail "$rule" "grep \"^MAXWEEKS\" /etc/default/passwd; echo \"\$userString\"; echo \"\$uinsString\"; echo \"\$ginsString\" | uniq" "Verified user passwords are NOT required to be changed at least every 56 days, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	fail "$rule" "grep \"^MAXWEEKS\" /etc/default/passwd; echo \"\$userString\"; echo \"\$uinsString\"; echo \"\$ginsString\" | uniq" "Verified user passwords are NOT required to be changed at least every 56 days, also User accounts listed are set other than 56 days; also listed are these users/groups that can login directly, therefore the reference STIG IS a finding. Please verify the user accounts listed, require to have an expiration other than 56 days and also whether they should be able to login directly. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi
unset userString uinsString ginsString

### V-47945 ###
resetRule "SV-60817r1_rule"
	na "$rule" "ls -l /opt/McAfee" "Verified a working McAfee HIPS is not available for Solaris 11, but we do install the other portions that are supported (CMA, ACCM, etc.), therefore the referenced STIG is Not Applicable"

### V-47947 ###
# Removed from Solaris 11 STIG V1R20
#resetRule "SV-60819r1_rule"
#na "$rule" "ls -l /opt/McAfee" "Verified a working McAfee HIPS is not available for Solaris 11, but we do install the other portions that are supported (CMA, ACCM, etc.), therefore the referenced STIG is Not Applicable"

### V-47949 ###
resetRule "SV-60821r1_rule"
	nr "$rule" "logins -S files -aox |awk -F: '(\$14 == \"0\") {print}' | sed 's/&//g'" "Manually Verify the accounts listed are not temporary accounts. Verified the operating system automatically terminates temporary accounts within 72 hours, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."


### V-47951 ###
resetRule "SV-60823r1_rule"
	na "$rule" "ls -l /opt/McAfee" "Verified a working McAfee HIPS is not available for Solaris 11, but we do install the other portions that are supported (CMA, ACCM, etc.), therefore the referenced STIG is Not Applicable"


### V-47953 ###
resetRule "SV-60825r2_rule"
users=$(awk -F: '$4 < 1 {print $1}' /etc/shadow | grep -v 'nobody' | grep -v 'noaccess')
output=""
testFail=false
for i in $users; do
	if [[ $(id -u $i) -ge 100 ]]; then
		output+="$i ; " 
		testFail=true
	else
		$nothing
	fi
done
if [[ $testFail = "true" ]]; then
	fail "$rule" "$(grep ^MINWEEKS /etc/default/passwd | grep -v '^\s*#');\n\n$(echo $output)" "Users listed do not have minimum password lifetime restrictions. Verified the operating system does NOT enforce minimum password lifetime restrictions.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	nonzero "$rule" "grep ^MINWEEKS /etc/default/passwd | grep -v '^\s*#' | grep 1" "Verified the operating system must enforce minimum password lifetime restrictions, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT enforce minimum password lifetime restrictions, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^MINWEEKS /etc/default/passwd"
fi
unset testFail output users

### V-47955 ###
resetRule "SV-60827r3_rule"
if [[ -f /home/nso/uvscan/uvscan ]]; then
	pass "$rule" "/home/nso/uvscan/uvscan --version" "Verified the operating system must have malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
elif [[ -f /usr/local/uvscan/uvscan ]]; then
	pass "$rule" "/usr/local/uvscan/uvscan --version" "Verified the operating system must have malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "echo \"uvscan not found\"" "Verified the operating system does NOT have malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-47957 ###
resetRule "SV-60829r1_rule"
	nonzero "$rule" "grep ^PASSLENGTH /etc/default/passwd | grep -v '^\s*#' | awk -F'=' '\$2 >= 15'" "Verified user passwords ARE required to be at least 15 characters in length, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified user passwords is NOT at least 15 characters in length, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47959 ###
resetRule "SV-60831r3_rule"
if [[ -f /home/nso/uvscan/uvscan ]]; then
	nonzero "$rule" "find /home/nso/uvscan/ -name avv*.dat -mtime -7 -type f" "Verified uvscan is installed, dat files are NOT more then 10 days old and configured correctly, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified uvscan is installed however dat files are more then 10 days old and therefore NOT configured correctly, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
elif [[ -f /usr/local/uvscan/uvscan ]]; then
	nonzero "$rule" "find /usr/local/uvscan/ -name avv*.dat -mtime -7 -type f" "Verified uvscan is installed, dat files are NOT more then 10 days old and configured correctly, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified uvscan is installed however dat files are more then 10 days old and therefore NOT configured correctly, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	fail "$rule" "echo \"uvscan not found\"" "Verified the operating system does NOT have malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-47961 ###
resetRule "SV-60833r1_rule"
	nonzero "$rule" "grep ^HISTORY /etc/default/passwd | grep -v '^\s*#' | awk -F'=' '\$2 >= 5'" "Verified users must not reuse the last 5 passwords, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified users reuse the last 5 passwords, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^HISTORY /etc/default/passwd"

### V-47963 ###
resetRule "SV-60835r3_rule"
if [[ -f /home/nso/uvscan/uvscan ]]; then
	nonzero "$rule" "find /home/nso/uvscan/ -name avv*.dat -mtime -7 -type f" "Verified uvscan is installed, dat files are NOT more then 10 days old and configured correctly, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified uvscan is installed however dat files are more then 10 days old and therefore NOT configured correctly, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
elif [[ -f /usr/local/uvscan/uvscan ]]; then
	nonzero "$rule" "find /usr/local/uvscan/ -name avv*.dat -mtime -7 -type f" "Verified uvscan is installed, dat files are NOT more then 10 days old and configured correctly, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified uvscan is installed however dat files are more then 10 days old and therefore NOT configured correctly, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	fail "$rule" "echo \"uvscan not found\"" "Verified the operating system does NOT have malicious code protection mechanisms at system entry and exit points to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-47967 ###
resetRule "SV-60839r2_rule"
	nonzero "$rule" "grep ^MINDIFF /etc/default/passwd | awk -F'=' '\$2 >= 8'" "Verifed the system must require at least eight characters be changed between the old and new passwords during a password change, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verifed the system does NOT require at least eight characters be changed between the old and new passwords during a password change, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^MINDIFF /etc/default/passwd"

### V-47969 ###
resetRule "SV-60841r2_rule"
if [[ -z $(pkg list web/browser/firefox | grep '\d*') ]]; then
	na "$rule" "pkg list web/browser/firefox" "Verified firefox is not installed, therefore the reference STIG is Not Applicable"
else
	nr "$rule" "pkg list web/browser/firefox" "Verified Firefox is installed and will require checking settings in the webUI"
fi

### V-47971 ###
resetRule "SV-60843r1_rule"
	nonzero "$rule" "grep ^MINUPPER /etc/default/passwd | awk -F'=' '\$2 >= 1'" "Verified the system must require passwords to contain at least one uppercase alphabetic character, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain at least one uppercase alphabetic character, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^MINUPPER /etc/default/passwd"

### V-47973 ###
resetRule "SV-60845r1_rule"
	nonzero "$rule" "ls -l /opt/commvault/" "Verified the operating system conducts backups of operating system documentation including security-related documentation per organization-defined frequency to conduct backups that is consistent with recovery time and recovery point objectives, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT conduct backups of operating system documentation including security-related documentation per organization-defined frequency to conduct backups that is consistent with recovery time and recovery point objectives, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47975 ###
resetRule "SV-60847r1_rule"
	nonzero "$rule" "ls -l /opt/commvault/" "Verified the operating system conducts backups of system-level information contained in the information system per organization-defined frequency to conduct backups that are consistent with recovery time and recovery point objectives, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT conduct backups of system-level information contained in the information system per organization-defined frequency to conduct backups that are consistent with recovery time and recovery point objectives, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47977 ###
resetRule "SV-60849r1_rule"
	nonzero "$rule" "ls -l /opt/commvault/" "Verified the operating system conducts backups of user-level information contained in the operating system per organization-defined frequency to conduct backups consistent with recovery time and recovery point objectives, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT conduct backups of user-level information contained in the operating system per organization-defined frequency to conduct backups consistent with recovery time and recovery point objectives, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47979 ###
resetRule "SV-60851r1_rule"
	nr "$rule" "awk -F':' '{print\$1,\$2}' /etc/shadow | egrep -v '\(:NP:|:\*LK\*:|root\)' | awk '{print\$1}' | xargs -i getent passwd {$1}" "Verified that the system does not have unecessary accounts, accounts returned are not locked"

### V-47981 ###
resetRule "SV-60853r1_rule"
	nonzero "$rule" "grep ^MINLOWER /etc/default/passwd | awk -F'=' '\$2 >= 1'" "Verified the operating system must enforce password complexity requiring that at least one lowercase character is used, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT enforce password complexity requiring that at least one lowercase character is used, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^MINLOWER /etc/default/passwd"

### V-47983 ###
resetRule "SV-60855r2_rule"
	nr "$rule" "egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print\$1}' | xargs -i getent passwd {$1}" "Manually verify no shared accounts exist on the system. Verified direct logins are not permitted to shared, default, application, or utility accounts, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-47985 ###
resetRule "SV-60857r2_rule"
if [[ -n $(zonename | grep global) ]]; then
        nonzero "$rule" "svcs -Ho state ntp | grep online" "Verified the operating system must synchronize internal information system clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT synchronize internal information system clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "svcs -Ho state ntp"
else
	zero "$rule" "svcs -Ho state ntp | grep online" "Verified the operating system does NOT synchronize internal information system clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS, the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "Verified the operating system must synchronize internal information system clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "svcs -Ho state ntp"
fi

### V-47987 ###
resetRule "SV-60859r1_rule"
if [[ -z $(crontab -l | grep -i bart | grep -v '^#' | awk '$5>=0&&$5<=6') ]]; then
  if [[ -z $(ls /var/adm/log/bartlogs/) ]]; then
	fail "$rule" "ls -l /var/adm/log/bartlogs/" "Verified BART is not being run by cron weekly and BART manifests were not found, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  else
	echo "Running BART, this may take a while" >> /dev/tty
	if [[ -f /home/nso/BART/bart.rules ]]; then
		nr "$rule" "crontab -l | grep -i bart; /home/nso/BART/bart.sh" "Verified BART is not being run by cron weekly. Examine the BART report in /var/adm/messages for changes. If there are changes to system files in /etc that are not approved, this reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
	else
		rulesBart='IGNORE acl\nCHECK mode uid gid mtime size contents\n/etc !devices/ !cma.d/ !McAfeeABM.d/ !McAfeeAuditEngine.d/ !cma.conf !mnttab !svc/repository.db !rmtab\n/devices !scsi_vhci/ !pseudo/\n/lib\n/usr/bin\n/usr/sbin\n/usr/lib !/ssm/fwupdate/emulex/rm.log\n/usr/platform\n/usr/xpg4\n/usr/xpg6'
		currentBart=$(ls -rt /var/adm/log/bartlogs | tail -1)

		echo "$rulesBart" | bart -r - create > /var/adm/log/bartlogs/bart.manifest.1

		nr "$rule" "crontab -l | grep -i bart; echo \"$rulesBart\" | /usr/bin/bart compare -r - -p /var/adm/log/bartlogs/\$currentBart /var/adm/log/bartlogs/bart.manifest.1" "Verified BART is not being run by cron weekly. Examine the listed BART report for changes. If there are changes to system files in /etc that are not approved, this reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
		rm -f /var/adm/log/bartlogs/$currentBart
		mv /var/adm/log/bartlogs/bart.manifest.1 /var/adm/log/bartlogs/bart.manifest.0
	fi
  fi
else
  if [[ -n $(/etc/init.d/splunk status) ]]; then
	pass "$rule" "crontab -l | grep -i bart; /home/nso/BART/bart.sh" "Verified BART is being run by cron weekly, BART logs are being ingested into Splunk for weekly review, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	nr "$rule" "crontab -l | grep -i bart; /home/nso/BART/bart.sh" "Verified BART is being run by cron weekly. Examine the BART report in /var/adm/messages for changes. If there are changes to system files in /etc that are not approved, this reference STIG IS a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  fi
fi
unset rulesBart currentBart

### V-47989 ###
resetRule "SV-60861r1_rule"
	nonzero "$rule" "grep ^MINDIGIT /etc/default/passwd | awk -F'=' '\$2 >=1'" "Verified the system must require passwords to contain at least one numeric character, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain at least one numeric character, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^MINDIGIT /etc/default/passwd"

### V-47991 ###
resetRule "SV-60863r1_rule"
	nonzero "$rule" "grep ^MINSPECIAL /etc/default/passwd | awk -F'=' '\$2 >=1'" "Verified the system must require passwords to contain at least one special character, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain at least one special character, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^MINSPECIAL /etc/default/passwd"

### V-47993 ###
resetRule "SV-60865r1_rule"
	nonzero "$rule" "grep ^MAXREPEATS /etc/default/passwd | awk -F'=' '\$2 <=3'" "Verified the system must require passwords to contain no more than three consecutive repeating characters, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to contain no more than three consecutive repeating characters, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^MAXREPEATS /etc/default/passwd"

### V-47995 ###
resetRule "SV-60867r2_rule"
	zero "$rule" "egrep \"public|private|snmp-trap|password\" /var/net-snmp/snmpd.conf" "Verified SNMP communities, users, and passphrases are changed from the default, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified SNMP communities, users, and passphrases are NOT changed from the default, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47997 ###
resetRule "SV-60869r1_rule"
	zero "$rule" "mount | grep nologging" "Verified the operating system must implement transaction recovery for transaction-based systems,  therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT implement transaction recovery for transaction-based systems,  therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-47999 ###
resetRule "SV-60871r1_rule"
	zero "$rule" "logins -S files -po" "Verified the system must not have accounts configured with blank or null passwords,  therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system has accounts configured with blank or null passwords,  therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48003 ###
resetRule "SV-60875r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "eeprom security-mode | grep command" "Verified the system must require passwords to change the boot device settings. (SPARC), therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT require passwords to change the boot device settings. (SPARC), therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Verified global zone is not used, therefore the referenced STIG is Not Applicable"
fi

### V-48007 ###
resetRule "SV-60879r1_rule"
if [[ -n $(zonename | grep global) ]]; then
dumpDir=$(readlink -f $(dumpadm | grep directory | awk -F':' '{print$2}'))
dumpPerm=$(stat -Lc '%a' $dumpDir)
	nonzero "$rule" "echo \"$dumpPerm\" | awk '\$0<=700'" "Verified the kernel core dump data directory must have mode 0700 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the kernel core dump data directory does NOT have mode 0700 or less permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "stat -Lc '%%a' $dumpDir"
# Extra % for PRINTF to ignore %
else
	na "$rule" "zonename | grep global" "Verified global zone is not used, therefore the referenced STIG is Not Applicable"
fi

### V-48009 ###
resetRule "SV-60881r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "ls -ld $dumpDir | awk '(\$4==\"root\"){print}'" "Verified the kernel core dump data directory must be group-owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the kernel core dump data directory is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -ld $dumpDir"
else
	na "$rule" "zonename | grep global" "Verified global zone is not used, therefore the referenced STIG is Not Applicable"
fi

### V-48011 ###
resetRule "SV-60883r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "ls -ld $dumpDir | awk '(\$3==\"root\"){print}'" "Verified the kernel core dump data directory must be owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the kernel core dump data directory is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -ld $dumpDir"
else
	na "$rule" "zonename | grep global" "Verified global zone is not used, therefore the referenced STIG is Not Applicable"
fi

### V-48013 ###
resetRule "SV-60885r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	zero "$rule" "dumpadm | grep 'Savecore enabled' | grep yes" "Verified kernel core dumps must be disabled unless needed, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified kernel core dumps is NOT disabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Verified global zone is not used, therefore the referenced STIG is Not Applicable"
fi
unset dumpDir dumpPerm

### V-48015 ###
resetRule "SV-60887r1_rule"
if [[ -f $(coreadm | grep "global core file pattern" | awk -F':' '{print $2}' | awk -F'.' '{print $1}' | tr -d '[:space:]') ]]; then
	nonzero "$rule" "stat -c '%a' $(readlink -f $(coreadm | grep 'global core file pattern' | awk -F':' '{print \$2}' | awk -F'.' '{print \$1}')) | awk '\$0 <= 700'" "Verified the centralized process core dump data directory must have mode 0700 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the centralized process core dump data directory does NOT have mode 0700 or less permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "stat -c '%%a' $(readlink -f $(coreadm | grep 'global core file pattern' | awk -F':' '{print \$2}') | awk -F'.' '{print \$1}')"
# Extra % for PRINTF to ignore %
else
	fail "$rule" "coreadm | grep 'global core file pattern'" "Verified the system is NOT configured to store any process core dumps in a specific, centralized directory so the centralized process core dump data directory does NOT have mode 0700 or less permissive, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48017 ###
resetRule "SV-60889r2_rule"
if [[ -f $(coreadm | grep "global core file pattern" | awk -F':' '{print \$2}' | awk -F'.' '{print $1}' | tr -d '[:space:]') ]]; then
	nonzero "$rule" "ls -ld $(readlink -f $(coreadm | grep 'global core file pattern' | awk -F':' '{print \$2}' | awk -F'.' '{print \$1}')) | awk '{print \$4}' | grep root" "Verified the centralized process core dump data directory must be group-owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the centralized process core dump data directory is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -ld $(readlink -f $(coreadm | grep 'global core file pattern' | awk -F':' '{print \$2}') | awk -F'.' '{print \$1}')"
else
	fail "$rule" "coreadm | grep 'global core file pattern'" "Verified the system is NOT configured to store any process core dumps in a specific, centralized directory so the centralized process core dump data directory is NOT group-owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48019 ###
resetRule "SV-60891r1_rule"
if [[ -f $(coreadm | grep "global core file pattern" | awk -F':' '{print \$2}' | awk -F'.' '{print $1}' | tr -d '[:space:]') ]]; then
	nonzero "$rule" "ls -ld $(readlink -f $(coreadm | grep 'global core file pattern' | awk -F':' '{print \$2}' | awk -F'.' '{print \$1}')) | awk '{print \$3}' | grep root" "Verified the centralized process core dump data directory must be owned by root, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the centralized process core dump data directory is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -ld $(readlink -f $(coreadm | grep 'global core file pattern' | awk -F':' '{print \$2}'))"
else
	fail "$rule" "coreadm | grep 'global core file pattern'" "Verified the system is NOT configured to store any process core dumps in a specific, centralized directory so the centralized process core dump data directory is NOT owned by root, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48021 ###
resetRule "SV-60893r2_rule"
	zero "$rule" "coreadm | grep enabled | egrep -v '(logging|diagnostic)'" "Verified the process core dumps IS disabled, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the process core dumps is NOT disabled, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."

### V-48023 ###
resetRule "SV-60895r3_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	nonzero "$rule" "sxadm info -p | grep aslr | grep enabled" "Verified address Space Layout Randomization (ASLR) IS enabled, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified address Space Layout Randomization (ASLR) is NOT enabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	nonzero "$rule" "sxadm status -p -o status aslr | grep enabled" "Verified address Space Layout Randomization (ASLR) IS enabled, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified address Space Layout Randomization (ASLR) is NOT enabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-48025 ###
resetRule "SV-60897r2_rule"
if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=2') ]]; then
  if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "grep noexec_user_stack /etc/system | grep -v '^\s*#' | grep 1" "Verified the system must implement non-executable program stacks, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOt implement non-executable program stacks, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep noexec_user_stack /etc/system"
  else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
  fi
elif [[ -n $(uname -v | awk -F'.' '$2>=3') ]]; then
	nonzero "$rule" "sxadm status -p nxstack | cut -d: -f2 | grep enabled | grep all" "Verified the system must implement non-executable program stacks, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOt implement non-executable program stacks, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "sxadm status -p nxstack | cut -d: -f2"
fi

### V-48027 ###
resetRule "SV-60899r1_rule"
	nr "$rule" "uname -a; pkg list entire" "Verify the operating system must be a supported release"

### V-48029 ###
resetRule "SV-60901r1_rule"
	echo "Running FIND, this may take a while" >> /dev/tty
	zero "$rule" "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -acl -ls" "Verified the operator must document all file system objects that have non-standard access control list settings, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operator must document all file system objects that have non-standard access control list settings, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48031 ###
resetRule "SV-60903r2_rule"
outputString=""
if [[ -n $(zonename | grep global) ]]; then
  auditDir=$(readlink -f $(auditconfig -getplugin audit_binfile | awk -F';' '{print $2}' | awk -F'=' '{print $2}' | sed '/^\s*$/d'))
  auditFiles=$(ls -l $auditDir | grep -v '^d' | awk '{print$9}')
  for i in $auditFiles; do
	if [[ -n $(stat -c '%a' "$auditDir/$i" | awk '$0 > 640') ]]; then
		outputString+=$(echo "$auditDir/$i")
	fi
  done
  zero "$rule" "$(echo $outputString)" "Verified the operating system must protect the audit records resulting from non-local accesses to privileged accounts and the execution of privileged functions, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Audit files listed have permissions not set to 640 or less. Verified the operating system does NOT protect the audit records resulting from non-local accesses to privileged accounts and the execution of privileged functions, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
        na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi
unset outputString auditFiles auditDir

### V-48033 ###
resetRule "SV-60905r2_rule"
	nonzero "$rule" "stat -c '%a' /var/adm/messages | awk '\$0<=640' && ls -l /var/adm/messages | awk '\$3==\"root\"&&\$4==\"root\"' &&  stat -c '%a' /var/adm | awk '\$0<=750' && ls -ld /var/adm | awk '\$3==\"root\"&&\$4==\"sys\"'" "Verified the operating system must reveal error messages only to authorized personnel, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT reveal error messages only to authorized personnel, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "ls -l /var/adm/messages; ls -ld /var/adm"

#if [[ -n $(stat -c '%a' /var/adm/messages | awk '$0<=640') && -n $(ls -l /var/adm/messages | awk '$3=="root"&&$4=="root"') && -n $(stat -c '%a' /var/adm | awk '$0<=750') && -n $(ls -ld /var/adm | awk '($3=="root"&&$4=="sys"') ]]; then
#	pass "$rule" "ls -l /var/adm/messages; ls -ld /var/adm" "Verified the operating system must reveal error messages only to authorized personnel, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
#else
#	fail "$rule" "ls -l /var/adm/messages; ls -ld /var/adm" "Verified the operating system does NOT reveal error messages only to authorized personnel, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
#fi

### V-48035 ###
resetRule "SV-60907r1_rule"
if [[ -n $(awk -F: '($4==0){print$1}' /etc/passwd | grep root) && -n $(awk -F: '($3==0){print$1}' /etc/group | grep root) ]]; then
	pass "$rule" "awk -F: '\$4 == 0' /etc/passwd; awk -F: '\$3 == 0' /etc/group" "Verified the root account must be the only account with GID of 0, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "awk -F: '\$4 == 0' /etc/passwd; awk -F: '\$3 == 0' /etc/group" "Verified the root account is NOT the only account with GID of 0,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48037 ###
resetRule "SV-60909r2_rule"
	echo "Running FIND, this may take a while" >> /dev/tty
	zero "$rule" "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -xattr -ls" "Verified the operating system must have no files with extended attributes, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system has some files with extended attributes, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48039 ###
resetRule "SV-60911r1_rule"
	echo "Running FIND, this may take a while" >> /dev/tty
	zero "$rule" "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune \( -nouser -o -nogroup \) -ls" "Verified the operating system must have no unowned files, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system has some unowned files, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48043 ###
resetRule "SV-60915r1_rule"
	nonzero "$rule" "grep ^SLEEPTIME /etc/default/login | awk -F'=' '\$2 >= 4'" "Verified the delay between login prompts following a failed login attempt must be at least 4 seconds, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the delay between login prompts following a failed login attempt is NOT at least 4 seconds,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^SLEEPTIME /etc/default/login"

### V-48045 ###
resetRule "SV-60917r4_rule"
if [[ -z $(pkg list x11/server/xorg) ]]; then
	na "$rule" "pkg list x11/server/xorg" "Verified the system is not running XWindows, therefore the referenced STIG is Not Applicable"
else
	if [[ -n $(grep "^\*timeout:" /usr/share/X11/app-defaults/XScreenSaver | awk -F':' '$2 <= 15') && -n $(grep "^\*lockTimeout:" /usr/share/X11/app-defaults/XScreenSaver | awk -F':' '$3 <= 5') && -n $(grep "^\*lock:" /usr/share/X11/app-defaults/XScreenSaver | grep True) ]]; then
	$nothing
	fi
fi

### V-48047 ###
resetRule "SV-60919r3_rule"
if [[ -z $(pkg list x11/server/xorg) ]]; then
	na "$rule" "pkg list x11/server/xorg" "Verified the system is not running XWindows, therefore the referenced STIG is Not Applicable"
else
	if [[ -n $(grep "^\*timeout:" /usr/share/X11/app-defaults/XScreenSaver | awk -F':' '$2 <= 15') && -n $(grep "^\*lockTimeout:" /usr/share/X11/app-defaults/XScreenSaver | awk -F':' '$3 <= 5') && -n $(grep "^\*lock:" /usr/share/X11/app-defaults/XScreenSaver | grep True) ]]; then
	$nothing
	fi
fi

### V-48053 ###
resetRule "SV-60925r1_rule"
if [[ -n $(grep ^DICTIONLIST /etc/default/passwd | grep '/usr/share/lib/dict/words') && -n $(grep ^DICTIONDBDIR /etc/default/passwd | grep '/var/passwd') && -f "/usr/share/lib/dict/words" && -d "/var/passwd" ]]; then
	pass "$rule" "grep ^DICTION /etc/default/passwd" "Verified the system must prevent the use of dictionary words for passwords, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep ^DICTION /etc/default/passwd" "Verified the system does NOT prevent the use of dictionary words for passwords, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48055 ###
resetRule "SV-60927r2_rule"
if [[ -n $(userattr type root | grep role) && -n $(grep '[:;]roles=root[^;]*' /etc/user_attr) ]]; then
	pass "$rule" "grep '[:;]roles=root[^;]*' /etc/user_attr" "Verified the system must restrict the ability of users to assume excessive privileges to members of a defined group and prevent unauthorized users from accessing administrative tools, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep '[:;]roles=root[^;]*' /etc/user_attr" "Verified the system does NOT restrict the ability of users to assume excessive privileges to members of a defined group and prevent unauthorized users from accessing administrative tools, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48057 ###
resetRule "SV-60929r2_rule"
if [[ -n $(userattr type root | grep role) && -n $(grep '[:;]roles=root[^;]*' /etc/user_attr) ]]; then
  pass "$rule" "grep '[:;]roles=root[^;]*' /etc/user_attr" "Verified the operating system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
  fail "$rule" "grep '[:;]roles=root[^;]*' /etc/user_attr" "Verified the operating system does NOT require individuals to be authenticated with an individual authenticator prior to using a group authenticator, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48059 ###
resetRule "SV-60931r2_rule"
uid_files=""
pkg_files=""
pkg_files_fix=""
uid_files_filter=""
uid_files=$(find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -4000 -o -perm -2000 -print)
pkg_files=$(pkg contents -Ha mode=4??? -a mode=2??? -t file -o path)
# prepend the /
for jj in $pkg_files; do
  pkg_files_fix+=$(echo "/$jj ")
done
# compare uid list to pkg list
for ii in $uid_files; do
  if [[ "$pkg_files_fix" =~ "$ii" ]]; then
    $nothing
  else
    uid_files_filter+=$(elfsign verify -e $ii 2>&1 | grep -v passed)
  fi
done
if [[ $uid_files_filter ]]; then
	nr "$rule" "$(echo 'SUID/SGID files which are not part of Solaris package provided SUID/SGID files:'; echo $uid_files_filter)" "Verified some binaries were not properly signed, files returned did not pass signature validation, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	zero "$rule" "$(find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -4000 -o -perm -2000 -print | xargs -i sh -c \"elfsign verify -e \"{$1}\" 2>&1\" | grep -v passed)" "Verified all binaries were properly signed, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified some binaries were not properly signed, files returned did not pass signature validation, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -4000 -o -perm -2000 -print | xargs -i sh -c \"elfsign verify -e \"{$1}\" 2&>1\" | grep -v passed"
fi
unset uid_files pkg_files pkg_files_fix uid_files_filter ii jj

### V-48061 ###
resetRule "SV-60933r2_rule"
if [[ -n $(grep -i "^UMASK=" /etc/default/login | grep 077) && -n $(cut -d: -f1 /etc/passwd | xargs -i sh -c "grep umask ~"{$1}"/.*") ]]; then
	pass "$rule" "grep -i \"^UMASK=\" /etc/default/login; cut -d: -f1 /etc/passwd | xargs -i sh -c \"grep umask ~\"{$1}\"/.*\"" "Verified the default umask for system and users IS 077 and local initialization files also have umask set to 077, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep -i \"^UMASK=\" /etc/default/login; cut -d: -f1 /etc/passwd | xargs -i sh -c \"grep umask ~\"{$1}\"/.*\"" "Verified the default umask for system and users is NOT 077 or local initialization files no not have umask set to 077, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48063 ###
resetRule "SV-60935r1_rule"
	zero "$rule" "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type f -perm -0002 -print" "Verified world-writable files do NOT exist, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified world-writable files exist, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48065 ###
resetRule "SV-60937r1_rule"
	zero "$rule" "for dir in `logins -S files -ox | awk -F: '($8 == "PS") { print $6 }'`; do ls -l ${dir}/.forward 2>/dev/null; done" "Verified the system does NOT allow users to configure .forward files, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system allows users to configure .forward files, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48067 ###
resetRule "SV-60939r2_rule"
	zero "$rule" "for dir in `logins -S files -ox | awk -F: '($8 == "PS") { print $6 }'`; do ls -l ${dir}/.netrc 2>/dev/null; done" "Verified user .netrc files do NOT exist, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified user .netrc files exist, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48069 ###
resetRule "SV-60941r2_rule"
	zero "$rule" "getent group | awk -F: '{print\$1}' | sort | uniq -d" "Verified duplicate group names do NOT exist, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified duplicate group names DO exist, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48071 ###
resetRule "SV-60943r1_rule"
if [[ -z $(pkg list service/network/ftp | grep '\d*') ]]; then
	pass "$rule" "pkg list service/network/ftp" "Verified FTP service is not installed, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	nonzero "$rule" "egrep -i \"^UMASK\" /etc/proftpd.conf | awk '{ print \$2 }' | grep 077" "Verified the default umask for FTP users is set to 077, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the default umask for FTP users is NOT set to 077, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48073 ###
resetRule "SV-60945r1_rule"
	zero "$rule" "getent passwd | awk -F: '{print \$1}' | sort | uniq -d" "Verified duplicate user names do NOT exist, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified duplicate user names DO exist, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48075 ###
resetRule "SV-60947r2_rule"
if [[ -z $(grep ^mesg /etc/.login /etc/profile | grep y) ]]; then
	pass "$rule" "grep ^mesg /etc/.login /etc/profile" "Verified the value mesg n IS configured as the default setting for all users, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep ^mesg /etc/.login /etc/profile" "Verified the value mesg n is NOT configured as the default setting for all users, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48077 ###
resetRule "SV-60949r6_rule"
if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
	zero "$rule" "logins -S files -so | awk -F: '{ print \$1 }' | while read user; do found=0; for tUser in root daemon bin sys adm dladm netadm netcfg ftp dhcpserv sshd smmsp gdm zfssnap aiuser polkitd ikeuser lp openldap webservd unknown uucp nuucp upnp xvm mysql postgres svctag pkg5srv nobody noaccess nobody4; do if [ \${user} = \${tUser} ]; then found=1; fi; done; if [ \$found -eq 0 ]; then echo \"Invalid User with Reserved UID: \${user}\"; fi; done" "Verified reserved UIDs 0-99 must only be used by system accounts, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified reserved UIDs 0-99 is NOT only be used by system accounts, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	zero "$rule" "logins -S files -so | awk -F: '{ print \$1 }' | while read user; do found=0; for tUser in root daemon bin sys adm dladm netadm netcfg sshd smmsp gdm zfssnap aiuser _polkitd ikeuser lp openldap webservd unknown uucp nuucp upnp xvm mysql postgres svctag pkg5srv nobody noaccess nobody4; do if [ \${user} = \${tUser} ]; then found=1; fi; done; if [ \$found -eq 0 ]; then echo \"Invalid User with Reserved UID: \${user}\"; fi; done" "Verified reserved UIDs 0-99 must only be used by system accounts, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified reserved UIDs 0-99 is NOT only be used by system accounts, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48079 ###
resetRule "SV-60951r1_rule"
if [[ -n $(useradd -D | xargs -n1 | grep inactive | grep 35) ]]; then
  if [[ -z $(egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print$1,$13}' | grep -v 35) ]]; then
	pass "$rule" "useradd -D | xargs -n1 | grep inactive" "Verified the default inactivity lock is set to 35 days and user accounts are set to lock after 35 days of inactivity, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	fail "$rule" "egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print\$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print\$1,\$13}' | grep -v 35" "Verified the default inactivity lock is set to 35 days, however some user accounts are NOT set to lock after 35 days of inactivity, therefore the reference STIG is a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  fi
else
	fail "$rule" "useradd -D | xargs -n1 | grep inactive'; egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print\$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print\$1,\$13}' | grep -v 35" "Verified the default inactivity lock is NOT set to 35 days and some user accounts may not be set to lock after 35 days of inactivity, therefore the reference STIG is a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-48081 ###
resetRule "SV-60953r1_rule"
	zero "$rule" "getent group | cut -f3 -d\":\" | sort -n | uniq -c | while read x ; do [ -z \"\${x}\" ] && break; set - \$x; if [ \$1 -gt 1 ]; then grps=`getent group | nawk -F: '(\$3 == n){print\$1}' n=\$2 | xargs`; echo \"Duplicate GID (\$2): \${grps}\"; fi; done" "Verified duplicate Group IDs (GIDs) must not exist for multiple groups, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified duplicate Group IDs (GIDs) exist for multiple groups, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48083 ###
resetRule "SV-60955r1_rule"
if [[ -n $(useradd -D | xargs -n1 | grep inactive | grep 35) ]]; then
  if [[ -z $(egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print$1,$13}' | grep -v 35) ]]; then
	pass "$rule" "useradd -D | xargs -n1 | grep inactive" "Verified the default inactivity lock is set to 35 days and user accounts are set to lock after 35 days of inactivity, so the OS disables user identifiers after 35 days of inactivity, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	fail "$rule" "egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print\$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print\$1,\$13}' | grep -v 35" "Verified the default inactivity lock is set to 35 days, however some user accounts are NOT set to lock after 35 days of inactivity, so the OS cannot disable all user identifiers after 35 days of inactivity, therefore the reference STIG is a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  fi
else
	fail "$rule" "useradd -D | xargs -n1 | grep inactive'; egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print\$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print\$1,\$13}' | grep -v 35" "Verified the default inactivity lock is NOT set to 35 days and some user accounts may not be set to lock after 35 days of inactivity, so the OS cannot disable all user identifiers after 35 days of inactivity, therefore the reference STIG is a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-48085 ###
resetRule "SV-60957r1_rule"
if [[ -n $(useradd -D | xargs -n1 | grep inactive | grep 35) ]]; then
  if [[ -z $(egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print$1,$13}' | grep -v 35) ]]; then
	pass "$rule" "useradd -D | xargs -n1 | grep inactive" "Verified the default inactivity lock is set to 35 days and user accounts are set to lock after 35 days of inactivity, so any emergency accounts are locked after 35 days of inactivity, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else 
	fail "$rule" "egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print\$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print\$1,\$13}' | grep -v 35" "Verified the default inactivity lock is set to 35 days, however some user accounts are NOT set to lock after 35 days of inactivity, so any emergency accounts may not be locked after 35 days of inactivity, therefore the reference STIG is a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  fi
else
	fail "$rule" "useradd -D | xargs -n1 | grep inactive'; egrep -v '(:NP:|:\*LK\*:|^root)' /etc/shadow | awk -F: '{print\$1}' | xargs -i logins -axo -l {$1} | awk -F: '{print\$1,\$13}' | grep -v 35" "Verified the default inactivity lock is NOT set to 35 days and some user accounts may not be set to lock after 35 days of inactivity, so any emergency accounts may not be locked after 35 days of inactivity, therefore the reference STIG is a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-48087 ###
resetRule "SV-60959r1_rule"
if [[ -n $(svcs -Ho state svc:/system/console-login:terma | grep disabled) && -n $(svcs -Ho state svc:/system/console-login:termb | grep disabled) ]]; then
	pass "$rule" "svcs -Ho state svc:/system/console-login:terma; svcs -Ho state svc:/system/console-login:termb" "Verified login services for serial ports IS disabled, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "svcs -Ho state svc:/system/console-login:terma; svcs -Ho state svc:/system/console-login:termb" "Verified login services for serial ports is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48089 ###
resetRule "SV-60961r1_rule"
	nonzero "$rule" "grep \"^ENABLE_NOBODY_KEYS=\" /etc/default/keyserv | grep -i no" "Verified the nobody access for RPC encryption key storage service IS disabled, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the nobody access for RPC encryption key storage service is NOT disabled,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep \"^ENABLE_NOBODY_KEYS=\" /etc/default/keyserv"

### V-48091 ###
resetRule "SV-60963r1_rule"
	zero "$rule" "logins -S files | awk '{print$2,$1}' | sort -n | uniq -d" "Verified duplicate UIDs must not exist for multiple non-organizational users, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified duplicate UIDs exist for multiple non-organizational users, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48093 ###
resetRule "SV-60965r1_rule"
	nonzero "$rule" "grep \"^X11Forwarding\" /etc/ssh/sshd_config | grep -i no" "Verified X11 forwarding for SSH IS disabled, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified X11 forwarding for SSH is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep \"^X11Forwarding\" /etc/ssh/sshd_config"

### V-48095 ###
resetRule "SV-60967r1_rule"
	zero "$rule" "logins -S files | awk '{print$2,$1}' | sort -n | uniq -d" "Verified duplicate UIDs must not exist for multiple non-organizational users, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified duplicate UIDs exist for multiple non-organizational users, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48097 ###
resetRule "SV-60969r2_rule"
	zero "$rule" "export IFS=\":\"; logins -S files -uxo | while read user uid group gid gecos home rest; do result=\$(find \${home} -type d -prune \! -user $user -print 2>/dev/null); if [ ! -z \"${result}\" ]; then echo \"User: \${user}\tOwner: \$(ls -ld \$home | awk '{ print \$3 }')\"; fi; done" "Verified all home directories must be owned by the respective user assigned to it in /etc/passwd, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified some home directories is NOT owned by the respective user assigned to it in /etc/passwd, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "export IFS=\":\"; logins -uxo | while read user uid group gid gecos home rest; do result=\$(find \${home} -type d -prune \! -user $user -print 2>/dev/null); if [ ! -z \"${result}\" ]; then echo \"User: \${user}\tOwner: \$(ls -ld \$home | awk '{ print \$3 }')\"; fi; done"

### V-48099 ###
resetRule "SV-60971r3_rule"
if [[ -n $(grep ^MaxAuthTries /etc/ssh/sshd_config | grep -vi log | grep 6) ]]; then
  if [[ -n $(uname -v | awk -F'.' '$2<=3') ]]; then
    if [[ -n $(grep ^MaxAuthTriesLog /etc/ssh/sshd_config | grep 6) ]]; then
	pass "$rule" "grep ^MaxAuthTries /etc/ssh/sshd_config" "Verified MaxAuthTries is set to 6. \nAlthough not a finding according to the Solaris 11.3 STIG Check Text, MaxAuthTriesLog should be set to MaxAuthTries/2, which is 3, not 6. \n(www.softpanorama.org/Net/Application_layer/SSH/sshd_configuration.shtml) \nBy setting this value to 6, failed login attempts do not get logged until the 6th try which will not happen because MaxAuthTries is limited to 3 (6/2). \nVerified consecutive login attempts for SSH is limited to 3, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    elif [[ -n $(grep ^MaxAuthTriesLog /etc/ssh/sshd_config | grep 3) ]]; then
	pass "$rule" "grep ^MaxAuthTries /etc/ssh/sshd_config" "Verified MaxAuthTries is set to 6. \nVerified MaxAuthTriesLog is set to MaxAuthTries/2, which is 3. \n(www.softpanorama.org/Net/Application_layer/SSH/sshd_configuration.shtml) \nIf this value is set to 6, failed login attempts do not get logged until the 6th try which will not happen because MaxAuthTries is limited to 3 (6/2). \nVerified consecutive login attempts for SSH is limited to 3, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
    else
	fail "$rule" "grep ^MaxAuthTries /etc/ssh/sshd_config" "Verified MaxAuthTries is set to 6. \nMaxAuthTriesLog should be set to MaxAuthTries/2, which is 3. \n(www.softpanorama.org/Net/Application_layer/SSH/sshd_configuration.shtml) \nIf this value is set to 6, failed login attempts do not get logged until the 6th try which will not happen because MaxAuthTries is limited to 3 (6/2). \nVerified consecutive login attempts for SSH is limited to 3, however logging is not set to log after 3 login attempts, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	pass "$rule" "grep ^MaxAuthTries /etc/ssh/sshd_config | grep -vi log" "Verified MaxAuthTries is set to 6. \nMaxAuthTriesLog is a deprecated directive in Solaris 11.4+ and is not checked. \nVerified consecutive login attempts for SSH is limited to 3, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  fi
else
  if [[ -n $(uname -v | awk -F'.' '$2<=3') ]]; then
	fail "$rule" "grep ^MaxAuthTries /etc/ssh/sshd_config" "MaxAuthTries should be set to 6. \nMaxAuthTriesLog should be set to MaxAuthTries/2, which is 3. \n(www.softpanorama.org/Net/Application_layer/SSH/sshd_configuration.shtml) \nIf this value is set to 6, failed login attempts do not get logged until the 6th try which will not happen because MaxAuthTries is limited to 3 (6/2). \nVerified consecutive login attempts for SSH is NOT limited to 3, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	fail "$rule" "grep ^MaxAuthTries /etc/ssh/sshd_config" "MaxAuthTries should be set to 6. \nMaxAuthTriesLog is a deprecated directive in Solaris 11.4+ and is not checked. \nVerified consecutive login attempts for SSH is NOT limited to 3, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48101 ###
resetRule "SV-60973r1_rule"
	zero "$rule" "grep ^IgnoreRhosts /etc/ssh/sshd_config | grep -vi yes" "Verified the rhost-based authentication for SSH IS disabled, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the rhost-based authentication for SSH is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^IgnoreRhosts /etc/ssh/sshd_config"

### V-48103 ###
resetRule "SV-60975r1_rule"
	nonzero "$rule" "grep ^PermitRootLogin /etc/ssh/sshd_config | grep -i no" "Verified direct root account login must not be permitted for SSH access, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified direct root account login IS permitted for SSH access, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^PermitRootLogin /etc/ssh/sshd_config"

### V-48105 ###
resetRule "SV-60977r3_rule"
if [[ -n $(uname -v | awk -F'.' '$2 >= 1 && $2 <= 3') ]]; then
  if [[ -z $(pkg info gdm) || -z $(pkg info coherence-26) || -z $(pkg info coherence-27) ]]; then
	na "$rule" "pkg info gdm;pkg info coherence-26;pkg info coherence-27" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
else
  if [[ -z $(pkg info gdm) ]]; then
	na "$rule" "pkg info gdm" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
fi

### V-48107 ###
resetRule "SV-60979r2_rule"
	nonzero "$rule" "grep ^PermitEmptyPasswords /etc/ssh/sshd_config | grep -i no" "Verified login is NOT be permitted with empty/null passwords for SSH, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified login IS permitted with empty/null passwords for SSH, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^PermitEmptyPasswords /etc/ssh/sshd_config"

### V-48109 ###
resetRule "SV-60981r1_rule"
	zero "$rule" "logins -S files -xo | while read line; do user=`echo \${line} | awk -F: '{ print \$1 }'`; home=`echo \${line} | awk -F: '{ print \$6 }'`; if [ -z \"\${home}\" ]; then echo \${user}; fi; done" "Verified users must have a valid home directory assignment, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified users do NOT have a valid home directory assignment, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "logins -xo | while read line; do user=`echo \${line} | awk -F: '{ print \$1 }'`; home=`echo \${line} | awk -F: '{ print \$6 }'`; if [ -z \"\${home}\" ]; then echo \${user}; fi; done"

### V-48111 ###
resetRule "SV-60983r2_rule"
if [[ -n $(grep ^ClientAlive /etc/ssh/sshd_config | grep -vi count | grep 600) && -n $(grep ^ClientAliveCount /etc/ssh/sshd_config | grep 0) ]]; then
	pass "$rule" "grep ^ClientAlive /etc/ssh/sshd_config" "Verified the operating system must terminate the network connection associated with a communications session at the end of the session or after 10 minutes of inactivity, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep ^ClientAlive /etc/ssh/sshd_config" "Verified the operating system does NOT terminate the network connection associated with a communications session at the end of the session or after 10 minutes of inactivity, therefore the reference STIG is a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
fi

### V-48113 ###
resetRule "SV-60985r4_rule"
	nonzero "$rule" "grep 'pam_rhosts_auth.so.1' /etc/pam.conf /etc/pam.d/*| grep -vc '^#' | grep 0" "Verified host-based authentication for login-based services IS disabled, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified host-based authentication for login-based services is NOT disabled, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep 'pam_rhosts_auth.so.1' /etc/pam.conf /etc/pam.d/*| grep -vc '^#'"

### V-48115 ###
resetRule "SV-60987r1_rule"
	zero "$rule" "logins -S files -xo | awk -F: '(\$3 == \"\") { print \$1 }'" "Verified groups assigned to users exist in the /etc/group file, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified groups assigned to users do NOT exist in the /etc/group file, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48117 ###
resetRule "SV-60989r1_rule"
if [[ -z $(pkg list service/network/ftp | grep '\d*') ]]; then
	pass "$rule" "pkg list service/network/ftp" "Verified FTP service is not installed, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	zero "$rule" "for user in `logins -S files -s | awk '{ print \$1 }'` aiuser noaccess nobody nobody4; do grep -w \"\${user}\" /etc/ftpd/ftpusers >/dev/null 2>&1; if [ \$? != 0 ]; then echo \"User '\${user}' not in /etc/ftpd/ftpusers.\"; fi; done" "Verified the use of FTP IS restricted, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the use of FTP is NOT restricted, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48119 ###
resetRule "SV-60991r1_rule"
	zero "$rule" "for dir in `logins -S files -ox | awk -F: '(\$8 == "PS") { print \$6 }'`; do find \${dir}/.rhosts -type f -ls 2>/dev/null; done" "Verified there must be no user .rhosts files, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified some users have .rhosts files, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

## V-48121 ###
resetRule "SV-60993r1_rule"
	nonzero "$rule" "egrep \"auth|account\" /etc/pam.d/gdm-autologin | grep -vc ^# | grep 0" "Verified the system must not allow autologin capabilities from the GNOME desktop, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system allow autologin capabilities from the GNOME desktop, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "egrep \"auth|account\" /etc/pam.d/gdm-autologin | grep -vc ^#"

### V-48123 ###
resetRule "SV-60995r1_rule"
	zero "$rule" "for dir in `logins -S files -ox | awk -F: '(\$8 == "PS") { print \$6 }'`; do find \${dir}/.netrc -type f \( -perm -g+r -o -perm -g+w -o -perm -g+x -o -perm -o+r -o -perm -o+w -o -perm -o+x \) -ls 2>/dev/null; done" "Verified permissions on user .netrc files must be 750 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified permissions on user .netrc files is NOT 750 or less permissive, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

## V-48125 ###
resetRule "SV-60997r3_rule"
if [[ -f "/etc/cron.d/cron.deny" || -f "/etc/cron.d/at.deny" ]]; then
	fail "$rule" "ls /etc/cron.d/cron.deny; ls /etc/cron.d/at.deny" "Verified either cron.deny or at.deny file exists, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  if [[ -z $(grep -v '^\s*#' /etc/cron.d/cron.allow | sed '/^$/d' | grep -v root) && -z $(grep -v '^\s*#' /etc/cron.d/at.allow | sed '/^$/d' | grep -v root) ]]; then
	pass "$rule" "grep -v '^\s*#' /etc/cron.d/cron.allow; grep -v '^\s*#' /etc/cron.d/at.allow" "Verified unauthorized use of the at or cron capabilities is NOT permitted, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  else
	fail "$rule" "grep -v '^\s*#' /etc/cron.d/cron.allow; grep -v '^\s*#' /etc/cron.d/at.allow" "Verified possible unauthorized use of the at or cron capabilities IS permitted, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48127 ###
resetRule "SV-60999r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "grep \"^CONSOLE=/dev/console\" /etc/default/login" "Verified logins to the root account must be restricted to the system console only, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified logins to the root account is NOT restricted to the system console only, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-48129 ###
resetRule "SV-61001r1_rule"
	zero "$rule" "for dir in `logins -S files -ox | awk -F: '(\$8 == "PS") { print \$6 }'`; do find \${dir}/.[A-Za-z0-9]* \! -type l \( -perm -20 -o -perm -02 \) -ls; done" "Verified permissions on user . (hidden) files must be 750 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified permissions on user . (hidden) files is NOT 750 or less permissive, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "for dir in `logins -S files -ox | awk -F: '(\$8 == "PS") { print \$6 }'`; do find \${dir}/.[A-Za-z0-9]* \! -type l \( -perm -20 -o -perm -02 \) -ls; done"

### V-48131 ###
resetRule "SV-61003r1_rule"
if [[ -n $(uname -v | awk -F'.' '$2<=3') ]]; then
	nonzero "$rule" "grep ^PrintLastLog /etc/ssh/sshd_config | grep yes" "Verified the operating system, upon successful logon, must display to the user the date and time of the last logon (access),  therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system, upon successful logon, does NOT display to the user the date and time of the last logon (access), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^PrintLastLog /etc/ssh/sshd_config"
elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
	zero "$rule" "grep ^PrintLastLog /etc/ssh/sshd_config | grep no" "PrintLastLog is a deprecated directive in Solaris 11.4+. Verified the operating system, upon successful logon, must display to the user the date and time of the last logon (access),  therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system, upon successful logon, does NOT display to the user the date and time of the last logon (access), therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^PrintLastLog /etc/ssh/sshd_config"
fi

### V-48133 ###
resetRule "SV-61005r1_rule"
	zero "$rule" "for dir in `logins -S files -ox | awk -F: '(\$8 == "PS") { print \$6 }'`; do find \${dir} -type d -prune \( -perm -g+w -o -perm -o+r -o -perm -o+w -o -perm -o+x \) -ls; done" "Verified permissions on user home directories IS 750 or less permissive, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified permissions on user home directories is NOT 750 or less permissive, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48135 ###
resetRule "SV-61007r2_rule"
if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
  if [[ -z $(pkg info gdm) || -z $(pkg info coherence-26) || -z $(pkg info coherence-27) ]]; then
	na "$rule" "pkg info gdm;pkg info coherence-26;pkg info coherence-27" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
  if [[ -z $(pkg info gdm) ]]; then
	na "$rule" "pkg info gdm" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
fi

### V-48137 ###
resetRule "SV-61009r1_rule"
	zero "$rule" "find / \( -fstype nfs -o -fstype cachefs -o -fstype autofs -o -fstype ctfs -o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o -type d \( -perm -0002 -a ! -perm -1000 \) -ls" "Verified the sticky bit IS set on all world writable directories, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the sticky bit is NOT set on all world writable directories, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48139 ###
resetRule "SV-61011r2_rule"
if [[ -n $(uname -v | awk -F'.' '$2>=1&&$2<=3') ]]; then
  if [[ -z $(pkg info gdm) || -z $(pkg info coherence-26) || -z $(pkg info coherence-27) ]]; then
	na "$rule" "pkg info gdm;pkg info coherence-26;pkg info coherence-27" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
  if [[ -z $(pkg info gdm) ]]; then
	na "$rule" "pkg info gdm" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
fi

### V-48141 ###
resetRule "SV-61013r1_rule"
	nonzero "$rule" "svcs -H svc:/network/ipsec/policy:default | grep online" "Verified the operating system protects the integrity of transmitted information, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT protect the integrity of transmitted information, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "svcs -H svc:/network/ipsec/policy:default"

### V-48143 ###
resetRule "SV-61015r1_rule"
	nonzero "$rule" "grep ^PASSREQ /etc/default/login | grep -i yes" "Verified the operating system does NOT allow logins for users with blank passwords, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does allow logins for users with blank passwords, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "grep ^PASSREQ /etc/default/login"

### V-48145 ###
resetRule "SV-61017r1_rule"
if [[ -n $(zonename | grep global) ]]; then
  if [[ -n $(zfs get encryption $(df -h $(auditconfig -getplugin audit_binfile | awk -F';' '{print $2}' | awk -F'=' '{print $2}') | awk -F' ' '{print $1}' | tail -1) | grep off) ]]; then
    fail "$rule" "zfs get encryption \$(df -h \$(auditconfig -getplugin audit_binfile | awk -F';' '{print \$2}' | awk -F'=' '{print \$2}') | awk -F' ' '{print \$1}' | tail -1)" "Verified the operating system does NOT use cryptographic mechanisms to protect the integrity of audit information, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  else
    pass "$rule" "zfs get encryption \$(df -h \$(auditconfig -getplugin audit_binfile | awk -F';' '{print \$2}' | awk -F'=' '{print \$2}') | awk -F' ' '{print \$1}' | tail -1)" "Verified  the operating system does use cryptographic mechanisms to protect the integrity of audit information, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
  fi
else
  na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-48147 ###
resetRule "SV-61019r1_rule"
nonzero "$rule" "profiles -p RestrictOutbound info | grep 'zone,!net_access'" "Verified the operating system must prevent remote devices that have established a non-remote connection with the system from communicating outside of the communication path with resources in external networks,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT prevent remote devices that have established a non-remote connection with the system from communicating outside of the communication path with resources in external networks, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48149 ###
resetRule "SV-61021r1_rule"
na "$rule" "Data at Rest encryption not required at the OS layer for DC2HS" "Verified Data at Rest encryption not required at the OS layer for DC2HS, therefore the reference STIG is Not Applicable"

### V-48151 ###
resetRule "SV-61023r2_rule"
na "$rule" "Data at Rest encryption not required at the OS layer for DC2HS" "Verified Data at Rest encryption not required at the OS layer for DC2HS, therefore the reference STIG is Not Applicable"

### V-48153 ###
resetRule "SV-61025r1_rule"
na "$rule" "Data at Rest encryption not required at the OS layer for DC2HS" "Verified Data at Rest encryption not required at the OS layer for DC2HS, therefore the reference STIG is Not Applicable"

### V-48155 ###
resetRule "SV-61027r1_rule"
na "$rule" "Data at Rest encryption not required at the OS layer for DC2HS" "Verified Data at Rest encryption not required at the OS layer for DC2HS, therefore the reference STIG is Not Applicable"

### V-48157 ###
resetRule "SV-61029r1_rule"
nonzero "$rule" "rmformat | grep 'No removables found'" "Verified No removable media was found on the system, therefore the reference STIG is Not Applicable"

### V-48159 ###
resetRule "SV-61031r1_rule"
nonzero "$rule" "svcs -H svc:/network/ssh | grep online" "Verified the operating system must use cryptography to protect the confidentiality of remote access sessions, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT use cryptography to protect the confidentiality of remote access sessions, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48161 ###
resetRule "SV-61033r1_rule"
nonzero "$rule" "svcs -H svc:/network/ssh | grep online" "Verified the operating system must maintain the confidentiality of information during aggregation, packaging, and transformation in preparation for transmission, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT maintain the confidentiality of information during aggregation, packaging, and transformation in preparation for transmission, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48163 ###
resetRule "SV-61035r1_rule"
nonzero "$rule" "svcs -H svc:/network/ssh | grep online" "Verified the operating system must employ cryptographic mechanisms to prevent unauthorized disclosure of information during transmission unless otherwise protected by alternative physical measures, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT employ cryptographic mechanisms to prevent unauthorized disclosure of information during transmission unless otherwise protected by alternative physical measures, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48165 ###
resetRule "SV-61037r1_rule"
nonzero "$rule" "ipadm show-prop -p _forward_directed_broadcasts -co current ip | grep 0" "Verified the system must disable directed broadcast packet forwarding, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT disable directed broadcast packet forwarding, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48167 ###
resetRule "SV-61039r1_rule"
nonzero "$rule" "svcs -H svc:/network/ssh | grep online" "Verified the operating system must protect the confidentiality of transmitted information, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT protect the confidentiality of transmitted information, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48169 ###
resetRule "SV-61041r1_rule"
nonzero "$rule" "ipadm show-prop -p _respond_to_timestamp -co current ip | grep 0" "Verified the system must not respond to ICMP timestamp requests, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT not respond to ICMP timestamp requests, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48171 ###
resetRule "SV-61043r1_rule"
nonzero "$rule" "svcs -H svc:/network/ssh | grep online" "Verified the operating system must maintain the integrity of information during aggregation, packaging, and transformation in preparation for transmission, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT maintain the integrity of information during aggregation, packaging, and transformation in preparation for transmission, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48173 ###
resetRule "SV-61045r1_rule"
nonzero "$rule" "ipadm show-prop -p _respond_to_timestamp_broadcast -co current ip | grep 0" "Verified the system must not respond to ICMP broadcast timestamp requests, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system respond to ICMP broadcast timestamp requests. therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48175 ###
resetRule "SV-61047r1_rule"
nonzero "$rule" "svcs -H svc:/network/ssh | grep online" "Verified the operating system must employ cryptographic mechanisms to recognize changes to information during transmission unless otherwise protected by alternative physical measures, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system must employ cryptographic mechanisms to recognize changes to information during transmission unless otherwise protected by alternative physical measures, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48177 ###
resetRule "SV-61049r1_rule"
nonzero "$rule" "ipadm show-prop -p _respond_to_address_mask_broadcast -co current ip | grep 0" "Verified the system must not respond to ICMP broadcast netmask requests, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system responds to ICMP broadcast netmask requests, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48179 ###
resetRule "SV-61051r1_rule"
nonzero "$rule" "svcs -H svc:/network/ssh | grep online" "Verified the operating system must protect the integrity of transmitted information, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT protect the integrity of transmitted information, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48181 ###
resetRule "SV-61053r1_rule"
nonzero "$rule" "ipadm show-prop -p _respond_to_echo_broadcast -co current ip | grep 0" "Verified the system must not respond to broadcast ICMP echo requests,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system responds to broadcast ICMP echo requests, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48183 ###
resetRule "SV-61055r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "cryptoadm list fips-140| grep -c \"is disabled\" | grep 0" "Verified the operating system must employ FIPS-validate or NSA-approved cryptography to implement digital signatures, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system must does NOT FIPS-validate or NSA-approved cryptography to implement digital signatures, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-48185 ###
resetRule "SV-61057r1_rule"
if [[ -n $(ipadm show-prop -p _respond_to_echo_multicast -co current ipv4 | grep 0) && -n $(ipadm show-prop -p _respond_to_echo_multicast -co current ipv6 | grep 0) ]]; then
	pass "$rule" "ipadm show-prop -p _respond_to_echo_multicast -co current ipv4; ipadm show-prop -p _respond_to_echo_multicast -co current ipv6" "Verified the system must not respond to multicast echo requests,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "ipadm show-prop -p _respond_to_echo_multicast -co current ipv4; ipadm show-prop -p _respond_to_echo_multicast -co current ipv6" "Verified the system responds to multicast echo requests, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48187 ###
resetRule "SV-61059r3_rule"
if [[ -n $(zonename | grep global) ]]; then
  nonzero "$rule" "cryptoadm list fips-140| grep -c \"is disabled\" | grep 0" "Verified the operating system must use mechanisms for authentication to a cryptographic module meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for such authentication, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT use mechanisms for authentication to a cryptographic module meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for such authentication, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  na "$rule" "zonename | grep global" "Zone is not global, therefore the reference STIG is Not Applicable"
fi

### V-48189 ###
resetRule "SV-61061r1_rule"
if [[ -n $(ipadm show-prop -p _ignore_redirect -co current ipv4 | grep 1) && -n $(ipadm show-prop -p _ignore_redirect -co current ipv6 | grep 1) ]]; then
  pass "$rule" "ipadm show-prop -p _ignore_redirect -co current ipv4; ipadm show-prop -p _ignore_redirect -co current ipv6" "Verified the system must ignore ICMP redirect messages,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
  fail "$rule" "ipadm show-prop -p _ignore_redirect -co current ipv4; ipadm show-prop -p _ignore_redirect -co current ipv6" "Verified the system does NOT ignore ICMP redirect messages, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48191 ###
resetRule "SV-61063r2_rule"
testFail="false"
outputString=""
if [[ $(zonename) == "global" ]]; then
  # if Global Zone     then check Physical interfaces
  physString=$(dladm show-link -po link,zone,class | grep global | grep phys | awk -F: '{print$1}')
else
  # if Non-Global Zone then check Physical interfaces and SR-IOV (VF) devices
  physString=$((dladm show-link -po link,zone,class | grep phys | awk -F: '{print$1}' && dladm show-phys -po link,device | grep vf | awk -F: '{print$1}') | sort | uniq)
fi
for ii in $physString; do
  # if Infiniband interface then protection should have              restricted, ip-nospoof, dhcp-nospoof
  if [[ $(dladm show-phys $ii -po media) == "Infiniband" && -z $(dladm show-linkprop $ii -c -o value -p protection | awk '(/restricted/ && /ip-nospoof/ && /dhcp-nospoof/){print}') ]];then
	testFail="true"
	outputString+="$(dladm show-phys $ii -o link,media,device)\n$(dladm show-linkprop $ii -o link,property,value -p protection)\n"
  fi
  # if Forwarding is on     then protection should have mac-nospoof, restricted,             dhcp-nospoof
  if [[ $(ipadm show-ifprop $ii -c -o current -p forwarding -m ipv4) == "on" && -z $(dladm show-linkprop $ii -c -o value -p protection | awk '(/mac-nospoof/ && /restricted/ && /dhcp-nospoof/){print}') ]];then
	testFail="true"
	outputString+="$(ipadm show-ifprop $ii -o ifname,property,proto,current)\n$(dladm show-linkprop $ii -o link,property,value -p protection)\n"
  fi
  # if Device is a VF       then protection should have mac-nospoof, restricted,             dhcp-nospoof
  if [[ -n $(dladm show-phys $ii -po device | grep vf) && -z $(dladm show-linkprop $ii -c -o value -p protection | awk '(/mac-nospoof/ && /restricted/ && /dhcp-nospoof/){print}') ]];then
	testFail="true"
	outputString+="$(dladm show-phys $ii -o link,media,device)\n$(dladm show-linkprop $ii -o link,property,value -p protection)\n"
  fi
  # if Ethernet w/o Fwrding then protection should have mac-nospoof, restricted, ip-nospoof, dhcp-nospoof
  if [[ $(dladm show-phys $ii -po media) == "Ethernet" && $(ipadm show-ifprop $ii -c -o current -p forwarding -m ipv4) == "off" && -z $(dladm show-linkprop $ii -c -o value -p protection | awk '(/mac-nospoof/ && /restricted/ && /ip-nospoof/ && /dhcp-nospoof/){print}') ]];then
	testFail="true"
	outputString+="$(dladm show-phys $ii -o link,media,device)\n$(ipadm show-ifprop $ii -o ifname,property,proto,current -p forwarding -m ipv4)\n$(dladm show-linkprop $ii -o link,property,value -p protection)\n"
  fi
done

if [[ $testFail == "false" ]]; then
	pass "$rule" "dladm show-link -o link,zone,class,state; dladm show-phys -o link,media,device; ipadm show-ifprop -o ifname,property,proto,current -p forwarding -m ipv4; dladm show-linkprop -o link,property,value -p protection" "Verified the operating system must prevent internal users from sending out packets which attempt to manipulate or spoof invalid IP addresses, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "$(echo \"$outputString\")" "Interfaces listed are not configured correctly. Verified the operating system does NOT prevent internal users from sending out packets which attempt to manipulate or spoof invalid IP addresses, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi
unset testFail outputString physString ii

### V-48193 ###
resetRule "SV-61065r1_rule"
if [[ -n $(ipadm show-prop -p _strict_dst_multihoming -co current ipv4 | grep 1) && -n $(ipadm show-prop -p _strict_dst_multihoming -co current ipv6 | grep 1) ]]; then
	pass "$rule" "ipadm show-prop -p _strict_dst_multihoming -co current ipv4; ipadm show-prop -p _strict_dst_multihoming -co current ipv6" "Verified the system must set strict multihoming,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "ipadm show-prop -p _ignore_redirect -co current ipv4; ipadm show-prop -p _ignore_redirect -co current ipv6" "Verified the system does NOT set strict multihoming, therefore the reference STIG IS a finding. Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48195 ###
resetRule "SV-61067r1_rule"
nonzero "$rule" "grep \"^ClientAlive\" /etc/ssh/sshd_config | grep '0' | wc -l | grep 2" "Verified the operating system must terminate the network connection associated with a communications session at the end of the session or after 10 minutes of inactivity, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT terminate the network connection associated with a communications session at the end of the session or after 10 minutes of inactivity,  therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48197 ###
resetRule "SV-75425r2_rule"
if [[ -n $(uname -v | awk -F'.' '$2 <= 1') ]]; then
  if [[ -n $(ipadm show-prop -p _send_redirects -co current ipv4 | grep 0) && -n $(ipadm show-prop -p _send_redirects -co current ipv6 | grep 0) ]]; then
		pass "$rule" "ipadm show-prop -p _send_redirects -co current ipv4; ipadm show-prop -p _send_redirects -co current ipv6" "Verified the system must disable ICMP redirect messages, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "ipadm show-prop -p _send_redirects -co current ipv4; ipadm show-prop -p _send_redirects -co current ipv6" "Verified the system does NOT disable ICMP redirect messages, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
else
  if [[ -n $(ipadm show-prop -p send_redirects -co current ipv4 | grep off) && -n $(ipadm show-prop -p send_redirects -co current ipv6 | grep off) ]]; then
		 pass "$rule" "ipadm show-prop -p _send_redirects -co current ipv4; ipadm show-prop -p _send_redirects -co current ipv6" "Verified the system must disable ICMP redirect messages, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
	else
		fail "$rule" "ipadm show-prop -p _send_redirects -co current ipv4; ipadm show-prop -p _send_redirects -co current ipv6" "Verified the system does NOT disable ICMP redirect messages, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48199 ###
resetRule "SV-61071r1_rule"
if [[ -z $(pkg list service/network/ftp | grep '\d*') ]]; then
  pass "$rule" "pkg list service/network/ftp" "Verified FTP service is not installed, therefore the reference STIG is NOT a finding. Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
  nonzero "$rule" "grep 'You are accessing a' \$(grep -i '^DisplayConnect' /etc/proftpd.conf | grep -o '/etc/issue')" "Verified the FTP service must display the DoD approved system use notification message or banner before granting access to the system, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the FTP service does NOT display the DoD approved system use notification message or banner before granting access to the system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48201 ###
resetRule "SV-61073r1_rule"
nonzero "$rule" "ipadm show-prop -p _rev_src_routes -co current tcp | grep 0" "Verified the system must disable TCP reverse IP source routing, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT disable TCP reverse IP source routing, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48203 ###
resetRule "SV-61075r1_rule"
if [[ -n $(uname -v | awk -F'.' '$2 >= 1 && $2 <= 3') ]]; then
  if [[ -z $(pkg info gdm) || -z $(pkg info coherence-26) || -z $(pkg info coherence-27) ]]; then
    na "$rule" "pkg info gdm;pkg info coherence-26;pkg info coherence-27" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
else
  if [[ -z $(pkg info gdm) ]]; then
    na "$rule" "pkg info gdm" "Verified GUI is not present on the system, therefore the reference STIG is Not Applicable"
  fi
fi

### V-48205 ###
resetRule "SV-61077r1_rule"
nonzero "$rule" "grep 'You are accessing a' \$(grep \"^Banner\" /etc/ssh/sshd_config | awk -F' ' '{print \$2}')" "Verified the operating system must display the DoD approved system use notification message or banner for SSH connections, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT display the DoD approved system use notification message or banner for SSH connections, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48207 ###
resetRule "SV-61079r1_rule"
nonzero "$rule" "ipadm show-prop -p _conn_req_max_q0 -co current tcp | grep 4096" "Verified the system must set maximum number of half-open TCP connections to 4096, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT set maximum number of half-open TCP connections to 4096, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48209 ###
resetRule "SV-61081r1_rule"
if [[ -n $(grep 'You are accessing a' /etc/motd) && -n $(grep 'You are accessing a' /etc/issue) ]]; then
	pass "$rule" "cat /etc/motd; cat /etc/issue" "Verified the operating system must display the DoD approved system use notification message or banner before granting access to the system for general system logons, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "cat /etc/motd; cat /etc/issue" "Verified the operating system must display the DoD approved system does NOT use notification message or banner before granting access to the system for general system logons, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48211 ###
resetRule "SV-61083r1_rule"
nonzero "$rule" "ipadm show-prop -p _conn_req_max_q -co current tcp | awk '\$0 >= 1024'" "Verified the system must set maximum number of incoming connections to 1024, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT set maximum number of incoming connections to 1024, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48213 ###
resetRule "SV-61085r4_rule"
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
	nonzero "$rule" "ipfstat -o | grep block | grep lsrr | grep ssrr" "Verified the system must prevent local applications from generating source-routed packets, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT prevent local applications from generating source-routed packets, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
	zero "$rule" "pfctl -s rules | grep allow-opts" "Verified the system must prevent local applications from generating source-routed packets, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT prevent local applications from generating source-routed packets, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48215 ###
resetRule "SV-61087r2_rule"
outputString1=$(ipfstat -io | egrep "block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state")
outputString2=$(pfctl -s rules | egrep "pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all")
failString="true"

if [[ -n $(uname -v | awk -F'.' '$2<=3') ]]; then
   if [[ -n $(svcs ipfilter | grep online) ]]; then
      if [[ "$outputString1" =~ "block out log all keep state keep frags" && "$outputString1" =~ "block in log all" && "$outputString1" =~ "block in log from any to 255.255.255.255/32" && "$outputString1" =~ "block in log from any to 127.0.0.1/32" && "$outputString1" =~ "pass in log quick proto tcp from pool/19 to any port = ssh keep state" ]]; then
         failString="false"
         nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system enforces requirements for remote connections to the information system, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
      else
         fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
      fi
   else
      fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
   fi
elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
   if [[ -n $(svcs firewall | grep online) ]]; then
      if [[ "$outputString2" =~ "pass in log (to pflog0) from <pool_19> to any flags S/SA" && "$outputString2" =~ "block drop in log (to pflog0) all" ]]; then
         failString="false"
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\""  "Verified the operating system enforces requirements for remote connections to the information system, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
      else
         fail "$rule" "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
      fi
   else
         fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
   fi
fi
unset outputString1 outputString2

### V-48217 ###
resetRule "SV-61089r1_rule"
zero "$rule" "routeadm -p | egrep \"routing |forwarding\" | grep enabled" "Verified the system must disable network routing unless required, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT disable network routing unless required, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-48219 ###
resetRule "SV-61091r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2<=3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
	nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
	 nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48221 ###
resetRule "SV-61093r2_rule"
if [[ -n $(inetadm -p | grep tcp_wrappers | grep -i true) ]]; then
	pass "$rule" "inetadm -p | grep tcp_wrappers" "Verified the system must implement TCP Wrappers, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	zero "$rule" "for svc in `inetadm | awk '/svc:\// { print \$NF }'`; do val=`inetadm -l \${svc} | grep -c tcp_wrappers=TRUE`; if [ \${val} -eq 1 ]; then echo \"TCP Wrappers enabled for \${svc}\"; fi; done | grep -v enabled" "Verified individual inetd services IS still be configured to use TCP Wrappers even if the global parameter (above) is set to FALSE, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified individual inetd services is NOT configured to use TCP Wrappers even if the global parameter (above) is set to FALSE, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48223 ###
resetRule "SV-61095r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2<=3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2>=4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48225 ###
resetRule "SV-61097r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48227 ###
resetRule "SV-61099r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48229 ###
resetRule "SV-61101r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48231 ###
resetRule "SV-61103r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48233 ###
resetRule "SV-61105r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48235 ###
resetRule "SV-61107r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48237 ###
resetRule "SV-61109r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48239 ###
resetRule "SV-61111r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi

### V-48241 ###
resetRule "SV-61113r2_rule"
### failString derived from previous check V-48215 SV-61087 ###
if [[ -n $(uname -v | awk -F'.' '$2 <= 3') ]]; then
  if [[ -n $(svcs ipfilter | grep online) ]]; then
    if [[ $failString = "false" ]]; then
        nonzero "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    else
        fail "$rule" "ipfstat -io | egrep \"block out log all keep state keep frags|block in log all|block in log from any to 255.255.255.255/32|block in log from any to 127.0.0.1/32|pass in log quick proto tcp from pool/19 to any port = ssh keep state\"\n$outputString1\nIPF does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs ipfilter" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
elif [[ -n $(uname -v | awk -F'.' '$2 >= 4') ]]; then
  if [[ -n $(svcs firewall | grep online) ]]; then
    if [[ $failString = "false" ]]; then
         nonzero "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"" "Verified the operating system blocks both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG is not a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT block both inbound and outbound traffic between instant messaging clients, independently configured by end users and external service providers, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "pfctl -s rules | egrep \"pass in log (to pflog0) from <pool_19> to any flags S/SA|block drop in log (to pflog0) all\""
    else
         fail "$rule" "pfctl -s rules | egrep \"pass in log \(to pflog0\) from <pool_19> to any flags S/SA|block drop in log \(to pflog0\) all\"\n$outputString2\nFIREWALL does not have all the required configuration items" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
    fi
  else
    fail "$rule" "svcs firewall" "Verified the operating system does NOT enforce requirements for remote connections to the information system, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
  fi
fi
unset failString

### V-48243 ###
resetRule "SV-61115r4_rule"
if [[ -n $(grep ^CRYPT_DEFAULT /etc/security/policy.conf | grep 6) && -n $(grep ^CRYPT_ALGORITHMS_ALLOW /etc/security/policy.conf | grep '6') ]]; then
	pass "$rule" "grep ^CRYPT /etc/security/policy.conf" "Verified systems must employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "grep ^CRYPT /etc/security/policy.conf" "Verified systems do NOT employ cryptographic hashes for passwords using the SHA-2 family of algorithms or FIPS 140-2 approved successors, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-48245 ###
resetRule "SV-61117r1_rule"
nonzero "$rule" "grep ^RETRIES /etc/default/login | awk -F'=' '\$2 <= 3'" "Verified the system must disable accounts after three consecutive unsuccessful login attempts, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system does NOT disable accounts after three consecutive unsuccessful login attempts, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-49621 ###
resetRule "SV-62545r1_rule"
if [[ -n $(zonename | grep global) ]]; then
	nonzero "$rule" "auditconfig -getplugin | grep 'p_fsize=4M'" "Verified the operating system must configure auditing to reduce the likelihood of storage capacity being exceeded,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT configure auditing to reduce the likelihood of storage capacity being exceeded, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  na "$rule" "zonename | grep global" "Verified global zone is not used, therefore the referenced STIG is Not Applicable"
fi

### V-49625 ###
resetRule "SV-62549r1_rule"
	fail "$rule" "" "PKI will be implemented with current plans being in the near future to utilize the Red Hat Identity Management application acting as a gatekeeper on the DC3N AD domain verifying full CAC authentication with Kerberos ticket authentication to provide compliance with this requirement."

### V-49635 ###
resetRule "SV-62559r2_rule"
if [[ -n $(zonename | grep global) ]]; then
  nonzero "$rule" "grep -h \"exclude: scsa2usb\" /etc/system /etc/system.d/* | grep 'exclude: scsa2usb'" "Verified the operating system must monitor for unauthorized connections of mobile devices to organizational information systems,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the operating system does NOT monitor for unauthorized connections of mobile devices to organizational information systems, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
else
  na "$rule" "zonename | grep global" "Verified global zone is not used, therefore the referenced STIG is Not Applicable"
fi

### V-59827 ###
resetRule "SV-74257r1_rule"
if [[ -z $(find /etc/rc* -type f -prune \( -perm -g+w -o -perm -o+w \) -ls) && -z $(find /etc/init.d/ -type f -prune \( -perm -g+w -o -perm -o+w \) -ls) && -z $(find /lib/svc/method/ -type f -prune \( -perm -g+w -o -perm -o+w \) -ls) ]]; then
	pass "$rule" "ls -lL /etc/rc* /etc/init.d /lib/svc/method" "Verified all run control scripts must have mode 0755 or less permissive, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "ls -lL /etc/rc* /etc/init.d /lib/svc/method" "Verified some run control scripts must have mode 0755 or less permissive, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-59829 ###
resetRule "SV-74259r1_rule"
if [[ -z $(find /etc/rc* -type f  -iname "*" -exec lsattr {} + | grep  -v -- '-------------') && -z $(find /etc/init.d/ -type f  -iname "*" -exec lsattr {} + | grep  -v -- '-------------') ]]; then
	pass "$rule" "ls -lL /etc/rc* /etc/init.d" "Verified all run control scripts must have no extended ACLs, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary."
else
	fail "$rule" "ls -lL /etc/rc* /etc/init.d" "Verified some run control scripts have extended ACLs, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-59831 ###
resetRule "SV-74261r3_rule"
	zero "$rule" "find /etc/rc* /etc/init.d -type f -print | xargs grep '^PATH' | egrep '(\\./|::|=:)'" "Verified run control scripts executable search paths must contain only authorized paths, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified run control scripts executable search paths do NOT contain only authorized paths, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-59833 ###
resetRule "SV-74263r2_rule"
	zero "$rule" "find /etc/rc* /etc/init.d -type f -print | xargs grep '^LD_LIBRARY_PATH' | egrep '(\\./|::|=:)'" "Verified run control scripts executable search paths must contain only authorized paths, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified run control scripts executable search paths do NOT contain only authorized paths, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-59835 ###
resetRule "SV-74265r2_rule"
if [[ -z $(find /etc/rc* /etc/init.d -type f -print | xargs grep LD_PRELOAD) ]]; then
	pass "$rule" "find /etc/rc* /etc/init.d -type f -print | xargs grep LD_PRELOAD" "Verified run control scripts lists of preloaded libraries must contain only authorized paths do not exist"
else
	zero "$rule" "find /etc/rc* /etc/init.d -type f -print | xargs grep '^LD_PRELOAD' | egrep '(\\./|::|=:|\\$)'" "Verified run control scripts executable search paths must contain only authorized paths, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified run control scripts executable search paths do NOT contain only authorized paths, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

#### V-59837 ###
resetRule "SV-74267r3_rule"
outputString=$(find /etc/init.d/* /etc/rc*.d/* | xargs -i sh -c "cat "{$1}" | grep '^[*/]'" | awk '{print$1}' | xargs -i ls -lL {$1} 2> /dev/null | awk '{$ii=substr($1,9,1);if($ii=="w"){print}}' | sort | uniq)
	zero "$rule" "echo \"$outputString\"" "Verified Run Control scripts (files or scripts executed from system startup) must not execute World Writable programs or scripts, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified Run Control scripts (files or scripts executed from system startup) DO execute World Writable programs or scripts, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "find /etc/init.d/* /etc/rc*.d/* | xargs -i sh -c \"cat \"{\$1}\" | grep '^[*/]'\" | awk '{print\$1}' | xargs -i ls -lL {\$1} 2> /dev/null | awk '{\$ii=substr(\$1,9,1);if(\$ii==\"w\"){print}}' | sort | uniq"
unset outputString

### V-59839 ###
resetRule "SV-74269r1_rule"
zero "$rule" "find /etc/init.d /etc/rc* -type f -ls | awk '(\$5!=\"root\"){print\$0}'" "Verified all system start-up files ARE owned by root,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all system start-up files are NOT owned by root, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-59841 ###
resetRule "SV-74271r1_rule"
	zero "$rule" "find /etc/init.d /etc/rc* -type f -ls | awk '(\$6!=\"root\"){print\$0}'" "Verified all system start-up files ARE group-owned by root,  therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified all system start-up files areNOT group-owned by root, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."

### V-59843 ###
resetRule "SV-74273r1_rule"
outputString=$(find /etc/init.d/* /etc/rc*.d/* | xargs -i sh -c "cat "{$1}" | grep '^[*/]'" | awk '{print$1}' | xargs -i ls -lL {$1} 2> /dev/null | awk '($3!="root"&&$3!="sys"&&$3!="bin"){print$9":"$1"\n"}' | grep -vi total | sort | uniq)

zero "$rule" "echo \"$outputString\"" "Verified system start-up files must only execute programs owned by a privileged UID or an application, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified system start-up files do NOT execute programs owned by a privileged UID or an application, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "find /etc/init.d/* /etc/rc*.d/* | xargs -i sh -c \"cat \"{\$1}\" | grep '^[*/]'\" | awk '{print\$1}' | xargs -i ls -lL {\$1} 2> /dev/null | awk '(\$3!=\"root\"&&\$3!=\"sys\"&&\$3!=\"bin\"){print\$9\":\"\$1\"\\\n\"}' | grep -vi total | sort | uniq"

unset outputString

### V-61003 ###
resetRule "SV-75471r2_rule"
if [[ -z $(ps -ef | grep xdm | grep -v 'grep xdm') ]]; then
	na "$rule" "ps -ef | grep xdm" "Verified X Display Manager (XDM) is not used on the system, therefore the reference STIG is Not Applicable"
fi

### V-61005 ###
resetRule "SV-75473r2_rule"
if [[ -z $(ps -ef | grep xdm | grep -v 'grep xdm') ]]; then
  na "$rule" "ps -ef | grep xdm" "Verified X Display Manager (XDM) is not used on the system, therefore the reference STIG is Not Applicable"
fi

### V-61023 ###
resetRule "SV-75491r2_rule"
if [[ -z $(ps -ef | grep xdm | grep -v 'grep xdm') ]]; then
  na "$rule" "ps -ef | grep xdm" "Verified X Display Manager (XDM) is not used on the system, therefore the reference STIG is Not Applicable"
fi

### V-61025 ###
resetRule "SV-75493r1_rule"
if [[ -z $(ps -ef | grep xdm | grep -v 'grep xdm') ]]; then
  na "$rule" "ps -ef | grep xdm" "Verified X Display Manager (XDM) is not used on the system, therefore the reference STIG is Not Applicable"
fi

### V-61027 ###
resetRule "SV-75495r2_rule"
if [[ -z $(ps -ef | grep xdm | grep -v 'grep xdm') ]]; then
  na "$rule" "ps -ef | grep xdm" "Verified X Display Manager (XDM) is not used on the system, therefore the reference STIG is Not Applicable"
fi

### V-61029 ###
resetRule "SV-75497r2_rule"
if [[ -z $(ps -ef | grep xdm | grep -v 'grep xdm') ]]; then
  na "$rule" "ps -ef | grep xdm" "Verified X Display Manager (XDM) is not used on the system, therefore the reference STIG is Not Applicable"
fi

### V-61031 ###
resetRule "SV-75499r1_rule"
if [[ -z $(ps -ef | grep xdm | grep -v 'grep xdm') ]]; then
  na "$rule" "ps -ef | grep xdm" "Verified X Display Manager (XDM) is not used on the system, therefore the reference STIG is Not Applicable"
fi

### V-71495 ###
resetRule "SV-86119r1_rule"
if [[ -n $(svcs vntsd | grep online) ]]; then
	na "$rule" "svcs vntsd | grep online" "Verified vnsd is in use, therefore the reference STIG is Not Applicable"
else
	nonzero "$rule" "cat /etc/user_attr | grep solaris.vntsd.consoles" "Verified access to a domain console via telnet must be restricted to the local host, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified access to a domain console via telnet is NOT restricted to the local host, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-71497 ###
resetRule "SV-86121r1_rule"
if [[ -n $(svcs vntsd | grep online) ]]; then
  na "$rule" "svcs vntsd | grep online" "Verified vnsd is in use, therefore the reference STIG is Not Applicable"
else
  nonzero "$rule" "svcprop -p vntsd/authorization vntsd | grep true" "Verified access to a logical domain console must be restricted to authorized users, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified access to a logical domain console is NOT restricted to authorized users, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."
fi

### V-72827 ###
resetRule "SV-87479r2_rule"
	zero "$rule" "dladm show-phys | grep -v Ethernet | grep -v LINK" "Verified wireless adapters do not exist on the system, therefore the reference STIG is Not Applicable" "Verify wireless adapter is documented"

### V-91209 ###
resetRule "SV-101309r1_rule"
# End of sshd_config must have Match Address xyz followed by MaxAuthTries 0.
sedSez=$(sed -n '/Match Address/ {;N;/\n.*/ p;}' /etc/ssh/sshd_config)
	nonzero "$rule" "echo i\"$sedSez\" | egrep '(Match Address|MaxAuthTries 0)'" "Verified systems using OpenSSH must be configured per site policy to only allow access by approved networks or hosts, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified systems using OpenSSH is NOT configured per site policy to only allow access by approved networks or hosts, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary." "sed -n '/Match Address/ {;N;/\\\n.*/ p;}' /etc/ssh/sshd_config | egrep '(Match Address|MaxAuthTries 0)'"
unset sedSez

### V-95717 ###
resetRule "SV-104855r1_rule"
	nonzero "$rule" "coreadm | grep \"global core file pattern\" | grep /" "Verified the system must be configured to store any process core dumps in a specific, centralized directory, therefore the reference STIG is NOT a finding.  Engineer did NOT apply a change. Setting was correct by default and/or no change was necessary." "Verified the system is NOT configured to store any process core dumps in a specific, centralized directory, therefore the reference STIG IS a finding.  Engineer did NOT apply a change. Setting was incorrect by default and/or no change was necessary."



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
