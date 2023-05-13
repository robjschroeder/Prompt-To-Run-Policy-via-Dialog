#!/bin/bash
# shellcheck disable=SC2034

####################################################################################################
#
# Prompt To Run Policy via swiftDialog
#
#	Script will use swiftDialog to let the user know they need to
#	run a specific policy in Jamf Pro. When prompted, the user
#	will be able to choose to run the policy or choose to do later.
#
#
####################################################################################################
#
# HISTORY
#
# Version 1.0.0; created 05.12.2023 @robjschroeder
#
#
####################################################################################################
#
####################################################################################################
#
# Global Variables
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Version and Jamf Pro Script Parameters
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

scriptVersion="1.0.0"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
scriptLog="${4:-"/var/log/com.company.log"}"														# Company log file
jamfProPolicyName="${5:-""}"																		# Jamf Pro Policy Name
jamfProPolicyID="${6:-""}"																			# Jamf Pro Policy ID
jamfProPolicyAction="${7:-"0"}"																		# Jamf Pro Policy Action [ 0 (view) | 1 (execute) | 2 (silently execute) ]
messageTitle="${8:-"This is the title of the prompt"}"												# Message Title
message="${9:-"This is the message of the prompt"}"													# Message
timeout="${10:-"120"}"																				# Timeout in seconds
kbArticle="${11:-""}"																				# KB Article Number


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Global Variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

dialogApp="/usr/local/bin/dialog"
dialogCommandFile=$( /usr/bin/mktemp "/var/tmp/Prompt-to-Run-Policy.XXXXXXX" )
overlayicon=$( defaults read /Library/Preferences/com.jamfsoftware.jamf.plist self_service_app_path )
icon="/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/AlertNoteIcon.icns"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Operating System, Computer Model Name, etc.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

osVersion=$( sw_vers -productVersion )
osBuild=$( sw_vers -buildVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
modelName=$( /usr/libexec/PlistBuddy -c 'Print :0:_items:0:machine_name' /dev/stdin <<< "$(system_profiler -xml SPHardwareDataType)" )
exitCode="0"

####################################################################################################
#
# Pre-flight Checks
#
####################################################################################################

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Logging
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ ! -f "${scriptLog}" ]]; then
	touch "${scriptLog}"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Client-side Script Logging Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function updateScriptLog() {
	echo -e "$( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Current Logged-in User Function
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function currentLoggedInUser() {
	loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
	updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User: ${loggedInUser}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Logging Preamble
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "\n\n###\n# PROMPT TO RUN POLICY (${scriptVersion})\n# \n###\n"
updateScriptLog "PRE-FLIGHT CHECK: Initiating …"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm script is running as root
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

if [[ $(id -u) -ne 0 ]]; then
	updateScriptLog "PRE-FLIGHT CHECK: This script must be run as root; exiting."
	exit 1
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Confirm Dock is running / user is at Desktop
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

until pgrep -q -x "Finder" && pgrep -q -x "Dock"; do
	updateScriptLog "PRE-FLIGHT CHECK: Finder & Dock are NOT running; pausing for 1 second"
	sleep 1
done

updateScriptLog "PRE-FLIGHT CHECK: Finder & Dock are running; proceeding …"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate Logged-in System Accounts
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Check for Logged-in System Accounts …"
currentLoggedInUser

counter="1"

until { [[ "${loggedInUser}" != "_mbsetupuser" ]] || [[ "${counter}" -gt "180" ]]; } && { [[ "${loggedInUser}" != "loginwindow" ]] || [[ "${counter}" -gt "30" ]]; } ; do
	
	updateScriptLog "PRE-FLIGHT CHECK: Logged-in User Counter: ${counter}"
	currentLoggedInUser
	sleep 2
	((counter++))
	
done

loggedInUserFullname=$( id -F "${loggedInUser}" )
loggedInUserFirstname=$( echo "$loggedInUserFullname" | sed -E 's/^.*, // ; s/([^ ]*).*/\1/' | sed 's/\(.\{25\}\).*/\1…/' | awk '{print toupper(substr($0,1,1))substr($0,2)}' )
loggedInUserID=$( id -u "${loggedInUser}" )
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User First Name: ${loggedInUserFirstname}"
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User ID: ${loggedInUserID}"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Validate / install swiftDialog (Thanks big bunches, @acodega!)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function dialogCheck() {
	
	# Get the URL of the latest PKG From the Dialog GitHub repo
	dialogURL=$(curl --silent --fail "https://api.github.com/repos/bartreardon/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")
	
	# Expected Team ID of the downloaded PKG
	expectedDialogTeamID="PWA5E9TQ59"
	
	# Check for Dialog and install if not found
	if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then
		
		updateScriptLog "PRE-FLIGHT CHECK: Dialog not found. Installing..."
		
		# Create temporary working directory
		workDirectory=$( /usr/bin/basename "$0" )
		tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )
		
		# Download the installer package
		/usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"
		
		# Verify the download
		teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')
		
		# Install the package if Team ID validates
		if [[ "$expectedDialogTeamID" == "$teamID" ]]; then
			
			/usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
			sleep 2
			dialogVersion=$( /usr/local/bin/dialog --version )
			updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} installed; proceeding..."
			
		else
			
			# Display a so-called "simple" dialog if Team ID fails to validate
			osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "PROMPT TO RUN POLICY: Error" buttons {"Close"} with icon caution'
			exitCode="1"
			quitScript
			
		fi
		
		# Remove the temporary working directory when done
		/bin/rm -Rf "$tempDirectory"
		
	else
		
		updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."
		
	fi
	
}

if [[ ! -e "/Library/Application Support/Dialog/Dialog.app" ]]; then
	dialogCheck
else
	updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."
fi



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Pre-flight Check: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Complete"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Prompt user to execute the Self Service policy via swiftDialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function promptUser() {
	
	updateScriptLog "PROMPT TO RUN POLICY: Prompting user to execute the \"${jamfProPolicyName}\" policy; "
	if [[ -n $kbArticle ]]; then
	
	dialogCMD="$dialogApp --ontop --title \"$messageTitle\" \
		--message \"Hello ${loggedInUserFirstname}, $message\" \
		--icon \"$icon\" \
		--button1text \"OK\" \
		--button2text \"Later\" \
		--overlayicon \"$overlayicon\" \
		--titlefont 'size=28' \
		--messagefont 'size=14' \
		--infobuttontext \"$kbArticle\" \
		--infobuttonaction \"https://servicenow.company.com/support?id=kb_article_view&sysparm_article=$kbArticle\" \
		--small \
		--moveable \
		--timer \"$timeout\" \
		--position 'centre' \
		--ignorednd \
		--commandfile \"$dialogCommandFile\" "
	
	eval "$dialogCMD"
	
	returnCode=$?
	
	else
		dialogCMD="$dialogApp --ontop --title \"$messageTitle\" \
		--message \"Hello ${loggedInUserFirstname}, $message\" \
		--icon \"$icon\" \
		--button1text \"OK\" \
		--button2text \"Later\" \
		--overlayicon \"$overlayicon\" \
		--titlefont 'size=28' \
		--messagefont 'size=14' \
		--small \
		--moveable \
		--timer \"$timeout\" \
		--position 'centre' \
		--ignorednd \
		--commandfile \"$dialogCommandFile\" "
		
		eval "$dialogCMD"
		
		returnCode=$?
	fi
	
	case ${returnCode} in
		
		0)  updateScriptLog "PROMPT TO RUN POLICY: ${loggedInUser} clicked OK; "
			case ${jamfProPolicyAction} in
				"2" )
					updateScriptLog "PROMPT TO RUN POLICY: Action is set to $jamfProPolicyAction, setting appropriately"
					updateScriptLog "PROMPT TO RUN POLICY: Executing policy $jamfProPolicyID silently"
					/usr/local/bin/jamf policy -id "$jamfProPolicyID"
					updateScriptLog "PROMPT TO RUN POLICY: Done"
          exit $exitCode
          ;;
				"1" )
					updateScriptLog "PROMPT TO RUN POLICY: Action is set to $jamfProPolicyAction, setting appropriately"
					policyExecuteURL="jamfselfservice://content?entity=policy&id=$jamfProPolicyID&action=execute"
					updateScriptLog  "PROMPT TO RUN POLICY: Executing policy at $policyExecuteURL"
					su - "${loggedInUser}" -c "/usr/bin/open \"${policyExecuteURL}\""
					updateScriptLog "PROMPT TO RUN POLICY: Done"
					exit $exitCode
				;;
				"0" )
					updateScriptLog "PROMPT TO RUN POLICY: Action is set to $jamfProPolicyAction, setting appropriately"
					policyViewURL="jamfselfservice://content?entity=policy&id=$jamfProPolicyID&action=view"
					updateScriptLog "PROMPT TO RUN POLICY: Viewing policy at $policyViewURL"
					su - "$loggedInUser" -c "/usr/bin/open \"${policyViewURL}\""
					updateScriptLog "PROMPT TO RUN POLICY: Done"
					exit $exitCode
				;;
			esac
		;;
		2)  updateScriptLog "PROMPT TO RUN POLICY: ${loggedInUser} clicked Later; "
		;;
		4)  updateScriptLog "PROMPT TO RUN POLICY: ${loggedInUser} allowed timer to expire; "
		;;
		*)  updateScriptLog "PROMPT TO RUN POLICY: Something else happened; swiftDialog Return Code: ${returnCode}; "
		;;
		
	esac
	
	/bin/rm -f "$dialogCommandFile"
	
}

promptUser
