$l1hklm= @{    
    "hklm\system\currentcontrolset\control\sam"= @{
        "relaxminimumpasswordlengthlimits"= 1
        "limitblankpassworduse"= 1
        "scenoapplylegacyauditpolicy"= 1
        "crashonauditfail"= 0
        "restrictremotesam"= "o:bag:bad:(a;;rc;;;ba)"
        "restrictanonymoussam"= 1
        "restrictanonymous"= 1
        "disabledomaincreds"= 1
        "everyoneincludesanonymous"= 0
        "forceguest"= 0
        "usemachineid"= 1
        "nolmhash"= 1
        "lmcompatibilitylevel"= 5
        "runasppl"= 1
        }

    "hklm\software\microsoft\windows\currentversion\policies\system"= @{
        "disablecad"= 0
        "dontdisplaylastusername"= 1
        "inactivitytimeoutsecs"= 900
        "legalnoticetext"= "{youre text}"
        "legalnoticecaption"= "{youre text}"
        "filteradministratortoken"= 1
        "consentpromptbehavioradmin"= 2
        "consentpromptbehavioruser"= 0
        "enableinstallerdetection"= 1
        "enablesecureuiapaths"= 1
        "enablelua"= 1
        "promptonsecuredesktop"= 1
        "enablevirtualization"= 1
        "msaoptional"= 1
        "enablempr"= 0
        "disableautomaticrestartsignon"= 1
        }

    "hklm\software\microsoft\windows nt\currentversion\winlogon"= @{
        "passwordexpirywarning"= 14
        "scremoveoption"= 3
        "screensavergraceperiod"= 5
        "autoadminlogon"= 0
        }

    "hklm\system\currentcontrolset\services\lanmanworkstation\parameters"= @{
        "requiresecuritysignature"= 1
        "enablesecuritysignature"= 1
        "enableplaintextpassword"= 0
        }

    "hklm\system\currentcontrolset\services\lanmanserver\parameters"= @{
        "autodisconnect"= 15
        "requiresecuritysignature"= 1
        "enablesecuritysignature"= 1
        "enableforcedlogoff"= 1
        "smbservernameh ardeninglevel"= 2
        "NullSessionPipes"= ""
        "restrictnullsessaccess"= 1
        "NullSessionShares"= ""
        "smb1"= 0
        }

    "hklm\system\currentcontrolset\control\securepipeservers\winreg\allowedexactpaths"= @{
        "machine" = "system\currentcontrolset\control\productoptions,system\currentcontrolset\control\server applications,software\microsoft\windows nt\currentversion"
        }

    "hklm\system\currentcontrolset\control\securepipeservers\winreg\allowedpaths"= @{
        "machine"= "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server, Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog"
        }

    "hklm\system\currentcontrolset\control\lsa\msv1_0"= @{
        "allownullsessionfallback"= 0
        "ntlmminclientsec"= 537395200
        "ntlmminserversec"= 537395200
        "auditreceivingntlmtraffic"= 2
        "restrictsendingntlmtraffic"= 2
        }

    "hklm\system\currentcontrolset\control\lsa\pku2u"= @{
        "allowonlineid"= 0
        }

    "hklm\software\microsoft\windows\currentversion\policies\system\kerberos\parameters"= @{
        "supportedencryptiontypes"= 2147483640
        }

    "hklm\system\currentcontrolset\services\ldap"= @{
        "ldapclientconfidentiality"= 2
        "ldapclientintegrity"= 1
        }

    "hklm\system\currentcontrolset\control\session manager\kernel"= @{
        "obcaseinsensitive"= 1
        "disableexceptionchainvalidation"= 0}

    "hklm\system\currentcontrolset\control\session manager"= @{
        "protectionmode"= 1
        "safedllsearchmode"= 1
        }


    "hklm\system\currentcontrolset\services\browser"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\iisadmin"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\irmon"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\ftpsvc"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\sshd"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\rpclocator"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\remoteaccess"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\simptcp"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\sacsvr"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\ssdpsrv"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\upnphost"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\wmsvc"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\wmpnetworksvc"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\icssvc"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\w3svc"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\xboxgipsvc"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\xblauthmanager"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\xblgamesave"= @{
        "start"= 4
        }

    "hklm\system\currentcontrolset\services\xboxnetapisvc"= @{
        "start"= 4
        }

    "hklm\software\policies\microsoft\windowsfirewall\privateprofile"= @{
        "enablefirewall"= 1
        "defaultinboundaction"= 1
        "disablenotifications"= 1
        }

    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"= @{
        "LogFilePath"= "%systemroot%\system32\logfiles\firewall\privatefw.log"
        "logfilesize"= 16384
        "logdroppedpackets"= 1
        "logsuccessfulconnections"= 1
        }

    "hklm\software\policies\microsoft\windowsfirewall\publicprofile"= @{
        "enablefirewall"= 1
        "defaultinboundaction"= 1
        "disablenotifications"= 1
        "allowlocalpolicymerge"= 0
        "allowlocalipsecpolicymerge"= 0
        }

    "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"= @{
        "LogFilePath"= "%systemroot%\system32\logfiles\firewall\publicfw.log"
        "logfilesize"= 16384
        "logdroppedpackets"= 1
        "logsuccessfulconnections"= 1
        }

    "hklm\software\policies\microsoft\windows\personalization"= @{
        "nolockscreencamera"= 1
        "nolockscreenslideshow"= 1
        }

    "hklm\software\policies\microsoft\inputpersonalization"= @{
        "allowinputpersonalization"= 0
        }

    "hklm\system\currentcontrolset\services\mrxsmb10"= @{
        "start"= 4
        }

    "hklm\software\microsoft\cryptography\wintrust\config"= @{
        "EnableCertPaddingCheck"= 1
        }

    "hklm\system\currentcontrolset\services\netbt\parameters"= @{
        "nodetype"= 2
        "nonamereleaseondemand"= 1
        }

    "hklm\system\currentcontrolset\control\securityproviders\wdigest"= @{
        "uselogoncredential"= 0
        }

    "hklm\system\currentcontrolset\services\tcpip6\parameters"= @{
        "disableipsourcerouting"= 2
        }

    "hklm\system\currentcontrolset\services\tcpip\parameters"= @{
        "disableipsourcerouting"= 2
        "enableicmpredirect"= 0
        }

    "hklm\system\currentcontrolset\services\eventlog\security"= @{
        "warninglevel"= 90
        }

    "hklm\software\policies\microsoft\windows nt\dnsclient"= @{
        "enablemdns"= 0
        }

    "hklm\software\policies\microsoft\windows\lanmanserver"= @{
        "auditclientdoesnotsupportencryption"= 1
        "auditclientdoesnotsupportsigning"= 1
        "auditinsecureguestlogon"= 1
        "enableauthratelimiter"= 1
        "minsmb2dialect"= 785
        "invalidauthenticationdelaytimeinms"= 2000
        }

    "hklm\software\policies\microsoft\windows\bowser"= @{
        "enablemailslots"= 0
        }

    "hklm\software\policies\microsoft\windows\lanmanworkstation"= @{
        "auditinsecureguestlogon"= 1
        "auditserverdoesnotsupportencryption"= 1
        "auditserverdoesnotsupportsigning"= 1
        "allowinsecureguestauth"= 0
        "minsmb2dialect"= 785
        "requireencryption"= 1
        }

    "hklm\software\policies\microsoft\windows\networkprovider"= @{"enablemailslots"= 0}

    "hklm\software\policies\microsoft\windows\network connections"= @{
        "nc_allownetbridge_nla"= 0
        "nc_showsharedaccessui"= 0
        }

    "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" = @{
        "\\*\SYSVOL" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
        "\\*\NETLOGON" = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
        }

    "hklm\software\policies\microsoft\windows\wcmsvc\grouppolicy"= @{
        "fminimizeconnections"= 3
        }

    "hklm\software\microsoft\wcmsvc\wifinetworkmanager\config"= @{
        "autoconnectallowedoem"= 0
        }

    "hklm\software\policies\microsoft\windows nt\printers"= @{
        "registerspoolerremoterpcendpoint"= 2
        "redirectionguardpolicy"= 1
        "copyfilespolicy"= 1
        "disablewebpnpdownload"= 1
        }

    "hklm\software\policies\microsoft\windows nt\printers\rpc"= @{
        "rpcusenamedpipeprotocol"= 0
        "rpcauthentication"= 0
        "rpcprotocols"= 5
        "forcekerberosforrpc"= 1
        "rpctcpport"= 0
        }

    "hklm\system\currentcontrolset\control\print"= @{
        "rpcauthnlevelprivacyenabled"= 1
        }

    "hklm\software\policies\microsoft\windows nt\printers\pointandprint"= @{
        "restrictdriverinstallationtoadministrators"= 1
        "nowarningnoelevationoninstall"= 0
        "updatepromptsettings"= 0
        }

    "hklm\software\microsoft\windows\currentversion\policies\system\audit"= @{
        "processcreationincludecmdline_enabled"= 1
        }

    "hklm\software\microsoft\windows\currentversion\policies\system\credssp\parameters"= @{
        "allowencryptionoracle"= 0
        }

    "hklm\software\policies\microsoft\windows\credentialsdelegation"= @{
        "allowprotectedcreds"= 1
        }

    "hklm\software\policies\microsoft\windows\deviceguard"= @{
        "enablevirtualizationbasedsecurity"= 1
        "requireplatformsecurityfeatures"= 3
        "hypervisorenforcedcodeintegrity"= 1
        "hvcimatrequired"= 1
        "lsacfgflags"= 1
        "configuresystemguardlaunch"= 1
        "configurekernelshadowstackslaunch"= 1
        }

    "hklm\software\policies\microsoft\windows\device metadata"= @{
        "preventdevicemetadatafromnetwork"= 1
        }

    "hklm\system\currentcontrolset\policies\earlylaunch"= @{
        "driverloadpolicy"= 3
        }

    "hklm\software\policies\microsoft\windows\system"= @{
        "enablecdp"= 0
        "allowcustomsspsaps"= 0
        "blockuserfromshowingaccountdetailsonsignin"= 1
        "dontdisplaynetworkselectionui"= 1
        "disablelockscreenappnotifications"= 1
        "allowdomainpinlogon"= 0
        "nolocalpasswordresetquestions"= 1
        "enablesmartscreen"= 1
        "shellsmartscreenlevel"= "Block"
        }

    "hklm\software\microsoft\windows\currentversion\policies\explorer"= @{
        "nowebservices"= 1
        "noautorun"= 1
        "nodrivetypeautorun"= 255
        "prexpsp2shellprotocolbehavior"= 0
        }

    "hklm\software\policies\microsoft\power\powersettings\f15576e8-98b7-4186-b944-eafa664402d9"= @{
        "dcsettingindex"= 0
        "acsettingindex"= 0
        }

    "hklm\software\policies\microsoft\power\powersettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"= @{
        "dcsettingindex"= 1
        "acsettingindex"= 1
        }

    "hklm\software\policies\microsoft\windows nt\terminal services"= @{
        "fallowunsolicited"= 0
        "fallowtogethelp"= 0
        "disablepasswordsaving"= 1
        "fdisablecdm"= 1
        "fpromptforpassword"= 1
        "fencryptrpctraffic"= 1
        "securitylayer"= 2
        "userauthentication"= 1
        "minencryptionlevel"= 3
        "deletetempdirsonexit"= 1
        }

    "hklm\software\policies\microsoft\windows nt\rpc"= @{
        "enableauthepresolution"= 1
        "restrictremoteclients"= 1
        }

    "hklm\software\policies\microsoft\w32time\timeproviders\ntpclient"= @{"enabled"= 1}
    "hklm\software\policies\microsoft\windows\sudo"= @{"enabled"= 0}
    "hklm\software\policies\microsoft\windows\appx"= @{
        "disableperuserunsignedpackagesbydefault"= 1
        "blocknonadminuserinstall"= 1
        }

    "hklm\software\policies\microsoft\windows\appprivacy"= @{
        "letappsactivatewithvoiceabovelock"= 2
        }

    "hklm\software\policies\microsoft\windows\explorer"= @{
        "noautoplayfornonvolume"= 1
        "nodataexecutionprevention"= 0
        "disablemotwoninsecurepathcopy"= 0
        "noheapterminationoncorruption"= 0
        }

    "hklm\software\policies\microsoft\biometrics\facialfeatures"= @{
        "enhancedantispoofing"= 1
        }

    "hklm\software\policies\microsoft\windows\cloudcontent"= @{
        "disableconsumeraccountstatecontent"= 1
        "disablewindowsconsumerfeatures"= 1
        }

    "hklm\software\policies\microsoft\windows\connect"= @{
        "requirepinforpairing"= 2
        }

    "hklm\software\policies\microsoft\windows\credui"= @{
        "disablepasswordreveal"= 1
        }

    "hklm\software\microsoft\windows\currentversion\policies\credui"= @{
        "enumerateadministrators"= 0
        }

    "hklm\software\policies\microsoft\windows\datacollection"= @{
        "allowtelemetry"= 1
        "disableonesettingsdownloads"= 1
        "donotshowfeedbacknotifications"= 1
        "enableonesettingsauditing"= 1
        "limitdiagnosticlogcollection"= 1
        "limitdumpcollection"= 1
        }

    "hklm\software\policies\microsoft\windows\deliveryoptimization"= @{
        "dodownloadmode"= 3
        }

    "hklm\software\policies\microsoft\windows\appinstaller"= @{
        "enableexperimentalfeatures"= 0
        "enablehashoverride"= 0
        "enablelocalarchivemalwarescanoverride"= 0
        "enablebypasscertificatepinningformicrosoftstore"= 0
        "enablemsappinstallerprotocol"= 0
        }

    "hklm\software\policies\microsoft\windows\eventlog\application"= @{
        "retention"= 0
        "maxsize"= 32768
        }

    "hklm\software\policies\microsoft\windows\eventlog\security"= @{
        "retention"= 0
        "maxsize"= 196608
        }

    "hklm\software\policies\microsoft\windows\eventlog\setup"= @{
        "retention"= 0
        "maxsize"= 32768
        }

    "hklm\software\policies\microsoft\windows\eventlog\system"= @{
        "retention"= 0
        "maxsize"= 32768
        }

    "hklm\software\policies\microsoft\microsoftaccount"= @{
        "disableuserauth"= 1
        }

    "hklm\software\policies\microsoft\windows defender\features"= @{
        "passiveremediation"= 1
        }

    "hklm\software\policies\microsoft\windows defender\spynet"= @{
        "localsettingoverridespynetreporting"= 0
        }

    "hklm\software\policies\microsoft\windows defender\windows defender exploit guard\asr"= @{
        "exploitguard_asr_rules"= 1
        }

    "hklm\software\policies\microsoft\windows defender\windows defender exploit guard\asr\rules"= @{
        "26190899-1602-49e8-8b27-eb1d0a1ce869"= 1
        "3b576869-a4ec-4529-8536-b80a7769e899"= 1
        "56a863a9-875e-4185-98a7-b882c64b5ce5"= 1
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc"= 1
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"= 1
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"= 1
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"= 1
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"= 1
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"= 1
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"= 1
        "d3e037e1-3eb8-44c8-a917-57927947596d"= 1
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a"= 1
        "e6db77e5-3df2-4cf1-b95a-636979351e5b"= 1
        }

    "hklm\software\policies\microsoft\windows defender\windows defender exploit guard\network protection"= @{
        "enablenetworkprotection"= 1
        }
    "hklm\software\policies\microsoft\windows defender\mpengine"= @{
        "enablefilehashcomputation"= 1
        }

    "hklm\software\policies\microsoft\windows defender\real-time protection"= @{
        "oobeenablertpandsigupdate"= 1
        "disableioavprotection"= 0
        "disablerealtimemonitoring"= 0
        "disablebehaviormonitoring"= 0
        "disablescriptscanning"= 0
        }

    "hklm\software\policies\microsoft\windows defender\remediation\behavioral network blocks\brute force protection"= @{
        "bruteforceprotectionconfiguredstate"= 1
        }

    "hklm\software\policies\microsoft\windows defender\scan"= @{
        "quickscanincludeexclusions"= 1
        "disablepackedexescanning"= 0
        "disableremovabledrivescanning"= 0
        "daysuntilaggressivecatchupquickscan"= 7
        "disableemailscanning"= 0
        }

    "hklm\software\policies\microsoft\windows defender"= @{
        "puaprotection"= 1
        "hideexclusionsfromlocalusers"= 1
        }

    "hklm\software\policies\microsoft\apphvsi"= @{
        "auditapplicationguard"= 1
        "allowcameramicrophoneredirection"= 0
        "allowpersistence"= 0
        "savefilestohost"= 0
        "apphvsiclipboardsettings"= 1
        "allowapphvsi_providerset"= 1
        }

    "hklm\software\policies\microsoft\windows\onedrive"= @{
        "disablefilesyncngsc"= 1
        }

    "hklm\software\policies\microsoft\internet explorer\feeds"= @{
        "disableenclosuredownload"= 1
        "allowbasicauthinclear"= 0
        }

    "hklm\software\policies\microsoft\windows\windows search"= @{
        "allowcortana"= 0
        "allowcortanaabovelock"= 0
        "allowindexingencryptedstoresoritems"= 0
        "allowsearchtouselocation"= 0
        }

    "hklm\software\policies\microsoft\windowsstore"= @{
        "autodownload"= 4
        "disableosupgrade"= 1
        }

    "hklm\software\policies\microsoft\dsh"= @{
        "allownewsandinterests"= 0
        }

    "hklm\software\policies\microsoft\windows\wtds\components"= @{
        "capturethreatwindow"= 1
        "notifymalicious"= 1
        "notifypasswordreuse"= 1
        "notifyunsafeapp"= 1
        "serviceenabled"= 1
        }

    "hklm\software\policies\microsoft\windows\gamedvr"= @{
        "allowgamedvr"= 0
        }

    "hklm\software\microsoft\policies\passportforwork\biometrics"= @{
        "enableesswithsupportedperipherals"= 1
        }

    "hklm\software\policies\microsoft\windowsinkworkspace"= @{
        "allowwindowsinkworkspace"= 1
        }

    "hklm\software\policies\microsoft\windows\installer"= @{"enableusercontrol"= 0
    "alwaysinstallelevated"= 0}

    "hklm\software\policies\microsoft\windows\winrm\client"= @{
        "allowbasic"= 0
        "allowunencryptedtraffic"= 0
        "allowdigest"= 0
        }

    "hklm\software\policies\microsoft\windows\winrm\service"= @{
        "allowbasic"= 0
        "allowunencryptedtraffic"= 0
        "disablerunas"= 1
        }

    "hklm\software\policies\microsoft\windows\sandbox"= @{
        "allowclipboardredirection"= 0
        "allownetworking"= 0
        }

    "hklm\software\policies\microsoft\windows defender security center\app and browser protection"= @{"disallowexploitprotectionoverride"= 1}
    "hklm\software\policies\microsoft\windows\windowsupdate\au"= @{
        "noautorebootwithloggedonusers"= 0
        "noautoupdate"= 0
        "scheduledinstallday"= 0
        }

    "hklm\software\policies\microsoft\windows\windowsupdate"= @{
        "allowtemporaryenterprisefeaturecontrol"= 0
        "setdisablepauseuxaccess"= 1
        "managepreviewbuildspolicyvalue"= 1
        "deferfeatureupdates"= 1 
        "deferfeatureupdatesperiodindays"= 180
        "deferqualityupdates"= 1
        "deferqualityupdatesperiodindays"= 0
        "setallowoptionalcontent"= 0
        }
}

$l1hku= @{
    "hku\[user sid]\software\policies\microsoft\windows\currentversion\pushnotifications"= @{
        "notoastapplicationnotificationonlockscreen"= 1
        }

    "hku\[user sid]\software\microsoft\windows\currentversion\policies\attachments"= @{
        "savezoneinformation"= 2
        "scanwithantivirus"= 3
        }

    "hku\[user sid]\software\policies\microsoft\windows\cloudcontent"= @{
        "configurewindowsspotlight"= 2
        "disablethirdpartysuggestions"= 1
        "disablespotlightcollectionondesktop"= 1
        }

    "hku\[user sid]\software\microsoft\windows\currentversion\policies\explorer"= @{
        "noinplacesharing"= 1
        }

    "hku\[user sid]\software\policies\microsoft\windows\windowscopilot"= @{
        "turnoffwindowscopilot"= 1
        }

    "hku\[user sid]\software\policies\microsoft\windows\installer"= @{
        "alwaysinstallelevated"= 0
        }
}

function Set-RegistryKeys {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$table
    )
    foreach ($key in $table.Keys) {
        try {
            # Convert HKLM to full path
            $fullPath = $key -replace '(?i)^hklm\\', 'HKLM:\\'
            
            if (!(Test-Path $fullPath)) {
                New-Item -Path $fullPath -Force | Out-Null
            }
            $values = $table[$key]
            foreach ($valueName in $values.Keys) {
                $value = $values[$valueName]
                $type = if ($value -is [int]) { "DWord" } else { "String" }
                
                # Use New-ItemProperty instead of Set-ItemProperty
                if (Get-ItemProperty -Path $fullPath -Name $valueName -ErrorAction SilentlyContinue) {
                    Set-ItemProperty -Path $fullPath -Name $valueName -Value $value
                } else {
                    New-ItemProperty -Path $fullPath -Name $valueName -Value $value -PropertyType $type -Force | Out-Null
                }
            }
        }
        catch {
            Write-Error "Failed to process key '$fullPath': $_"
        }
    }
}
function Set-UserRegistryKeys {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Table
    )

    # Get all user SIDs from HKEY_USERS except system SIDs
    $userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object {
        $_.PSChildName -notmatch '^(S-1-5-18|S-1-5-19|S-1-5-20|\.DEFAULT)$'
    }

    foreach ($sid in $userSIDs) {
        foreach ($key in $Table.Keys) {
            # Replace the placeholder [USER SID] with the actual user SID
            $userKey = $key -replace '\[USER SID\]', $sid.PSChildName
            $userKey = "Registry::$userKey"  # Ensure we're using the Registry provider

            if (!(Test-Path $userKey)) {
                try {
                    New-Item -Path $userKey -Force | Out-Null
                }
                catch {
                    Write-Error "Failed to create registry key '$userKey': $_"
                    continue
                }
            }

            $values = $Table[$key]
            foreach ($valueName in $values.Keys) {
                $value = $values[$valueName]
                try {
                    $type = if ($value -is [int]) { "DWord" } else { "String" }
                    Set-ItemProperty -Path $userKey -Name $valueName -Value $value -Type $type
                }
                catch {
                    Write-Error "Failed to set value '$valueName' in key '$userKey': $_"
                }
            }
        }
    }
}
Set-RegistryKeys -Table $l1hklm
Set-UserRegistryKeys -Table $l1hku
Write-Host "All Local and User registry settings for level 1 has been applied"