bl= @{
    "HKLM\SOFTWARE\Policies\Microsoft\FVE" = @{
        "FDVDiscoveryVolumeType" = ""
        "fdvrecovery" = 1
        "fdvmanagedra" = 1
        "fdvrecoverypassword" = 2
        "fdvrecoverykey" = 2
        "fdvhiderecoverypage" = 1
        "fdvhardwareencryption" = 0
        "fdvpassphrase" = 0
        "fdvallowusercert" = 1
        "fdvenforceusercert" = 1
        "useenhancedpin" = 1
        "osallowsecurebootforintegrity" = 1
        "osrecovery" = 1
        "osmanagedra" = 0
        "osrecoverypassword" = 1
        "osrecoverykey" = 0
        "oshiderecoverypage" = 1
        "oshardwareencryption" = 0
        "ospassphrase" = 0
        "useadvancedstartup" = 1
        "enablebdewithnotpm" = 0
        "RDVDiscoveryVolumeType" = ""
        "rdvrecovery" = 1
        "rdvmanagedra" = 1
        "rdvrecoverypassword" = 0
        "rdvrecoverykey" = 0
        "rdvhiderecoverypage" = 1
        "rdvhardwareencryption" = 0
        "rdvpassphrase" = 0
        "rdvallowusercert" = 1
        "rdvenforceusercert" = 1
        "rdvdenycrossorg" = 0
        "disableexternaldmaunderlock" = 1 
        }
    
    "hklm\system\currentcontrolset\policies\microsoft\fve" = @{
        "rdvdenywriteaccess" = 1
    }

    "hklm\software\policies\microsoft\power\powersettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" = @{
        "dcsettingindex" = 0
        "acsettingindex" = 0
    }

    "hklm\software\policies\microsoft\windows\deviceinstall\restrictions" = @{
        "denydeviceclasses" = 1
        "denydeviceclassesretroactive" = 1
    }

    "hklm\software\microsoft\windows\currentversion\policies\system" = @{
        "maxdevicepasswordfailedattempts" = 10
    }

    "hklm\software\policies\microsoft\windows\deviceinstall\restrictions\denydeviceclasses" = @{
        "{d48179be-ec20-11d1-b6b8-00c04fa372a7},{7ebefbc0-3200-11d2-b4c2-00a0c9697d07},{c06ff265-ae09-48f0-812c-16753d7cba83},{6bdd1fc1-810f-11d0-bec7-08002be2092f}"
    }

    "hklm\software\policies\microsoft\windows\kernel dma protection" = @{
        "deviceenumerationpolicy" = 0
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
Set-RegistryKeys -Table $bl
Write-Host "All BitLocker registry settings applied"