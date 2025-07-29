function New-RandomString {
    [CmdletBinding()]
    param(
        [int]$Length = 16, 
        [switch]$IncludeSpecialCharacters
    )
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    if ($IncludeSpecialCharacters) {
        $chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    }
    $randomString = -join ($chars | Get-Random -Count $Length)
    return $randomString
}


function New-ASRepRoastableHoneypotAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OU,
        [Parameter(Mandatory=$true)]
        [string]$AccountName
    )

    $password = (New-RandomString -Length 16 -IncludeSpecialCharacters:$true) # Strong random password

    Write-Host "Attempting to create AS-REP Roaster Honeypot account '$AccountName' in '$OU'..."

    try {
        if (-not (Get-ADOrganizationalUnit -Identity $OU -ErrorAction SilentlyContinue)) {
            Write-Error "The specified OU '$OU' does not exist. Please create it manually before running this function."
            return
        }

        # Create account
        $user = New-ADUser -Name $AccountName `
            -SamAccountName $AccountName `
            -UserPrincipalName "$AccountName@$((Get-ADDomain).NetBIOSName).$((Get-ADDomain).RootDomain.Name)" `
            -DisplayName $displayName `
            -Description $description `
            -Path $OU `
            -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
            -Enabled $true `
            -ChangePasswordAtLogon $false

        # Disable Kerberos pre-authentication
        # Sets the UF_DONT_REQUIRE_PREAUTH (0x00000040) flag.
        Set-ADAccountControl -Identity $AccountName -DoesNotRequirePreAuth $true

        Write-Host "AS-REP Roaster Honeypot account '$AccountName' created successfully in '$OU'." -ForegroundColor Green
        Write-Host "Password for '$AccountName' (for your records - not used for authentication, but for detection): $password" -ForegroundColor Yellow
        Write-Host "MONITORING NOTE: Monitor for Event ID 4768 (Kerberos Authentication Service Ticket Granted) without pre-authentication (Failure Code 0x18 or 0x19) for this account." -ForegroundColor Cyan

    }
    catch {
        Write-Error "Failed to create AS-REP Roaster Honeypot account. Error: $($_.Exception.Message)"
    }
}

function New-KerberoastableHoneypotAccount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OU,
        [Parameter(Mandatory=$true)]
        [string]$AccountName,
        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalName
    )

    $password = (New-RandomString -Length 16 -IncludeSpecialCharacters:$true)
    Write-Host "Attempting to create Kerberoastable Honeypot account '$AccountName' in '$OU' with SPN '$ServicePrincipalName'..."

    try {
        if (-not (Get-ADOrganizationalUnit -Identity $OU -ErrorAction SilentlyContinue)) {
            Write-Error "The specified OU '$OU' does not exist. Please create it manually before running this function."
            return
        }

        # Create the user account (service account)
        $user = New-ADUser -Name $AccountName `
            -SamAccountName $AccountName `
            -UserPrincipalName "$AccountName@$((Get-ADDomain).NetBIOSName).$((Get-ADDomain).RootDomain.Name)" `
            -DisplayName $displayName `
            -Description $description `
            -Path $OU `
            -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) `
            -Enabled $true `
            -ChangePasswordAtLogon $false

        # Set SPN
        Set-ADUser -Identity $AccountName -ServicePrincipalNames @{Add=$ServicePrincipalName} -PassThru | Out-Null
        Write-Host "Kerberoastable Honeypot account '$AccountName' created successfully in '$OU' with SPN '$ServicePrincipalName'." -ForegroundColor Green
        Write-Host "MONITORING NOTE: Monitor for Event ID 4769 (Kerberos Service Ticket Granted) for 'TargetUserName' = '$AccountName'." -ForegroundColor Cyan
        Write-Host "An attacker attempting Kerberoasting will request a service ticket for this SPN, which will appear as a 4769 event." -ForegroundColor Red

    }
    catch {
        Write-Error "Failed to create Kerberoastable Honeypot account. Error: $($_.Exception.Message)"
        # Clean up partially created user if SPN setting failed
        if (Get-ADUser -Identity $AccountName -ErrorAction SilentlyContinue) {
            Write-Warning "Attempting to remove partially created user account '$AccountName'."
            Remove-ADUser -Identity $AccountName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function New-HoneypotUserAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OU,

        [Parameter(Mandatory=$true)]
        [string]$UserName,

        [Parameter(Mandatory=$false)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    # If DisplayName is not provided, use the UserName as the display name.
    if ([string]::IsNullOrEmpty($DisplayName)) {
        $DisplayName = $UserName
    }

    # Initial Validation
    Write-Host "Validating prerequisites..."
    try {
        if (-not (Get-ADOrganizationalUnit -Identity $OU -ErrorAction SilentlyContinue)) {
            Write-Error "The specified OU '$OU' does not exist. Please create it manually before running this function."
            return
        }
        Write-Host "OU '$OU' found." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred while validating the OU. Error: $($_.Exception.Message)"
        return
    }

    # Create user account
    $dn = "CN=$($DisplayName),$($OU)"
    $userObject = $null
    if ($PSCmdlet.ShouldProcess($dn, "Create Honeypot User Account")) {
        try {
            Write-Host "Attempting to create honeypot user account '$UserName'..."
            $userObject = New-ADUser -Name $DisplayName `
                -SamAccountName $UserName `
                -Path $OU `
                -Description $Description `
                -Enabled $true `
                -PasswordNotRequired $true ` # Sets up PasswordNotRequired, to encourage attacker to try to authenticate with it
                -AccountPassword (New-Object System.Security.SecureString) `
                -PassThru # Returns the newly created user object

            Write-Host "Successfully created user account '$UserName'." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create honeypot user account. Error: $($_.Exception.Message)"
            return
        }
    }

    # Apply Restrictive "Deny" permissions at domain Level
    # Deny ACE is applied to the domain root to override default "Authenticated Users" read permissions.
    $domainDN = (Get-ADDomain).DistinguishedName
    if ($PSCmdlet.ShouldProcess($domainDN, "Apply Deny All Permissions ACL for user '$UserName'")) {
        try {
            Write-Host "Applying 'Deny All' permissions for '$UserName' at the domain root..."
            $identity = $userObject.SID

            $acl = Get-Acl -Path "AD:\$($domainDN)"
            $adRights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            # apply to the domain object and everything under it.
            $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $type = [System.Security.AccessControl.AccessControlType]"Deny"
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $inheritance)
            $acl.AddAccessRule($accessRule)
            Set-Acl -Path "AD:\$($domainDN)" -AclObject $acl
            Write-Host "Successfully applied domain-level 'Deny All' permissions." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to apply domain-level 'Deny All' permissions. Error: $_"
            return
        }
    }

    # Configure failure auditing on the user object itself 
    if ($PSCmdlet.ShouldProcess($dn, "Configure Failure Auditing SACL")) {
        try {
            Write-Host "Configuring failure audit for 'Read' and 'Write' properties on the user object..."
            $auditAcl = Get-Acl -Path "AD:\$($dn)" -Audit
            $auditIdentity = [System.Security.Principal.NTAccount]"Everyone"
            $auditFlags = [System.Security.AccessControl.AuditFlags]"Failure"
            $auditInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"

            # Audit rule for failed READ attempts
            $readAuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($auditIdentity, [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty", $auditFlags, $auditInheritance)
            # Audit rule for failed WRITE attempts
            $writeAuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($auditIdentity, [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty", $auditFlags, $auditInheritance)

            $auditAcl.AddAuditRule($readAuditRule)
            $auditAcl.AddAuditRule($writeAuditRule)

            Set-Acl -Path "AD:\$($dn)" -AclObject $auditAcl
            Write-Host "Successfully configured failure auditing on the user object." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to configure auditing. You may need to run PowerShell as an administrator with the appropriate privileges ('Manage auditing and security log'). Error: $_"
            return
        }
    }

    # Final monitoring note
    Write-Host "`n--- HONEYPOT DEPLOYMENT COMPLETE ---" -ForegroundColor Cyan
    Write-Host "USER ACCOUNT: $UserName" -ForegroundColor Cyan
    Write-Host "LOCATION: $OU" -ForegroundColor Cyan
    Write-Host "CONFIGURATION: This account has a 'Deny All' permission set at the domain root." -ForegroundColor Cyan
    Write-Host "MONITORING NOTE:" -ForegroundColor Red
    Write-Host "1. Any authentication event (4624, 4625, 4768) for '$UserName' is a HIGH severity alert." -ForegroundColor Red
    Write-Host "2. Any failed READ or WRITE object access (Event ID 4662) for this user is a CRITICAL severity alert, indicating active reconnaissance." -ForegroundColor Red
}

function New-PreW2K-HoneypotComputerAccount {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OU,

        [Parameter(Mandatory=$true)]
        [string]$MachineName,

        [Parameter(Mandatory=$false)]
        [string]$Description 
    )

    # --- Initial Validation ---
    $MachineName = $MachineName.TrimEnd('$')
    Write-Host "Validating prerequisites..."
    try {
        if (-not (Get-ADOrganizationalUnit -Identity $OU -ErrorAction SilentlyContinue)) {
            Write-Error "The specified OU '$OU' does not exist. Please create it manually before running this function."
            return
        }
        Write-Host "OU '$OU' found." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred during validation. Error: $($_.Exception.Message)"
        return
    }

    # Create computer account and sets its password
    $dn = "CN=$($MachineName),$($OU)"
    $computerObject = $null
    if ($PSCmdlet.ShouldProcess($dn, "Create Honeypot Computer Account")) {
        try {
            Write-Host "Attempting to create honeypot account '$MachineName'..."
            $computerObject = New-ADComputer -Name $MachineName `
                -Path $OU `
                -Description $Description `
                -Enabled $true `
                -PassThru # Return the newly created computer object
            Write-Host "Successfully created computer account '$MachineName'." -ForegroundColor Green

            # Sets the computer account's password to its own name, converted to lowercase.
            Write-Host "Setting password for '$MachineName' to match its name (in lowercase)..."
            $passwordString = $MachineName.ToLower()
            $password = ConvertTo-SecureString -String $passwordString -AsPlainText -Force
            Set-ADAccountPassword -Identity $dn -NewPassword $password -Reset
            Write-Host "Successfully set vulnerable password to '$($passwordString)'." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create or configure honeypot account. Error: $($_.Exception.Message)"
            return
        }
    }

    # Apply restrictive "Deny" permissions at the domain Level
    # Deny ACE is applied to domain root to override the default "Authenticated Users" read permissions.
    $domainDN = (Get-ADDomain).DistinguishedName
    if ($PSCmdlet.ShouldProcess($domainDN, "Apply Deny All Permissions ACL for computer '$MachineName'")) {
        try {
            Write-Host "Applying 'Deny All' permissions for '$MachineName' at the domain root..."
            $identity = $computerObject.SID

            $acl = Get-Acl -Path "AD:\$($domainDN)"
            $adRights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"
            # applies to domain object and everything under it.
            $inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $type = [System.Security.AccessControl.AccessControlType]"Deny"
            $accessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity, $adRights, $type, $inheritance)
            $acl.AddAccessRule($accessRule)
            Set-Acl -Path "AD:\$($domainDN)" -AclObject $acl
            Write-Host "Successfully applied domain-level 'Deny All' permissions." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to apply domain-level 'Deny All' permissions. Error: $_"
            return
        }
    }

    # Configure failure auditing on the computer object itself
    if ($PSCmdlet.ShouldProcess($dn, "Configure Failure Auditing SACL")) {
        try {
            Write-Host "Configuring failure audit for 'Read' and 'Write' properties on the computer object..."
            $auditAcl = Get-Acl -Path "AD:\$($dn)" -Audit
            $auditIdentity = [System.Security.Principal.NTAccount]"Everyone"
            $auditFlags = [System.Security.AccessControl.AuditFlags]"Failure"
            $auditInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $readAuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($auditIdentity, [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty", $auditFlags, $auditInheritance)
            $writeAuditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($auditIdentity, [System.DirectoryServices.ActiveDirectoryRights]"WriteProperty", $auditFlags, $auditInheritance)
            $auditAcl.AddAuditRule($readAuditRule)
            $auditAcl.AddAuditRule($writeAuditRule)
            Set-Acl -Path "AD:\$($dn)" -AclObject $auditAcl
            Write-Host "Successfully configured failure auditing on the computer object." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to configure auditing. You may need to run PowerShell as an administrator with the appropriate privileges ('Manage auditing and security log'). Error: $_"
            return
        }
    }

    # Final monitoring note
    Write-Host "`n--- HONEYPOT DEPLOYMENT COMPLETE ---" -ForegroundColor Cyan
    Write-Host "ACCOUNT: $($MachineName)$" -ForegroundColor Cyan
    Write-Host "LOCATION: $OU" -ForegroundColor Cyan
    Write-Host "CONFIGURATION: Password set to computer name (Pre-W2K compatible style). 'Deny All' set at domain root." -ForegroundColor Cyan
    Write-Host "MONITORING NOTE:" -ForegroundColor Red
    Write-Host "1. Any authentication event (4624, 4625, 4768) for '$($MachineName)$' is a HIGH severity alert." -ForegroundColor Red
    Write-Host "2. Any failed READ or WRITE object access (Event ID 4662) for this account is a CRITICAL severity alert." -ForegroundColor Red
}


function New-HoneyGPPAutologon {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$GpoName,

        [Parameter(Mandatory = $false)]
        [string]$HoneyUsername,

        [Parameter(Mandatory = $false)]
        [string]$HoneyPassword,

        [Parameter(Mandatory = $false)]
        [string]$LinkTarget = (Get-ADDomain).DistinguishedName
    )

    begin {
        # Check for required modules
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            throw "The 'GroupPolicy' PowerShell module is required. Please install it via RSAT."
        }
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "The 'ActiveDirectory' PowerShell module is required. Please install it via RSAT."
        }
        Import-Module GroupPolicy -Force
        Import-Module ActiveDirectory -Force
    }

    process {
        if ($PSCmdlet.ShouldProcess($LinkTarget, "Deploy GPP Autologon Honeypot '$GpoName'")) {
            try {
                if (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue) {
                    Write-Error "A GPO with the name '$GpoName' already exists. Please choose a different name or remove the existing one."
                    return
                }

                Write-Verbose "Creating GPO '$GpoName'..."
                $gpo = New-GPO -Name $GpoName -Comment "HONEYPOT: Contains fake autologon credentials for intrusion detection. Any authentication attempt with these credentials should be treated as a security incident."

                # Registry path for autologon settings. HKLM specifies the Computer Configuration context for the GPO.
                $regKey = 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'

                # Sets GPP registry values. These will be stored in SYSVOL\...\Preferences\Registry\Registry.xml.
                Write-Verbose "Setting GPP registry value 'AutoAdminLogon' to '1'."
                Set-GPRegistryValue -Name $gpo.DisplayName -Key $regKey -ValueName 'AutoAdminLogon' -Value '1' -Type String | Out-Null

                Write-Verbose "Setting GPP registry value 'DefaultUserName' to '$HoneyUsername'."
                Set-GPRegistryValue -Name $gpo.DisplayName -Key $regKey -ValueName 'DefaultUserName' -Value $HoneyUsername -Type String | Out-Null

                Write-Verbose "Setting GPP registry value 'DefaultPassword' to the honeypot password."
                Set-GPRegistryValue -Name $gpo.DisplayName -Key $regKey -ValueName 'DefaultPassword' -Value $HoneyPassword -Type String | Out-Null

                Write-Verbose "Linking GPO '$GpoName' to target '$LinkTarget'."
                New-GPLink -Name $gpo.DisplayName -Target $LinkTarget -ErrorAction Stop | Out-Null

                # Output summary
                $output = [PSCustomObject]@{
                    GpoName                  = $gpo.DisplayName
                    LinkTarget               = $LinkTarget
                    HoneypotUsername         = $HoneyUsername
                    HoneypotPassword         = $HoneyPassword
                    MonitoringRecommendation = "Monitor Domain Controllers for failed logon events (ID 4625) with username '$HoneyUsername'."
                }
                Write-Output $output

            }
            catch {
                Write-Error "An error occurred during GPO creation or configuration: $($_.Exception.Message)"
                # Clean up a partially created GPO if an error occurs after its creation but before linking
                if ($null -ne $gpo) {
                    Write-Warning "Attempting to remove partially created GPO '$($gpo.DisplayName)' due to an error."
                    Remove-GPO -Name $gpo.DisplayName -Confirm:$false
                }
            }
        }
    }
}

function Enable-AllGpoAuditing {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    begin {
        # Check if running as Administrator, which is required to set SACLs.
        $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUser = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
        
        if (-not $currentUser.IsInRole([System.Security.Principal.WindowsBuiltinRole]::Administrator)) {
            throw "This function must be run with elevated administrator privileges to modify audit settings (SACLs)."
        }
        Write-Warning "This function will apply an audit rule to EVERY GPO in the domain. This can generate a large volume of security events. Use -WhatIf to test first."
    }

    process {
        try {
            $allGpos = Get-GPO -All
            $domainName = (Get-ADDomain).DnsRoot
            $policiesPath = "\\$domainName\SYSVOL\$domainName\Policies"

            foreach ($gpo in $allGpos) {
                $gpoFolderPath = Join-Path -Path $policiesPath -ChildPath "\{$($gpo.Id)}"
                
                if ($PSCmdlet.ShouldProcess($gpoFolderPath, "Apply 'Everyone-Read-Success' Audit Rule")) {
                    if (-not (Test-Path -Path $gpoFolderPath -PathType Container)) {
                        Write-Warning "Could not find path for GPO '$($gpo.DisplayName)' at '$gpoFolderPath'. Skipping."
                        continue
                    }

                    # Get the current ACL of the GPO folder
                    $acl = Get-Acl -Path $gpoFolderPath

                    # Define the audit rule
                    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
                        "Everyone",
                        "Read",
                        "ContainerInherit, ObjectInherit",
                        "None",
                        "Success"
                    )

                    # Add the new audit rule to the ACL
                    $acl.AddAuditRule($auditRule)

                    # Apply the updated ACL back to the folder
                    Set-Acl -Path $gpoFolderPath -AclObject $acl
                    Write-Verbose "Successfully applied SACL to GPO '$($gpo.DisplayName)'."
                }
            }
             Write-Host "SUCCESS: Auditing process completed for all GPOs." -ForegroundColor Green
        }
        catch {
            Write-Error "An error occurred while enabling GPO auditing. Error: $($_.Exception.Message)"
        }
    }
}

function New-HoneyGpoAccessTrap {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $false)]
        [string]$GpoName = 'Domain Admins - Password Policy'
    )

    $LinkTarget = (Get-ADDomain).DistinguishedName

    if ($PSCmdlet.ShouldProcess($LinkTarget, "Create GPO Access Honeypot '$GpoName'")) {
        $gpo = $null
        try {
            if (Get-GPO -Name $GpoName -ErrorAction SilentlyContinue) {
                throw "A GPO with the name '$GpoName' already exists. Please choose a different name."
            }

            Write-Verbose "Creating honeypot GPO '$GpoName'..."
            $gpo = New-GPO -Name $GpoName -Comment "HONEYPOT: GPO Access Trap. Any read access to this GPO's files in SYSVOL should be treated as a security incident."

            Write-Verbose "Linking GPO '$GpoName' to target '$LinkTarget'."
            New-GPLink -Name $gpo.DisplayName -Target $LinkTarget | Out-Null
            
            Write-Host "SUCCESS: Honeypot GPO '$($gpo.DisplayName)' created with ID $($gpo.Id)." -ForegroundColor Green
            Write-Host "To enable auditing, you can now use the 'Enable-AllGpoAuditing' function." -ForegroundColor Yellow

        }
        catch {
            Write-Error "Failed to create GPO Access Honeypot. Error: $($_.Exception.Message)"
            if ($null -ne $gpo) {
                Write-Warning "Attempting to clean up partially created GPO '$($gpo.DisplayName)'."
                Remove-GPO -Name $gpo.DisplayName -Confirm:$false
            }
        }
    }
}

