# KeePass Backup Service - BitLocker Module
# Contains functions for BitLocker operations

# BitLocker functions
function Get-BitLockerRecoveryKey {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter,
        
        [string]$KeyPath = $(if ($null -ne $global:config -and $null -ne $global:config.BitLockerKeyPath) { $global:config.BitLockerKeyPath } else { "C:\BitLockerKeys" })
    )
    
    try {
        # Ensure key directory exists
        if (!(Test-Path $KeyPath)) {
            $null = New-Item -ItemType Directory -Path $KeyPath -Force
            Write-ServiceLog "Created BitLocker key directory: $KeyPath" -Type Information
        }
        
        # Generate unique filename
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $keyFileName = "RecoveryKey_${DriveLetter}_${timestamp}.bek"
        $keyFullPath = Join-Path $KeyPath $keyFileName
        
        # Generate recovery key
        Write-ServiceLog "Generating BitLocker recovery key for drive $DriveLetter" -Type Information
        $null = manage-bde.exe -protectors -add ${DriveLetter}: -recoverykey $keyFullPath
        
        # Verify key was created
        if (Test-Path $keyFullPath) {
            Write-ServiceLog "BitLocker recovery key created successfully at $keyFullPath" -Type Information
            
            # Set secure permissions
            $acl = Get-Acl $keyFullPath
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                [System.Security.Principal.WindowsIdentity]::GetCurrent().User, 
                [System.Security.AccessControl.FileSystemRights]::FullControl, 
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($rule) # <- Changed from SetAccessRule to AddAccessRule
            $acl | Set-Acl $keyFullPath
            
            return $keyFullPath
        }
        else {
            Write-ServiceLog "Failed to create BitLocker recovery key" -Type Error
            return $null
        }
    }
    catch {
        Write-ServiceLog "Error creating BitLocker recovery key: $_" -Type Error
        return $null
    }
}

function Test-OneDriveSyncStatus {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        if ($FilePath -like "*OneDrive*") {
            Write-ServiceLog "Detecting OneDrive file: $FilePath" -Type Information
            
            # Don't rely solely on the OneDrive process - check if file is accessible
            if (Test-Path $FilePath) {
                Write-ServiceLog "OneDrive file is accessible: $FilePath" -Type Information
                return $true
            } else {
                Write-ServiceLog "OneDrive file is not accessible: $FilePath" -Type Error
                return $false
            }
        }
        
        # Not an OneDrive file, so no sync issues
        return $true
    }
    catch {
        Write-ServiceLog "Error checking OneDrive sync status: $_" -Type Error
        # Continue with backup attempt anyway
        return $true
    }
}

function Unlock-BitLockerDrive {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter,
        
        [string]$KeyPath = $(if ($null -ne $global:config -and $null -ne $global:config.BitLockerKeyPath) { $global:config.BitLockerKeyPath } else { "C:\BitLockerKeys" })
    )
    
    try {
        # Validate parameters
        Write-ServiceLog "Attempting to unlock BitLocker drive $DriveLetter using keys from $KeyPath" -Type Debug
        
        # Ensure BitLocker service is running
        $bdeService = Get-Service -Name 'BDESVC' -ErrorAction SilentlyContinue
        if ($null -eq $bdeService) {
            Write-ServiceLog "BitLocker Drive Encryption Service (BDESVC) not found" -Type Error
            return $false
        }
        
        if ($bdeService.Status -ne 'Running') {
            try {
                Start-Service -Name 'BDESVC' -ErrorAction Stop
                Write-ServiceLog "Started BitLocker Drive Encryption Service (BDESVC)" -Type Information
            } catch {
                Write-ServiceLog "Failed to start BitLocker service: $_" -Type Error
                return $false
            }
        }
        
        # Ensure manage-bde.exe is available
        if ($null -eq (Get-Command manage-bde.exe -ErrorAction SilentlyContinue)) {
            Write-ServiceLog "manage-bde.exe not found. Ensure BitLocker is installed." -Type Error
            return $false
        }
        
        # Check if drive exists
        if (-not (Test-Path -Path "${DriveLetter}:\" -ErrorAction SilentlyContinue)) {
            Write-ServiceLog "Drive ${DriveLetter}: not found or not accessible" -Type Error
            return $false
        }
        
        # Check if drive is BitLocker-protected
        $status = manage-bde.exe -status ${DriveLetter}:
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -ne 0) {
            Write-ServiceLog "Failed to get BitLocker status for drive $DriveLetter. Exit code: $exitCode" -Type Error
            return $false
        }
        
        # Check for BitLocker protection status - using more forgiving regex
        if ($status -match "(?im)\s*Protection\s*:\s*Off") {
            Write-ServiceLog "Drive $DriveLetter is not BitLocker-protected" -Type Information
            return $true
        }
        
        # Check if already unlocked - using more forgiving regex
        if ($status -match "(?im)\s*Lock\s*Status\s*:\s*Unlocked") {
            Write-ServiceLog "Drive $DriveLetter is already unlocked" -Type Information
            return $true
        }
        
        # First try with recovery password file
        $passwordFile = Join-Path $KeyPath "RecoveryPassword_$DriveLetter.txt"
        if (Test-Path $passwordFile -ErrorAction SilentlyContinue) {
            try {
                $recoveryPassword = Get-Content $passwordFile -Raw -ErrorAction Stop
                $recoveryPassword = $recoveryPassword.Trim()
                
                # Validate recovery password format (remove hyphens for validation)
                $cleanPassword = $recoveryPassword -replace "-", ""
                if ([string]::IsNullOrWhiteSpace($recoveryPassword)) {
                    Write-ServiceLog "Recovery password file exists but is empty" -Type Warning
                }
                elseif ($cleanPassword -notmatch '^\d{48}$' -and $cleanPassword -notmatch '^\d{8}-\d{8}-\d{8}-\d{8}-\d{8}-\d{8}$') {
                    Write-ServiceLog "Invalid recovery password format in file $passwordFile" -Type Warning
                }
                else {
                    Write-ServiceLog "Attempting to unlock drive $DriveLetter with recovery password from file" -Type Information
                    $result = manage-bde.exe -unlock ${DriveLetter}: -rp $recoveryPassword
                    $exitCode = $LASTEXITCODE
                    
                    if ($exitCode -ne 0) {
                        Write-ServiceLog "manage-bde.exe failed with exit code $exitCode when using recovery password" -Type Warning
                    }
                    
                    # Verify if unlock was successful
                    Start-Sleep -Milliseconds 500  # Brief pause to allow system to update status
                    $status = manage-bde.exe -status ${DriveLetter}:
                    
                    if ($status -match "(?im)\s*Lock\s*Status\s*:\s*Unlocked") {
                        Write-ServiceLog "Successfully unlocked drive $DriveLetter with recovery password" -Type Information
                        return $true
                    } else {
                        Write-ServiceLog "Failed to unlock with recovery password from file: $($result -join ' ')" -Type Warning
                    }
                }
            } catch {
                Write-ServiceLog "Error reading recovery password file: $_" -Type Error
            }
        } else {
            Write-ServiceLog "No recovery password file found at $passwordFile" -Type Debug
        }
        
        # As a fallback, try with .bek files
        try {
            $keyFiles = Get-ChildItem -Path $KeyPath -Filter "RecoveryKey_${DriveLetter}_*.bek" -ErrorAction SilentlyContinue
            
            if ($null -eq $keyFiles -or $keyFiles.Count -eq 0) {
                Write-ServiceLog "No .bek recovery key files found for drive $DriveLetter" -Type Warning
                return $false
            }
            
            Write-ServiceLog "Found $($keyFiles.Count) .bek key files to try" -Type Debug
            
            # Try each key, starting with the newest
            $successfulUnlock = $false
            foreach ($keyFile in ($keyFiles | Sort-Object CreationTime -Descending)) {
                Write-ServiceLog "Attempting to unlock drive $DriveLetter with key file: $($keyFile.Name)" -Type Debug
                
                if (-not (Test-Path $keyFile.FullName -ErrorAction SilentlyContinue)) {
                    Write-ServiceLog "Key file no longer exists: $($keyFile.FullName)" -Type Warning
                    continue
                }
                
                $result = manage-bde.exe -unlock ${DriveLetter}: -recoverykey $keyFile.FullName
                $exitCode = $LASTEXITCODE
                
                if ($exitCode -ne 0) {
                    Write-ServiceLog "manage-bde.exe failed with exit code $exitCode for key file $($keyFile.Name)" -Type Warning
                    continue
                }
                
                # Verify if unlock was successful
                Start-Sleep -Milliseconds 500  # Brief pause
                $status = manage-bde.exe -status ${DriveLetter}:
                
                if ($status -match "(?im)\s*Lock\s*Status\s*:\s*Unlocked") {
                    Write-ServiceLog "Successfully unlocked drive $DriveLetter with key file $($keyFile.Name)" -Type Information
                    $successfulUnlock = $true
                    break
                }
                
                Write-ServiceLog "Key file $($keyFile.Name) did not unlock the drive" -Type Debug
            }
            
            if ($successfulUnlock) {
                return $true
            }
        } catch {
            Write-ServiceLog "Error processing .bek recovery key files: $_" -Type Error
        }
        
        Write-ServiceLog "Failed to unlock drive $DriveLetter with any available recovery method" -Type Error
        return $false
    }
    catch {
        Write-ServiceLog "Error unlocking BitLocker drive: $_" -Type Error
        return $false
    }
}


# Export functions for use in main script
# Claude removal: Export-ModuleMember -Function Get-BitLockerRecoveryKey, Unlock-BitLockerDrive, Test-OneDriveSyncStatus