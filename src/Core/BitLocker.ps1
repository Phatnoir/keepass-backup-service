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
            $acl.AddAccessRule($rule)
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
        
        [string]$KeyPath = $(if ($null -ne $global:config -and $null -ne $global:config.BitLockerKeyPath) { 
            $global:config.BitLockerKeyPath 
        } else { 
            "C:\BitLockerKeys" 
        }),
        
        [switch]$AutoLock = $(if ($null -ne $global:config -and $null -ne $global:config.AutoLockAfterBackup) { 
            $global:config.AutoLockAfterBackup 
        } else { 
            $false 
        })
    )
    
    try {
        # Check if drive exists as a volume
        if ($null -eq (Get-Volume -DriveLetter $DriveLetter -ErrorAction SilentlyContinue)) {
            Write-ServiceLog "Drive $DriveLetter does not exist as a mounted volume" -Type Information
            return $false
        }
        
        # Check BitLocker status
        $status = manage-bde.exe -status ${DriveLetter}:
        
        # If BitLocker isn't available on this drive
        if ($LASTEXITCODE -ne 0) {
            Write-ServiceLog "Drive $DriveLetter exists but doesn't appear to be BitLocker-protected" -Type Information
            return $true
        }
        
        # If already unlocked
        if ($status -match "Lock Status\s*:\s*Unlocked") {
            Write-ServiceLog "Drive $DriveLetter is already unlocked" -Type Information
            return $true
        }
        
        Write-ServiceLog "Drive $DriveLetter is locked. Attempting to unlock..." -Type Information
        
        # Try with recovery password files (multiple formats)
        $passwordFiles = @(
            (Join-Path $KeyPath "RecoveryPassword_$DriveLetter.txt"),
            (Join-Path $KeyPath "$DriveLetter`_password.txt"),
            (Join-Path $KeyPath "BitLocker_$DriveLetter.txt"),
            (Join-Path $KeyPath "BitLocker_${DriveLetter}_password.txt")
        )
        
        # Try to find and use a valid recovery password
        foreach ($passwordFile in $passwordFiles) {
            if (Test-Path $passwordFile) {
                $recoveryPassword = (Get-Content $passwordFile -Raw).Trim()
                
                # Validate it's a recovery password (48 digits with or without hyphens)
                $passwordNoHyphens = $recoveryPassword -replace '-', ''
                if ($passwordNoHyphens -match '^\d{48}$') {
                    # Format password with hyphens if needed
                    if ($recoveryPassword -notmatch '-') {
                        $formatted = ""
                        for ($i = 0; $i -lt $recoveryPassword.Length; $i += 6) {
                            if ($i -gt 0) { $formatted += "-" }
                            $formatted += $recoveryPassword.Substring($i, [Math]::Min(6, $recoveryPassword.Length - $i))
                        }
                        $recoveryPassword = $formatted
                    }
                    
                    # Attempt unlock with manage-bde
                    manage-bde.exe -unlock ${DriveLetter}: -rp $recoveryPassword
                    
                    # Verify unlock (with retry)
                    for ($i = 0; $i -lt 3; $i++) {
                        $status = manage-bde.exe -status ${DriveLetter}:
                        if ($status -match "Lock Status\s*:\s*Unlocked") {
                            Write-ServiceLog "Successfully unlocked drive $DriveLetter with recovery password" -Type Information
                            
                            # Register for auto-lock if enabled
                            if ($AutoLock) {
                                if ($null -eq $global:drivesToLock) { $global:drivesToLock = @() }
                                if ($global:drivesToLock -notcontains $DriveLetter) {
                                    $global:drivesToLock += $DriveLetter
                                    Write-ServiceLog "Drive $DriveLetter registered for auto-locking after backup" -Type Information
                                }
                            }
                            
                            return $true
                        }
                        Start-Sleep -Seconds 2
                    }
                }
            }
        }
        
        # Try with .bek key files as fallback
        $keyFiles = Get-ChildItem -Path $KeyPath -Filter "RecoveryKey_${DriveLetter}_*.bek" -ErrorAction SilentlyContinue
        
        if ($keyFiles) {
            # Try each key, starting with the newest
            foreach ($keyFile in ($keyFiles | Sort-Object CreationTime -Descending)) {
                Write-ServiceLog "Attempting to unlock with key: $($keyFile.Name)" -Type Information
                manage-bde.exe -unlock ${DriveLetter}: -recoverykey $keyFile.FullName
                
                # Verify unlock
                $status = manage-bde.exe -status ${DriveLetter}:
                if ($status -match "Lock Status\s*:\s*Unlocked") {
                    Write-ServiceLog "Successfully unlocked drive $DriveLetter with key file" -Type Information
                    
                    # Register for auto-lock if enabled
                    if ($AutoLock) {
                        if ($null -eq $global:drivesToLock) { $global:drivesToLock = @() }
                        if ($global:drivesToLock -notcontains $DriveLetter) {
                            $global:drivesToLock += $DriveLetter
                            Write-ServiceLog "Drive $DriveLetter registered for auto-locking after backup" -Type Information
                        }
                    }
                    
                    return $true
                }
            }
        }
        
        Write-ServiceLog "Failed to unlock drive $DriveLetter with any available recovery method" -Type Error
        return $false
    }
    catch {
        Write-ServiceLog "Error unlocking BitLocker drive: $_" -Type Error
        return $false
    }
}

function Lock-BitLockerDrive {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter
    )
    
    try {
        # Check if drive is BitLocker-protected and unlocked
        $status = manage-bde.exe -status ${DriveLetter}:
        if ($LASTEXITCODE -ne 0) {
            Write-ServiceLog "Drive $DriveLetter is not accessible or not BitLocker-protected" -Type Warning
            return $false
        }
        
        # Check if it's already locked
        if ($status -match "Lock Status\s*:\s*Locked") {
            Write-ServiceLog "Drive $DriveLetter is already locked" -Type Information
            return $true
        }
        
        # Lock the drive
        Write-ServiceLog "Locking drive $DriveLetter" -Type Information
        $result = manage-bde.exe -lock ${DriveLetter}:
        
        # Verify lock was successful
        $status = manage-bde.exe -status ${DriveLetter}:
        if ($status -match "Lock Status\s*:\s*Locked") {
            Write-ServiceLog "Successfully locked drive $DriveLetter" -Type Information
            return $true
        } else {
            Write-ServiceLog "Failed to lock drive $DriveLetter" -Type Warning
            return $false
        }
    }
    catch {
        Write-ServiceLog "Error locking BitLocker drive: $_" -Type Error
        return $false
    }
}

# Function to lock all drives that were unlocked during backup
function Lock-AllUnlockedDrives {
    if ($null -ne $global:drivesToLock -and $global:drivesToLock.Count -gt 0) {
        Write-ServiceLog "Auto-locking $($global:drivesToLock.Count) drive(s) that were unlocked during backup" -Type Information
        
        foreach ($drive in $global:drivesToLock) {
            $lockResult = Lock-BitLockerDrive -DriveLetter $drive
            if ($lockResult) {
                Write-ServiceLog "Successfully locked drive $drive" -Type Information
            } else {
                Write-ServiceLog "Failed to lock drive $drive" -Type Warning
            }
        }
        
        # Clear the list after locking
        $global:drivesToLock = @()
    }
}