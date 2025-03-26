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
            
            # Check if the OneDrive process is running
            $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue
            
            if ($null -eq $oneDriveProcess) {
                Write-ServiceLog "OneDrive is not running. Sync status unknown." -Type Warning
                return $true # Continue anyway
            }
            
            # Check file attributes to see if it's available locally
            $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
            
            if ($null -eq $fileInfo) {
                Write-ServiceLog "File not found or not synced: $FilePath" -Type Error
                return $false
            }
            
            # Check if file is marked as "online-only"
            if ($fileInfo) {
                $fileAttributes = $fileInfo.Attributes
                $isOnlineOnly = $fileAttributes.HasFlag([System.IO.FileAttributes]::NotContentIndexed) -and 
                                $fileAttributes.HasFlag([System.IO.FileAttributes]::Offline)
            
                if ($isOnlineOnly) {
                    Write-ServiceLog "File is in 'online-only' state, trying to sync: $FilePath" -Type Warning
                
                    # Try to access the file to trigger sync
                    $fileContent = Get-Content $FilePath -TotalCount 1 -ErrorAction SilentlyContinue
                    
                    # Re-check attributes after accessing the file
                    $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
                    if ($fileInfo) {
                        $fileAttributes = $fileInfo.Attributes
                        $isStillOnlineOnly = $fileAttributes.HasFlag([System.IO.FileAttributes]::NotContentIndexed) -and 
                                             $fileAttributes.HasFlag([System.IO.FileAttributes]::Offline)
                
                        if ($isStillOnlineOnly) {
                            Write-ServiceLog "Unable to sync OneDrive file: $FilePath" -Type Error
                            return $false
                        }
                    }
                }
            }
            
            Write-ServiceLog "OneDrive file is available: $FilePath" -Type Information
            return $true
        }
        
        return $true
    }
    catch {
        Write-ServiceLog "Error checking OneDrive sync status: $_" -Type Error
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
        $status = & manage-bde.exe -status ${DriveLetter}:
        if ($status -match "(?i)Protection\s*:\s*Off") {
            Write-ServiceLog "Drive $DriveLetter is not BitLocker-protected" -Type Information
            return $true
        }
        
        if ($status -match "(?i)Lock Status\s*:\s*Unlocked") {
            Write-ServiceLog "Drive $DriveLetter is already unlocked" -Type Information
            return $true
        }
        
        # Try each key
        $keyFiles = Get-ChildItem -Path $KeyPath -Filter "RecoveryKey_${DriveLetter}_*.bek" -ErrorAction SilentlyContinue
        
        foreach ($keyFile in ($keyFiles | Sort-Object CreationTime -Descending)) {
            Write-ServiceLog "Attempting to unlock drive $DriveLetter with key: $($keyFile.Name)" -Type Debug
            $result = & manage-bde.exe -unlock ${DriveLetter}: -recoverykey $keyFile.FullName
            
            if ($?) {
                Write-ServiceLog "Successfully unlocked drive $DriveLetter" -Type Information
                return $true
            }
        }
        
        Write-ServiceLog "Failed to unlock drive $DriveLetter" -Type Error
        return $false
    }
    catch {
        Write-ServiceLog "Error unlocking BitLocker drive: $_" -Type Error
        return $false
    }
}


# Export functions for use in main script
# Claude removal: Export-ModuleMember -Function Get-BitLockerRecoveryKey, Unlock-BitLockerDrive, Test-OneDriveSyncStatus