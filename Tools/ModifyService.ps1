# This script securely modifies the Unlock-BitLockerDrive function in KeePassBackupService.ps1
# to use a recovery password from a secure location instead of .bek files

param(
    [Parameter(Mandatory=$true)]
    [string]$ScriptPath,
    
    [Parameter(Mandatory=$false)]
    [string]$RecoveryKeyPath = "$env:USERPROFILE\Documents\BitLocker_Keys"
)

# Input validation
if (!(Test-Path $ScriptPath)) {
    Write-Host "ERROR: Script not found at: $ScriptPath" -ForegroundColor Red
    exit 1
}

# Backup the original script
$backupPath = "$ScriptPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
Copy-Item -Path $ScriptPath -Destination $backupPath -Force
Write-Host "Original script backed up to: $backupPath" -ForegroundColor Green

# Read the script content
$content = Get-Content -Path $ScriptPath -Raw

# Define the new function - using secure key retrieval instead of hardcoded passwords
$newFunction = @'
function Unlock-BitLockerDrive {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriveLetter,
        
        [string]$KeyPath = $global:config.BitLockerKeyPath
    )
    
    try {
        # Check if drive is BitLocker-protected
        $status = manage-bde.exe -status ${DriveLetter}:
        if ($status -match "Protection\s*:\s*Off") {
            Write-ServiceLog "Drive $DriveLetter is not BitLocker-protected" -Type Information
            return $true
        }
        
        if ($status -match "Lock Status\s*:\s*Unlocked") {
            Write-ServiceLog "Drive $DriveLetter is already unlocked" -Type Information
            return $true
        }
        
        # First try with recovery password file
        $passwordFile = Join-Path $KeyPath "RecoveryPassword_$DriveLetter.txt"
        if (Test-Path $passwordFile) {
            $recoveryPassword = Get-Content $passwordFile -Raw
            $recoveryPassword = $recoveryPassword.Trim()
            
            Write-ServiceLog "Attempting to unlock drive $DriveLetter with recovery password" -Type Information
            $result = manage-bde.exe -unlock ${DriveLetter}: -rp $recoveryPassword
            
            # Check if unlock was successful
            $status = manage-bde.exe -status ${DriveLetter}:
            if ($status -match "Lock Status\s*:\s*Unlocked") {
                Write-ServiceLog "Successfully unlocked drive $DriveLetter with recovery password" -Type Information
                return $true
            }
        }
        
        # As a last resort, try with .bek files
        $keyFiles = Get-ChildItem -Path $KeyPath -Filter "RecoveryKey_${DriveLetter}_*.bek" -ErrorAction SilentlyContinue
        
        if ($null -eq $keyFiles -or $keyFiles.Count -eq 0) {
            Write-ServiceLog "No recovery keys found for drive $DriveLetter" -Type Warning
            return $false
        }
        
        # Try each key, starting with the newest
        foreach ($keyFile in ($keyFiles | Sort-Object CreationTime -Descending)) {
            Write-ServiceLog "Attempting to unlock drive $DriveLetter with key: $($keyFile.Name)" -Type Debug
            $result = manage-bde.exe -unlock ${DriveLetter}: -recoverykey $keyFile.FullName
            
            # Check if unlock was successful
            if ($LASTEXITCODE -eq 0 -or $result -match "successfully unlocked") {
                Write-ServiceLog "Successfully unlocked drive $DriveLetter" -Type Information
                return $true
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
'@

# Replace the function in the content
$pattern = "function Unlock-BitLockerDrive \{[\s\S]*?\n\}"
if ($content -match $pattern) {
    $content = $content -replace $pattern, $newFunction
    
    # Save the modified script
    Set-Content -Path $ScriptPath -Value $content -Force
    Write-Host "Script successfully modified with secure BitLocker recovery approach" -ForegroundColor Green
} else {
    Write-Host "WARNING: Could not find Unlock-BitLockerDrive function in the script" -ForegroundColor Yellow
}

# Create recovery key path if it doesn't exist
if (!(Test-Path $RecoveryKeyPath)) {
    try {
        New-Item -ItemType Directory -Path $RecoveryKeyPath -Force | Out-Null
        Write-Host "Created recovery key directory: $RecoveryKeyPath" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to create recovery key directory: $_" -ForegroundColor Red
    }
}

Write-Host "IMPORTANT: For each BitLocker-protected drive you want to use,"
Write-Host "create a text file named 'RecoveryPassword_X.txt' (where X is the drive letter)"
Write-Host "in $RecoveryKeyPath containing just the recovery password." -ForegroundColor Yellow