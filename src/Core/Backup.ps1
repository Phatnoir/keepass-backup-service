# KeePass Backup Service - Backup Module
# Extracted from KeePassBackupService.ps1
# Contains functions for backup operations

# Add this function to check if OneDrive is synced before backup
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

# Function to check if backup should run based on last backup time
# Function to check if backup should run based on last backup time
function Should-RunBackup {
    param(
        [string]$Destination = $global:config.LocalBackupPath
    )
    try {
        # Check if destination is provided or use the one from global config
        if ([string]::IsNullOrEmpty($Destination) -and $null -ne $global:config) {
            $Destination = $global:config.LocalBackupPath
        }
        
        # Validate we have a destination
        if ([string]::IsNullOrEmpty($Destination)) {
            Write-ServiceLog "No backup destination specified" -Type Error
            return $true  # Default to running backup if we can't determine
        }
        
        # Check if we have any existing backups
        Write-ServiceLog "Scanning for backup files in $Destination" -Type Debug
        $backupFiles = Get-ChildItem -Path $Destination -Filter "Database_Backup_*.kdbx" -ErrorAction SilentlyContinue
        
        # Log all found backup files for debugging
        Write-ServiceLog "Found $($backupFiles.Count) backup files in $Destination" -Type Debug
        
        # If no backups exist, we should run
        if ($null -eq $backupFiles -or $backupFiles.Count -eq 0) {
            Write-ServiceLog "No existing backups found, running initial backup" -Type Information
            return $true
        }
        
        # Get the newest backup file (guard against null values)
        $lastBackup = $backupFiles | Sort-Object CreationTime -Descending | Select-Object -First 1
        
        if ($null -eq $lastBackup) {
            Write-ServiceLog "No valid backup files found, running initial backup" -Type Warning
            return $true
        }
        
        # Calculate time since last backup (in hours)
        $timeSinceBackup = (Get-Date) - $lastBackup.CreationTime
        $hoursSinceBackup = $timeSinceBackup.TotalHours
        
        # Use configured interval or default to 24 hours
        $backupInterval = $global:config.BackupIntervalHours
        if ($null -eq $backupInterval) {
            $backupInterval = 24
        }
        
        # Check if enough time has passed since last backup
        $shouldRun = $hoursSinceBackup -ge $backupInterval
        
        if ($shouldRun) {
            Write-ServiceLog ("Last backup was {0:N1} hours ago, running backup now based on {1:N1} hour interval" -f [math]::Round($hoursSinceBackup, 1), [math]::Round($backupInterval, 1)) -Type Information
            return $true
        } else {
            $hoursRemaining = $backupInterval - $hoursSinceBackup
            Write-ServiceLog ("Last backup was {0:N1} hours ago, next backup in {1:N1} hours" -f [math]::Round($hoursSinceBackup, 1), [math]::Round($hoursRemaining, 1)) -Type Debug
            return $false
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-ServiceLog "Permission error checking backup schedule: $_" -Type Error
        return $true  # Better to run backup than fail silently
    }
    catch [System.IO.IOException] {
        Write-ServiceLog "File I/O error checking backup schedule: $_" -Type Error
        return $true
    }
    catch {
        Write-ServiceLog "Unexpected error checking backup schedule: $_" -Type Error
        return $true
    }
}



# Calculate time until next backup
function Get-TimeUntilNextBackup {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Destination
    )
    
    try {
        $backupFiles = Get-ChildItem -Path $Destination -Filter "Database_Backup_*.kdbx" -ErrorAction SilentlyContinue | 
                       Sort-Object CreationTime -Descending | 
                       Select-Object -First 1
        
        if ($null -eq $backupFiles) {
            Write-ServiceLog "No backup files found. Running backup immediately." -Type Information
            return 0  # Run immediately if no backups found
        }
        
        $lastBackup = $backupFiles
        
        # Calculate time since last backup
        $timeSinceBackup = (Get-Date) - $lastBackup.CreationTime
        $hoursSinceBackup = $timeSinceBackup.TotalHours
        
        # Get the configured interval
        $backupInterval = $global:config.BackupIntervalHours
        if ($null -eq $backupInterval) {
            Write-ServiceLog "BackupIntervalHours not defined. Using default interval of 24 hours." -Type Warning
            $backupInterval = 24
        }
        
        # Calculate time until next backup
        $timeUntilNextBackup = ($backupInterval - $hoursSinceBackup) * 3600  # Convert to seconds
        
        if ($timeUntilNextBackup -le 0) {
            Write-ServiceLog ("Backup is overdue by {0:N1} hours. Running immediately." -f [math]::Round(-$timeUntilNextBackup / 3600, 1)) -Type Warning
            return 0  # Run immediately if overdue
        }
        
        Write-ServiceLog ("Next backup scheduled in {0:N1} hours." -f [math]::Round($timeUntilNextBackup / 3600, 1)) -Type Information
        
        return [math]::Round($timeUntilNextBackup) # Round to nearest second
    }
    catch [System.UnauthorizedAccessException] {
        Write-ServiceLog "Permission error calculating next backup time: $_" -Type Error
        return 3600  # Retry in 1 hour
    }
    catch [System.IO.IOException] {
        Write-ServiceLog "File I/O error calculating next backup time: $_" -Type Error
        return 3600  # Retry in 1 hour
    }
    catch {
        Write-ServiceLog "Unexpected error calculating next backup time: $_" -Type Error
        return 3600  # Default to 1 hour in case of error
    }
}



# Find USB drive
function Find-USBDrive {
    try {
        # If drive letter is explicitly specified, use it
        if (-not [string]::IsNullOrWhiteSpace($global:config.USBDriveLetter)) {
            $driveLetter = $global:config.USBDriveLetter.Trim(':').ToUpper()
            
            # Check if drive exists as a volume even if not accessible
            $volumeExists = Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue
            
            if ($null -ne $volumeExists) {
                # If BitLocker is enabled, try to unlock the drive
                if ($global:config.EnableBitLocker -and $global:config.BitLockerUSB) {
                    $unlocked = Unlock-BitLockerDrive -DriveLetter $driveLetter
                    
                    if ($unlocked) {
                        Write-ServiceLog "Successfully unlocked BitLocker drive $driveLetter" -Type Information
                        return $driveLetter
                    } 
                    else {
                        Write-ServiceLog "Failed to unlock BitLocker drive $driveLetter" -Type Warning
                        return $null
                    }
                } 
                elseif (Test-Path "${driveLetter}:") {
                    return $driveLetter
                }
                else {
                    # Drive exists as volume but isn't accessible and we couldn't unlock it
                    Write-ServiceLog "Drive $driveLetter exists but isn't accessible" -Type Warning
                    return $null
                }
            }
            else {
                Write-ServiceLog "Specified USB drive $driveLetter not found" -Type Warning
                return $null
            }
        }
        
        # Otherwise, look for drive by label
        $drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 }  # 2 = Removable disk
        
        foreach ($drive in $drives) {
            if (-not [string]::IsNullOrWhiteSpace($global:config.USBDriveLabel)) {
                if ($drive.VolumeName -eq $global:config.USBDriveLabel) {
                    Write-ServiceLog "Found USB drive $($drive.DeviceID) with label $($drive.VolumeName)" -Type Information
                    
                    # Get just the drive letter without colon
                    $foundDriveLetter = $drive.DeviceID.Replace(':', '')
                    
                    # If BitLocker is enabled, try to unlock the drive
                    if ($global:config.EnableBitLocker -and $global:config.BitLockerUSB) {
                        $unlocked = Unlock-BitLockerDrive -DriveLetter $foundDriveLetter
                        
                        if ($unlocked) {
                            Write-ServiceLog "Successfully unlocked BitLocker drive $foundDriveLetter" -Type Information
                            return $foundDriveLetter
                        }
                        else {
                            Write-ServiceLog "Failed to unlock BitLocker drive $foundDriveLetter" -Type Warning
                            return $null
                        }
                    }
                    
                    return $foundDriveLetter
                }
            }
            else {
                # If no label specified, use first USB drive found
                Write-ServiceLog "Found USB drive $($drive.DeviceID)" -Type Information
                
                # Get just the drive letter without colon
                $foundDriveLetter = $drive.DeviceID.Replace(':', '')
                
                # If BitLocker is enabled, try to unlock the drive
                if ($global:config.EnableBitLocker -and $global:config.BitLockerUSB) {
                    $unlocked = Unlock-BitLockerDrive -DriveLetter $foundDriveLetter
                    
                    if ($unlocked) {
                        Write-ServiceLog "Successfully unlocked BitLocker drive $foundDriveLetter" -Type Information
                        return $foundDriveLetter
                    }
                    else {
                        Write-ServiceLog "Failed to unlock BitLocker drive $foundDriveLetter" -Type Warning
                        return $null
                    }
                }
                
                return $foundDriveLetter
            }
        }
        
        Write-ServiceLog "No matching USB drive found" -Type Warning
        return $null
    }
    catch {
        Write-ServiceLog "Error finding USB drive: $($_.Exception.Message)" -Type Error
        return $null
    }
}

function Apply-RetentionPolicy {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        [string]$FileFilter = "Database_Backup_*.kdbx"
    )
    
    try {
        # Get all backup files
        $allBackups = Get-ChildItem -Path $BackupPath -Filter $FileFilter | 
                     Sort-Object CreationTime
        
        Write-ServiceLog "Applying retention policy to $BackupPath. Found $($allBackups.Count) backups." -Type Debug
        
        # Keep all backups within retention days
        $retentionDate = (Get-Date).AddDays(-$global:config.RetentionDays)
        $oldBackups = $allBackups | Where-Object { $_.CreationTime -lt $retentionDate }
        
	# Apply retention policy logic
	if ($oldBackups.Count -gt 0) {
		foreach ($backup in $oldBackups) {
			$creation = $backup.CreationTime
			$keepWeekly = $false
			$keepMonthly = $false

			# Retain one backup per week
			for ($i = 1; $i -le $global:config.RetentionWeeks; $i++) {
				$startOfWeek = (Get-Date).Date.AddDays(-7 * $i)
				$endOfWeek = $startOfWeek.AddDays(7)
				$sameWeek = $allBackups | Where-Object {
					$_.CreationTime -ge $startOfWeek -and $_.CreationTime -lt $endOfWeek
				} | Sort-Object CreationTime | Select-Object -First 1
				if ($sameWeek.FullName -eq $backup.FullName) {
					$keepWeekly = $true
					break
				}
			}

			# Retain one backup per month
			for ($i = 1; $i -le $global:config.RetentionMonths; $i++) {
				$target = (Get-Date).AddMonths(-$i)
				$month = $target.Month
				$year = $target.Year
				$sameMonth = $allBackups | Where-Object {
					$_.CreationTime.Month -eq $month -and $_.CreationTime.Year -eq $year
				} | Sort-Object CreationTime | Select-Object -First 1
				if ($sameMonth.FullName -eq $backup.FullName) {
					$keepMonthly = $true
					break
				}
			}

        if (-not ($keepWeekly -or $keepMonthly)) {
            Remove-Item $backup.FullName -Force
            Write-ServiceLog "Removed old backup: $($backup.Name)" -Type Debug
        }
    }
}

        
        return $true
    }
    catch {
        Write-ServiceLog ("Error applying retention policy to {0}: {1}" -f $BackupPath, $_.Exception.Message) -Type Error
        return $false
    }
}

# Full backup function
function Backup-KeePassDatabase {
    # Check if source is a OneDrive file and ensure it's synced
    $isSynced = Test-OneDriveSyncStatus -FilePath $source
    if (-not $isSynced) {
        Write-ServiceLog "Source file is not available or not synced: $source" -Type Error
        return
    }
    
    # Generate backup filename with timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $backupFileName = "Database_Backup_${timestamp}.kdbx"
    $localBackupPath = Join-Path $destination $backupFileName
    
    # Ensure destination directory exists
    if (!(Test-Path $destination)) {
        try {
            $null = New-Item -ItemType Directory -Path $destination -Force
            Write-ServiceLog "Created backup directory: $destination" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create backup directory: $_" -Type Error
            return
        }
    }
    
    # Perform local backup
    try {
        Copy-Item -Path $source -Destination $localBackupPath -Force
        Write-ServiceLog "Local backup created successfully: $localBackupPath" -Type Information
    }
    catch {
        Write-ServiceLog "Failed to create local backup: $_" -Type Error
        return
    }
    
    # Check if USB backup is enabled
    if ($global:config.EnableUSBBackup) {
        # Find USB drive
        $usbDrive = Find-USBDrive
        
        if ($null -ne $usbDrive) {
            $usbBackupDir = "$usbDrive`:\$($global:config.USBBackupPath)"
            
            # Check if BitLocker is enabled and unlock drive if needed
            if ($global:config.EnableBitLocker -and $global:config.BitLockerUSB) {
                $unlocked = Unlock-BitLockerDrive -DriveLetter $usbDrive
                if (-not $unlocked) {
                    Write-ServiceLog "Could not unlock USB drive $usbDrive for backup" -Type Error
                    return
                }
            }
            
            # Ensure USB backup directory exists
            if (!(Test-Path $usbBackupDir)) {
                try {
                    $null = New-Item -ItemType Directory -Path $usbBackupDir -Force
                    Write-ServiceLog "Created USB backup directory: $usbBackupDir" -Type Information
                }
                catch {
                    Write-ServiceLog "Failed to create USB backup directory: $_" -Type Error
                    return
                }
            }
            
            # Perform USB backup
            try {
                $usbBackupPath = Join-Path $usbBackupDir $backupFileName
                Copy-Item -Path $source -Destination $usbBackupPath -Force
                Write-ServiceLog "USB backup created successfully: $usbBackupPath" -Type Information
            }
            catch {
                Write-ServiceLog "Failed to create USB backup: $_" -Type Error
            }
        }
        else {
            Write-ServiceLog "USB drive not found for backup. This is normal if no USB drive is connected." -Type Information
        }
    }
    
# Apply retention policy for local backups
	Apply-RetentionPolicy -BackupPath $destination

	# Apply retention policy for USB backups if enabled
	if ($global:config.EnableUSBBackup -and 
		($global:config.EnableUSBPrune -eq $true) -and 
		($null -ne $usbBackupDir) -and 
		(Test-Path $usbBackupDir)) {
    
		Write-ServiceLog "Applying retention policy to USB backups at $usbBackupDir" -Type Information
		Apply-RetentionPolicy -BackupPath $usbBackupDir
	}

	# Lock any drives that were unlocked during this backup
	if (Test-Path Function:\Lock-AllUnlockedDrives) {
		Lock-AllUnlockedDrives
	}

	Write-ServiceLog "Backup completed successfully" -Type Information

}
# Export functions for use in main script
# Module export commented out to prevent errors when dot-sourcing

