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

            

            # Check if the OneDrive process is running

            $oneDriveProcess = Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue

            

            if ($null -eq $oneDriveProcess) {

                Write-ServiceLog "OneDrive is not running. Sync status unknown." -Type Warning

                return $true # Continue anyway

            }

# Function to check if backup should run based on last backup time

function Should-RunBackup {

    try {

        # Check if we have any existing backups - using CreationTime now

        Write-ServiceLog "Scanning for backup files in $destination" -Type Debug

        $backupFiles = Get-ChildItem -Path $destination -Filter "Database_Backup_*.kdbx" -ErrorAction SilentlyContinue

        

        # Log all found backup files for debugging

        Write-ServiceLog "Found $($backupFiles.Count) backup files in $destination" -Type Debug

        

        # Additional debugging for all files

        foreach ($file in $backupFiles | Sort-Object CreationTime -Descending | Select-Object -First 3) {

            Write-ServiceLog "DEBUG: File $($file.Name) - Created: $($file.CreationTime) - Modified: $($file.LastWriteTime)" -Type Debug

        }

# Calculate time until next backup

function Get-TimeUntilNextBackup {

    try {

        $lastBackup = Get-ChildItem -Path $destination -Filter "Database_Backup_*.kdbx" -ErrorAction SilentlyContinue | 

                     Sort-Object CreationTime -Descending | 

                     Select-Object -First 1

        

        if ($null -eq $lastBackup) {

            return 0  # Run immediately if no backups found

        }

# Find USB drive

function Find-USBDrive {

    try {

        # If drive letter is explicitly specified, use it

        if (-not [string]::IsNullOrWhiteSpace($global:config.USBDriveLetter)) {

            $driveLetter = $global:config.USBDriveLetter.Trim(':').ToUpper()

            if (Test-Path "${driveLetter}

# Full backup function

function Backup-KeePassDatabase {

	# Check if source is a OneDrive file and ensure it's synced

	$isSynced = Test-OneDriveSyncStatus -FilePath $source

	if (-not $isSynced) {

		Write-ServiceLog "Source file is not available or not synced: $source" -Type Error

		return

	}

# Export functions for use in main script
Export-ModuleMember -Function Test-OneDriveSyncStatus, Should-RunBackup, Get-TimeUntilNextBackup, Find-USBDrive, Backup-KeePassDatabase
