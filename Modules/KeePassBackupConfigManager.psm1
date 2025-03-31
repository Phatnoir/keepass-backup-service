# KeePass Backup Configuration Management Module

# Updated version with better error handling and documentation



function New-KeePassBackupConfig {

    <#

    .SYNOPSIS

        Creates a new configuration file for the KeePass Backup Service.

    

    .DESCRIPTION

        Creates and saves a configuration file for the KeePass Backup Service with all 

        necessary settings. Will validate paths and create directories if needed.

    

    .PARAMETER SourcePath

        The path to the KeePass database file (.kdbx) to be backed up.

    

    .PARAMETER LocalBackupPath

        The path where local backups will be stored.

    

    .PARAMETER EnableUSBBackup

        Whether USB backup is enabled.

    

    .PARAMETER USBDriveLetter

        The specific USB drive letter to use (e.g., "E"). Leave empty to auto-detect.

    

    .PARAMETER USBBackupPath

        The folder on the USB drive where backups will be stored.

    

    .PARAMETER USBDriveLabel

        The volume label of the USB drive to look for when auto-detecting.

    

    .PARAMETER EnableBitLocker

        Whether BitLocker encryption should be used.

    

    .PARAMETER BitLockerUSB

        Whether to use BitLocker for USB drives.

    

    .PARAMETER BitLockerKeyPath

        The path where BitLocker recovery keys will be stored.

    

    .PARAMETER BackupIntervalHours

        Hours between backups. Default is 24 (daily).

    

    .PARAMETER RetentionDays

        Number of days to keep all backups.

    

    .PARAMETER RetentionWeeks

        Number of weeks to keep weekly backups.

    

    .PARAMETER RetentionMonths

        Number of months to keep monthly backups.

    

    .PARAMETER ConfigPath

        The path where the configuration file will be saved.

    

    .EXAMPLE

        New-KeePassBackupConfig -SourcePath "C:\Users\Me\OneDrive\KeePass.kdbx" -LocalBackupPath "C:\Backups\KeePass"

    #>

    [CmdletBinding()]

    param(

        [Parameter(Mandatory=$true)]

        [ValidateNotNullOrEmpty()]

        [string]$SourcePath,

        

        [Parameter(Mandatory=$true)]

        [ValidateNotNullOrEmpty()]

        [string]$LocalBackupPath,

        

        [switch]$EnableUSBBackup,

        

        [string]$USBDriveLetter = '',

        

        [string]$USBBackupPath = 'KeePass_Backups',

        

        [string]$USBDriveLabel = 'BACKUP',

        

        [switch]$EnableBitLocker,

        

        [switch]$BitLockerUSB,

        

        [string]$BitLockerKeyPath = "$env:USERPROFILE\Documents\BitLocker_Keys",

        

        [double]$BackupIntervalHours = 24,

        

        [int]$RetentionDays = 7,

        

        [int]$RetentionWeeks = 4,

        

        [int]$RetentionMonths = 6,

        

        [string]$ConfigPath = "$env:USERPROFILE\KeePassBackup\config.json",

        

        [switch]$Force

    )



    # Ensure config directory exists

    $configDir = Split-Path -Path $ConfigPath -Parent

    if (!(Test-Path -Path $configDir)) {

        try {

            $null = New-Item -ItemType Directory -Path $configDir -Force

            Write-Verbose "Created configuration directory: $configDir"

        }

        catch {

            throw "Failed to create configuration directory: $_"

        }

    }



    # Validate source path

    if (!(Test-Path -Path $SourcePath)) {

        throw "Source path does not exist: $SourcePath"

    }



    # Create local backup path if it doesn't exist

    if (!(Test-Path -Path $LocalBackupPath)) {

        try {

            $null = New-Item -ItemType Directory -Path $LocalBackupPath -Force

            Write-Verbose "Created local backup directory: $LocalBackupPath"

        }

        catch {

            throw "Failed to create local backup directory: $_"

        }

    }



    # Create BitLocker key path if needed

    if ($EnableBitLocker -and ![string]::IsNullOrWhiteSpace($BitLockerKeyPath) -and !(Test-Path -Path $BitLockerKeyPath)) {

        try {

            $null = New-Item -ItemType Directory -Path $BitLockerKeyPath -Force

            Write-Verbose "Created BitLocker key directory: $BitLockerKeyPath"

        }

        catch {

            throw "Failed to create BitLocker key directory: $_"

        }

    }



    # Check if config file already exists and Force not specified

    if ((Test-Path -Path $ConfigPath) -and !$Force) {

        throw "Configuration file already exists at $ConfigPath. Use -Force to overwrite."

    }



    # Validate USB drive letter if specified

    if (![string]::IsNullOrWhiteSpace($USBDriveLetter)) {

        # Clean up drive letter (remove trailing colon if present)

        $USBDriveLetter = $USBDriveLetter.TrimEnd(':').ToUpper()

        

        # Check if it's a valid drive letter

        if ($USBDriveLetter -notmatch '^[A-Z]$') {

            throw "Invalid USB drive letter. Please specify a single letter (A-Z)."

        }

    }



    # Create configuration object

    $config = @{

        SourcePath = $SourcePath

        LocalBackupPath = $LocalBackupPath

        EnableUSBBackup = $EnableUSBBackup.IsPresent

        USBDriveLetter = $USBDriveLetter

        USBBackupPath = $USBBackupPath

        USBDriveLabel = $USBDriveLabel

        EnableBitLocker = $EnableBitLocker.IsPresent

        BitLockerUSB = $BitLockerUSB.IsPresent

        BitLockerKeyPath = $BitLockerKeyPath

        BackupIntervalHours = $BackupIntervalHours

        RetentionDays = $RetentionDays

        RetentionWeeks = $RetentionWeeks

        RetentionMonths = $RetentionMonths

        LogLevel = 3  # 1=Error, 2=Warning, 3=Info, 4=Debug

    }



    # Convert to JSON and save

    try {

        $configJson = ConvertTo-Json -InputObject $config -Depth 3

        Set-Content -Path $ConfigPath -Value $configJson -Force

        Write-Verbose "Configuration saved to $ConfigPath"

    }

    catch {

        throw "Failed to save configuration: $_"

    }



    # Set secure permissions on config file

    try {

        $acl = Get-Acl -Path $ConfigPath

        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(

            [System.Security.Principal.WindowsIdentity]::GetCurrent().User, 

            [System.Security.AccessControl.FileSystemRights]::FullControl, 

            [System.Security.AccessControl.AccessControlType]::Allow

        )

        $acl.SetAccessRule($rule)

        Set-Acl -Path $ConfigPath -AclObject $acl

    }

    catch {

        Write-Warning "Failed to set permissions on configuration file: $_"

    }



    Write-Host "KeePass Backup configuration created successfully at $ConfigPath"

    return $config

}



function Get-KeePassBackupConfig {

    <#

    .SYNOPSIS

        Gets the KeePass Backup Service configuration.

    

    .DESCRIPTION

        Reads and returns the KeePass Backup Service configuration from the specified file.

        

    .PARAMETER ConfigPath

        The path to the configuration file.

    

    .EXAMPLE

        $config = Get-KeePassBackupConfig

    #>

    [CmdletBinding()]

    param(

        [string]$ConfigPath = "$env:USERPROFILE\KeePassBackup\config.json"

    )



    if (!(Test-Path -Path $ConfigPath)) {

        throw "Configuration file not found at $ConfigPath. Please create a configuration first using New-KeePassBackupConfig."

    }



    try {

        $configJson = Get-Content -Path $ConfigPath -Raw

        $config = ConvertFrom-Json -InputObject $configJson



        # Create a hashtable from the JSON object for easier use

        $configHash = @{}

        foreach ($prop in $config.PSObject.Properties) {

            $configHash[$prop.Name] = $prop.Value

        }



        return $configHash

    }

    catch {

        throw "Failed to read configuration: $_"

    }

}



function Test-KeePassBackupConfig {

    <#

    .SYNOPSIS

        Tests the KeePass Backup Service configuration.

    

    .DESCRIPTION

        Validates that the KeePass Backup Service configuration is correct and all required

        paths exist and are accessible.

    

    .PARAMETER ConfigPath

        The path to the configuration file.

    

    .EXAMPLE

        if (Test-KeePassBackupConfig) { 

            Write-Host "Configuration is valid"

        }

    #>

    [CmdletBinding()]

    param(

        [string]$ConfigPath = "$env:USERPROFILE\KeePassBackup\config.json"

    )



    try {

        # Get configuration

        $config = Get-KeePassBackupConfig -ConfigPath $ConfigPath

        $valid = $true

        

        # Validate required paths

        if (![string]::IsNullOrWhiteSpace($config.SourcePath) -and !(Test-Path -Path $config.SourcePath)) {

            Write-Warning "Source path does not exist: $($config.SourcePath)"

            $valid = $false

        }

        

        if (![string]::IsNullOrWhiteSpace($config.LocalBackupPath) -and !(Test-Path -Path $config.LocalBackupPath)) {

            Write-Warning "Local backup path does not exist: $($config.LocalBackupPath)"

            $valid = $false

        }

        

        # Validate BitLocker path if enabled

        if ($config.EnableBitLocker -and ![string]::IsNullOrWhiteSpace($config.BitLockerKeyPath) -and !(Test-Path -Path $config.BitLockerKeyPath)) {

            Write-Warning "BitLocker key path does not exist: $($config.BitLockerKeyPath)"

            $valid = $false

        }

        

        # Validate USB backup settings

        if ($config.EnableUSBBackup) {

            if ([string]::IsNullOrWhiteSpace($config.USBDriveLetter) -and [string]::IsNullOrWhiteSpace($config.USBDriveLabel)) {

                Write-Warning "USB backup is enabled but neither drive letter nor label is specified"

                $valid = $false

            }

        }

        

        # Validate numeric parameters

        if ($config.BackupIntervalHours -le 0) {

            Write-Warning "Backup interval must be greater than zero"

            $valid = $false

        }

        

        if ($config.RetentionDays -lt 1) {

            Write-Warning "Retention days must be at least 1"

            $valid = $false

        }

        

        return $valid

    }

    catch {

        Write-Warning "Configuration validation failed: $_"

        return $false

    }

}



function Set-KeePassBackupConfig {

    <#

    .SYNOPSIS

        Updates an existing KeePass Backup Service configuration.

    

    .DESCRIPTION

        Updates specified parameters in an existing configuration file.

    

    .PARAMETER ConfigPath

        The path to the configuration file.

    

    .EXAMPLE

        Set-KeePassBackupConfig -BackupIntervalHours 12

    #>

    [CmdletBinding()]

    param(

        [string]$SourcePath,

        [string]$LocalBackupPath,

        [bool]$EnableUSBBackup,

        [string]$USBDriveLetter,

        [string]$USBBackupPath,

        [string]$USBDriveLabel,

        [bool]$EnableBitLocker,

        [bool]$BitLockerUSB,

        [string]$BitLockerKeyPath,

        [double]$BackupIntervalHours,

        [int]$RetentionDays,

        [int]$RetentionWeeks,

        [int]$RetentionMonths,

        [int]$LogLevel,
		
		[bool]$AutoLockAfterBackup,

        [string]$ConfigPath = "$env:USERPROFILE\KeePassBackup\config.json"

    )



    # Check if config exists

    if (!(Test-Path -Path $ConfigPath)) {

        throw "Configuration file not found at $ConfigPath. Please create a configuration first using New-KeePassBackupConfig."

    }



    try {

        # Read existing configuration

        $config = Get-KeePassBackupConfig -ConfigPath $ConfigPath

        

        # Update only the parameters that were passed

        $PSBoundParameters.GetEnumerator() | Where-Object { $_.Key -ne 'ConfigPath' } | ForEach-Object {

            $config[$_.Key] = $_.Value

        }

        

        # Save updated configuration

        $configJson = ConvertTo-Json -InputObject $config -Depth 3

        Set-Content -Path $ConfigPath -Value $configJson -Force

        

        Write-Host "Configuration updated successfully"

        return $config

    }

    catch {

        throw "Failed to update configuration: $_"

    }

}



# Export module functions

Export-ModuleMember -Function New-KeePassBackupConfig, Get-KeePassBackupConfig, Test-KeePassBackupConfig, Set-KeePassBackupConfig