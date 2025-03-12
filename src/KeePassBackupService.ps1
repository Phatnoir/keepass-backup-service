# KeePass Backup Service with BitLocker and USB Support
# Version: 2.1.0
# Date: 2025-03-11

# Load core modules
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$corePath = Join-Path -Path $scriptPath -ChildPath "Core"

# Import core modules by dot-sourcing
. (Join-Path -Path $corePath -ChildPath "Logging.ps1")
. (Join-Path -Path $corePath -ChildPath "BitLocker.ps1")
. (Join-Path -Path $corePath -ChildPath "Backup.ps1")

# Service setup
$serviceName = "KeePassBackupService"
$script:serviceRunning = $true  # Control variable for service loop

# Default configuration - will be overridden if config file exists
$global:config = @{
    SourcePath = "$env:USERPROFILE\OneDrive\KeePass.kdbx"
    LocalBackupPath = "$env:USERPROFILE\Documents\KeePass_Backups"
    EnableUSBBackup = $true
    USBDriveLetter = ""
    USBBackupPath = "KeePass_Backups"
    USBDriveLabel = "BACKUP"
    EnableBitLocker = $true
    BitLockerUSB = $true
    BitLockerKeyPath = "$env:USERPROFILE\Documents\BitLocker_Keys"
    BackupIntervalHours = 24
    RetentionDays = 7
    RetentionWeeks = 4
    RetentionMonths = 6
    LogLevel = 3  # 1=Error, 2=Warning, 3=Info, 4=Debug
}

# Try to load configuration from file
function Load-Configuration {
    param(
        [string]$ConfigPath = $null
    )
    
    try {
        # First, try to use the script directory to find config
        if ([string]::IsNullOrEmpty($ConfigPath)) {
            $scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
            $configDir = Join-Path -Path (Split-Path -Parent -Path $scriptDir) -ChildPath "Config"
            $ConfigPath = Join-Path -Path $configDir -ChildPath "config.json"
        }
        
        if (Test-Path $ConfigPath) {
            Write-Host "Loading configuration from: $ConfigPath"
            $loadedConfig = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            
            # Update our global config with loaded values
            foreach ($prop in $loadedConfig.PSObject.Properties) {
                $global:config[$prop.Name] = $prop.Value
            }
            
            return $true
        }
        else {
            # Fallback to user profile if not found in script directory
            $fallbackPath = "$env:USERPROFILE\KeePassBackup\config.json"
            if (Test-Path $fallbackPath) {
                Write-Host "Loading configuration from fallback location: $fallbackPath"
                $loadedConfig = Get-Content $fallbackPath -Raw | ConvertFrom-Json
                
                # Update our global config with loaded values
                foreach ($prop in $loadedConfig.PSObject.Properties) {
                    $global:config[$prop.Name] = $prop.Value
                }
                
                return $true
            }
        }
    }
    catch {
        # If loading fails, we'll continue with default configuration
        # But we'll log the error once logging is set up
        $script:configError = $_.Exception.Message
    }
    
    return $false
}

# Try to load configuration
$configLoaded = Load-Configuration

# Define path variables from loaded configuration
$source = $global:config.SourcePath
$destination = $global:config.LocalBackupPath

# Adjust logging path to be in the Data directory
$dataDir = Join-Path -Path (Split-Path -Parent (Split-Path -Parent $scriptPath)) -ChildPath "Data"
$logsDir = Join-Path -Path $dataDir -ChildPath "Logs"
$logFile = Join-Path $logsDir "service.log"

# Prepare log directory if it doesn't exist
if (!(Test-Path -Path $logsDir)) {
    $null = New-Item -ItemType Directory -Path $logsDir -Force
}

# Register event source if not exists
if (![System.Diagnostics.EventLog]::SourceExists($serviceName)) {
    try {
        [System.Diagnostics.EventLog]::CreateEventSource($serviceName, "Application")
    }
    catch {
        # Continue even if event source creation fails
        # We'll still have file logging
    }
}

# Log any configuration errors now that logging is setup
if ($script:configError) {
    Write-ServiceLog "Error loading configuration: $script:configError" -Type Warning
    Write-ServiceLog "Using default configuration settings" -Type Warning
}
else {
    if ($configLoaded) {
        Write-ServiceLog "Configuration loaded successfully" -Type Information
    }
    else {
        Write-ServiceLog "No configuration file found, using default settings" -Type Warning
    }
}

# Service control functions
function Start-ServiceWork {
    Write-ServiceLog "KeePass Backup Service starting" -Type Information
    
    while ($script:serviceRunning) {
        try {
            # Check if we should run a backup based on last backup time
            if (Should-RunBackup) {
                # Run the backup
                Backup-KeePassDatabase
            }
            
            # Calculate time until next backup (in seconds)
            $timeout = Get-TimeUntilNextBackup
            
            # If it's 0, we'll do a small wait before checking again
            if ($timeout -le 0) {
                $timeout = 300  # 5 minutes
            }
            
            # Cap the maximum wait time to 8 hours to prevent issues
            if ($timeout -gt 28800) {
                $timeout = 28800  # 8 hours
            }
            
            Write-ServiceLog "Next backup check in $([Math]::Round($timeout/3600, 1)) hours" -Type Information
            
            # Wait for next check or service stop
            $start = Get-Date
            while (((Get-Date) - $start).TotalSeconds -lt $timeout -and $script:serviceRunning) {
                Start-Sleep -Seconds 60  # Check every minute for stop signal
            }
        }
        catch {
            Write-ServiceLog "Critical service error: $($_.Exception.Message)" -Type Error
            # Wait shorter interval on error before retry
            Start-Sleep -Seconds 3600  # 1 hour
        }
    }
    Write-ServiceLog "KeePass Backup Service stopping gracefully" -Type Information
}

# Handle various stop signals
$stopScript = {
    Write-ServiceLog "Stop signal received" -Type Information
    $script:serviceRunning = $false
}

# Register stop signal handlers
try {
    Register-ObjectEvent -InputObject ([System.Console]) -EventName CancelKeyPress -Action $stopScript
    Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PipelineState]::Stopped) -Action $stopScript
} catch {
    Write-Host "Warning: Failed to register event handlers. Service may not stop gracefully." -ForegroundColor Yellow
}

# Start the service work
Start-ServiceWork