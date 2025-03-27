# KeePass Backup Service with BitLocker and USB Support
# Version: 2.1.1
# Date: 2025-03-17

# Configure error handling
$ErrorActionPreference = "Continue"

# Set global variables
$global:serviceName = "KeePassBackupService"
$global:scriptPath = $MyInvocation.MyCommand.Definition
$global:scriptDir = Split-Path -Parent -Path $global:scriptPath
$global:rootDir = Split-Path -Parent -Path $global:scriptDir
$global:dataDir = Join-Path -Path $global:rootDir -ChildPath "Data"
$global:logsDir = Join-Path -Path $global:dataDir -ChildPath "Logs"
$global:logFile = Join-Path $global:logsDir "service.log"
$global:corePath = Join-Path -Path $global:scriptDir -ChildPath "Core"
$global:configDir = Join-Path -Path $global:rootDir -ChildPath "Config"
$global:configPath = Join-Path -Path $global:configDir -ChildPath "config.json"

# Prepare log directory if it doesn't exist
if (!(Test-Path -Path $global:logsDir)) {
    try {
        New-Item -ItemType Directory -Path $global:logsDir -Force | Out-Null
    } catch {
        # Can't log this since logging isn't set up yet
        # Just continue
    }
}

# Simple internal logging function for startup before modules are loaded
function Write-StartupLog {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - [$Type] $Message" | Out-File -FilePath $global:logFile -Append
}

Write-StartupLog "KeePass Backup Service starting..."

# Import core modules by dot-sourcing
Write-StartupLog "Loading core modules..."

try {
    $loggingScriptPath = Join-Path -Path $global:corePath -ChildPath "Logging.ps1"
if (Test-Path $loggingScriptPath) {
    . $loggingScriptPath
    if (Get-Command -Name Write-ServiceLog -ErrorAction SilentlyContinue) {
        Write-ServiceLog "Loaded Logging.ps1" -Type Information
    } else {
        Write-Host "Loaded Logging.ps1"
    }
} else {
    if (Get-Command -Name Write-StartupLog -ErrorAction SilentlyContinue) {
        Write-StartupLog "Logging.ps1 not found at $loggingScriptPath" "ERROR"
    } else {
        Write-Host "ERROR: Logging.ps1 not found at $loggingScriptPath"
    }
}

    Write-StartupLog "Loaded Logging.ps1" "SUCCESS"
} catch {
    Write-StartupLog "Error loading Logging.ps1: $_" "ERROR"
    # Create basic Write-ServiceLog function if module loading failed
    function Write-ServiceLog {
        param([string]$Message, [string]$Type = "Information", [int]$LogLevel = 3)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - [$Type] $Message" | Out-File -FilePath $global:logFile -Append
    }
}

try {
    . (Join-Path -Path $global:corePath -ChildPath "BitLocker.ps1")
    Write-ServiceLog "Loaded BitLocker.ps1" -Type Information
} catch {
    Write-ServiceLog "Error loading BitLocker.ps1: $_" -Type Error
}

try {
    . (Join-Path -Path $global:corePath -ChildPath "Backup.ps1")
    Write-ServiceLog "Loaded Backup.ps1" -Type Information
} catch {
    Write-ServiceLog "Error loading Backup.ps1: $_" -Type Error
}

# Service setup
$script:serviceRunning = $true  # Control variable for service loop

# Default configuration - will be overridden if config file exists
$global:config = @{
    SourcePath = "$env:USERPROFILE\OneDrive\Database.kdbx"
    LocalBackupPath = "$env:USERPROFILE\Documents\Keepass_Backups"
    EnableUSBBackup = $false
    USBDriveLetter = ""
    USBBackupPath = "KeePass_Backups"
    USBDriveLabel = "BACKUP"
    EnableBitLocker = $false
    BitLockerUSB = $false
    BitLockerKeyPath = "$env:USERPROFILE\Documents\BitLocker_Keys"
    BackupIntervalHours = 24
    RetentionDays = 7
    RetentionWeeks = 4
    RetentionMonths = 6
    LogLevel = 3  # 1=Error, 2=Warning, 3=Info, 4=Debug
}

# Try to load configuration from file
function Load-Configuration {
    param([string]$ConfigPath = $global:configPath)
    
    try {
        # Ensure global config is initialized
        if ($null -eq $global:config) {
            $global:config = @{}
        }

        # Check if config file exists
        if (Test-Path $ConfigPath) {
            Write-ServiceLog "Loading configuration from: $ConfigPath" -Type Information
            $loadedConfig = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            
            foreach ($prop in $loadedConfig.PSObject.Properties) {
                $global:config[$prop.Name] = $prop.Value
            }

            Write-ServiceLog "Configuration loaded successfully" -Type Information
            return $true
        }
        
        Write-ServiceLog "No configuration file found at $ConfigPath. Using default settings." -Type Warning
        return $false
    }
    catch {
        Write-ServiceLog "Error loading configuration: $_" -Type Error
        return $false
    }
}


# Try to load configuration
$configLoaded = Load-Configuration
if ($configLoaded) {
    Write-ServiceLog "Configuration loaded successfully" -Type Information
} else {
    Write-ServiceLog "No configuration file found or error loading, using default settings" -Type Warning
}

# Define path variables from loaded configuration
$source = $global:config.SourcePath
$destination = $global:config.LocalBackupPath

# Verify the source file exists
if (!(Test-Path $source)) {
    Write-ServiceLog "WARNING: Source file not found at $source" -Type Warning
} else {
    Write-ServiceLog "Source file verified at $source" -Type Information
}

# Ensure backup directory exists
if (!(Test-Path $destination)) {
    try {
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Write-ServiceLog "Created backup directory: $destination" -Type Information
    } catch {
        Write-ServiceLog "Failed to create backup directory: $_" -Type Error
    }
} else {
    Write-ServiceLog "Backup directory verified at $destination" -Type Information
}

# Service control functions
function Start-ServiceWork {
    Write-ServiceLog "KeePass Backup Service starting" -Type Information
    
    # Initial check on service start
    try {
        if (Test-Path Function:\Should-RunBackup) {
            $shouldRunBackup = Should-RunBackup
            if ($shouldRunBackup) {
                Backup-KeePassDatabase
                Write-ServiceLog "Initial backup completed successfully" -Type Information
            } else {
                Write-ServiceLog "No backup needed on service start - already backed up today" -Type Information
            }
        } else {
            Write-ServiceLog "Should-RunBackup function not available. Check module loading." -Type Error
        }
    } catch {
        Write-ServiceLog "Error checking if backup needed: $_" -Type Error
    }
    
    while ($script:serviceRunning) {
        try {
            $shouldRunBackup = $false
            if (Test-Path Function:\Should-RunBackup) {
                $shouldRunBackup = Should-RunBackup
            }

            if ($shouldRunBackup) {
                $result = Backup-KeePassDatabase
                if ($result) {
                    Write-ServiceLog "Backup completed successfully" -Type Information
                } else {
                    Write-ServiceLog "Backup failed or incomplete" -Type Error
                }
            }
            
            # Adjust timeout based on the result
            if ($shouldRunBackup) {
                # Successful backup → Wait until the next day or interval
                $timeout = 3600 * $global:config.BackupIntervalHours
            } else {
                # No backup needed → Try again in 1 hour
                $timeout = 3600
            }
            
            # Handle failure or error recovery
            if ($null -eq $shouldRunBackup) {
                # If function throws an error or returns unexpected result, retry in 10 minutes
                Write-ServiceLog "Error or undefined result from Should-RunBackup. Retrying in 10 minutes." -Type Warning
                $timeout = 600  # 10 minutes
            }
            
            # Cap the maximum wait time to 8 hours to avoid getting stuck
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
            Write-ServiceLog "Critical service error: $_" -Type Error
            # Shorter retry on failure to reduce downtime
            Start-Sleep -Seconds 600  # 10 minutes
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
    # Check if we're running in interactive mode or as a service
    if ([Environment]::UserInteractive) {
        # Register console events when running in console mode
        Register-ObjectEvent -InputObject ([System.Console]) -EventName CancelKeyPress -Action $stopScript -ErrorAction SilentlyContinue
        Write-ServiceLog "Registered interactive console handlers for graceful shutdown" -Type Information
    } else {
        # Running as a service - no need for console event handlers
        Write-ServiceLog "Running in service mode - console handlers not required" -Type Information
    }
    
    # This event is safe to register in both modes
    Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PipelineState]::Stopped) -Action $stopScript -ErrorAction SilentlyContinue
} catch {
    # Only log as warning if we're in interactive mode where we actually need these handlers
    if ([Environment]::UserInteractive) {
        Write-ServiceLog "Warning: Failed to register event handlers: $_" -Type Warning
    }
}

# Start the service work
Start-ServiceWork

