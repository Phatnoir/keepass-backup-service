# Simple internal logging function for startup before modules are loaded
function Write-StartupLog {
    param([string]$Message, [string]$Type = "INIT")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [STARTUP:$Type]: $Message" | Out-File -FilePath $global:logFile -Append # Changed format to match SERVICE
}

function Write-ServiceLog {
    param(
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error', 'Debug')]
        [string]$Type = 'Information',
        [int]$LogLevel = 3
    )
    
    # Skip if message log level is higher than configured log level
    $messageLevel = switch ($Type) {
        'Error' { 1 }
        'Warning' { 2 }
        'Information' { 3 }
        'Debug' { 4 }
        default { 3 }
    }
    
    # Default to configured log level or 3 if not set
    if ($null -eq $global:config -or $null -eq $global:config.LogLevel) {
        $configLogLevel = 3
    } else {
        $configLogLevel = $global:config.LogLevel
    }
    
    if ($messageLevel -gt $configLogLevel) {
        return
    }
    
    # Default log file if not set
    if ([string]::IsNullOrEmpty($global:logFile)) {
        $global:logFile = "C:\Program Files\KeePassBackup\Data\Logs\service.log"
    }
    
    # Ensure log directory exists
    $logDir = Split-Path -Parent $global:logFile
    if (!(Test-Path $logDir)) {
        try {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        } catch {
            # Can't log this error since logging is what's broken!
            # Just continue to attempt file logging
        }
    }
    
    # File logging with timestamp - standardized format
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [SERVICE:$Type]: $Message"
    Add-Content -Path $global:logFile -Value $logMessage -ErrorAction SilentlyContinue
    
    # Event logging (only for non-debug messages)
    if ($Type -ne 'Debug') {
        try {
            # Default service name if not set
            if ([string]::IsNullOrEmpty($global:serviceName)) {
                $global:serviceName = "KeePassBackupService"
            }
            
            # Convert our type to valid EventLogEntryType enum
            $eventLogEntryType = switch ($Type) {
                'Error' { [System.Diagnostics.EventLogEntryType]::Error }
                'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
                'Information' { [System.Diagnostics.EventLogEntryType]::Information }
                default { [System.Diagnostics.EventLogEntryType]::Information }
            }
            
            if ([System.Diagnostics.EventLog]::SourceExists($global:serviceName)) {
                Write-EventLog -LogName "Application" -Source $global:serviceName -EventId 1000 -EntryType $eventLogEntryType -Message $Message -ErrorAction SilentlyContinue
            }
        } catch {
            # If event log fails, at least we have file logging
            Add-Content -Path $global:logFile -Value "Failed to write to Event Log: $($_.Exception.Message)" -ErrorAction SilentlyContinue
        }
    }
}


