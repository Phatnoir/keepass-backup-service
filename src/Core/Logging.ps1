# KeePass Backup Service - Logging Module
# Contains functions for logging operations

function Write-ServiceLog {
    param(
        [string]$Message,
        
        [ValidateSet('Information', 'Warning', 'Error', 'Debug')]
        [string]$Type = 'Information',
        
        [int]$LogLevel = 3  # Default to Info
    )
    
    # Skip if message log level is higher than configured log level
    $messageLevel = switch ($Type) {
        'Error' { 1 }
        'Warning' { 2 }
        'Information' { 3 }
        'Debug' { 4 }
        default { 3 }
    }
    
    if ($messageLevel -gt $global:config.LogLevel) {
        return
    }
    
    # File logging with timestamp
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Type]: $Message"
    Add-Content -Path $logFile -Value $logMessage -ErrorAction SilentlyContinue
    
    # Event logging (only for non-debug messages)
    if ($Type -ne 'Debug') {
        try {
            # Convert our type to valid EventLogEntryType enum
            $eventLogEntryType = switch ($Type) {
                'Error' { [System.Diagnostics.EventLogEntryType]::Error }
                'Warning' { [System.Diagnostics.EventLogEntryType]::Warning }
                'Information' { [System.Diagnostics.EventLogEntryType]::Information }
                default { [System.Diagnostics.EventLogEntryType]::Information }
            }
            
            Write-EventLog -LogName "Application" -Source $serviceName -EventId 1000 -EntryType $eventLogEntryType -Message $Message -ErrorAction SilentlyContinue
        }
        catch {
            # If event log fails, at least we have file logging
            Add-Content -Path $logFile -Value "Failed to write to Event Log: $($_.Exception.Message)" -ErrorAction SilentlyContinue
        }
    }
}

# Export function for use in main script
# Note: This line should be removed if not using as a module
# Export-ModuleMember -Function Write-ServiceLog