# Secure-Install-KeePassBackupService.ps1
# Enhanced secure installation script with credential prompting and improved security

param(
    [Parameter(Mandatory=$false)]
    [string]$InstallBase = (Get-Location).Path,  # Default to current directory
    
    [Parameter(Mandatory=$false)]
    [string]$ScriptPath = $null,  # Will be computed based on InstallBase if null
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = $null,  # Will be computed based on InstallBase if null
    
    [Parameter(Mandatory=$false)]
    [string]$ServiceName = "KeePassBackupService",
    
    [Parameter(Mandatory=$false)]
    [string]$DisplayName = "KeePass Backup Service",
    
    [Parameter(Mandatory=$false)]
    [string]$Description = "Automated backup service for KeePass database with BitLocker and USB support",
    
    [Parameter(Mandatory=$false)]
    [string]$NSSMPath = "C:\Program Files\nssm\nssm.exe",
    
    [Parameter(Mandatory=$false)]
    [switch]$UseLocalSystem,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoPrompt,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

if ([string]::IsNullOrEmpty($ScriptPath)) {
    # Go up one level from installer directory to root, then into src
    $rootDir = Split-Path -Parent -Path $InstallBase
    $srcDir = Join-Path -Path $rootDir -ChildPath "src"
    $ScriptPath = Join-Path -Path $srcDir -ChildPath "KeePassBackupService.ps1"
}

if ([string]::IsNullOrEmpty($ConfigPath)) {
    $rootDir = Split-Path -Parent -Path $InstallBase
    $configDir = Join-Path -Path $rootDir -ChildPath "Config"
    $ConfigPath = Join-Path -Path $configDir -ChildPath "config.json"
}

Write-Host "InstallBase: $InstallBase"
Write-Host "ScriptPath: $ScriptPath"
Write-Host "ConfigPath: $ConfigPath"


#region Functions

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-InstallLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Type = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Color selection with dictionary for more consistent handling
    $colors = @{
        'Info'    = 'White'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
    }
    $foregroundColor = $colors[$Type]
    
    # Console output with color
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Cyan
    Write-Host "[$Type] " -NoNewline -ForegroundColor $foregroundColor
    Write-Host "$Message" -ForegroundColor $foregroundColor
    
    # Also log to file
    $logDir = "$env:TEMP\KeePassBackup"
    if (!(Test-Path $logDir)) {
        $null = New-Item -ItemType Directory -Path $logDir -Force
    }
    
    $logFile = "$logDir\Install_$(Get-Date -Format 'yyyyMMdd').log"
    "[$timestamp] [$Type] $Message" | Out-File -FilePath $logFile -Append
}

function Get-SecureCredential {
    param(
        [string]$Username = "$env:USERDOMAIN\$env:USERNAME"
    )
    
    $title = "KeePass Backup Service Credentials"
    $message = "Enter the credentials for the service account:"
    
    if ($NoPrompt) {
        if ($null -eq $Credential) {
            Write-InstallLog "No credentials provided with -NoPrompt. Using LocalSystem account." -Type Warning
            return $null
        }
        return $Credential
    }
    
    # Prompt for credentials if not using LocalSystem
    if (!$UseLocalSystem) {
        $cred = $Host.UI.PromptForCredential($title, $message, $Username, "")
        
        if ($null -eq $cred) {
            Write-InstallLog "No credentials provided. Using LocalSystem account." -Type Warning
            return $null
        }
        
        return $cred
    }
    
    return $null
}

function Set-SecureServicePassword {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName,
        
        [Parameter(Mandatory=$true)]
        [string]$NSSMPath,
        
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    $BSTR = $null
    try {
        # Use SecureString methods to access the password
        Write-InstallLog "Setting service credentials securely..." -Type Info
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        # Escape special characters in password to handle ALL problematic characters
        $escapedPassword = ($plainPassword.ToCharArray() | ForEach-Object { 
            if ('&|^<>()@!%"' -contains $_) { "`$_" } else { $_ } 
        }) -join ''
        
        # Also escape the username to handle special characters
        $escapedUsername = ($Credential.UserName.ToCharArray() | ForEach-Object { 
            if ('&|^<>()@!%"' -contains $_) { "`$_" } else { $_ } 
        }) -join ''
        
        # Set the service account with both escaped username and password
        & $NSSMPath set $ServiceName ObjectName "$escapedUsername" "$escapedPassword"
        $result = $LASTEXITCODE
        
        # Clear sensitive data immediately
        $plainPassword = $null
        $escapedPassword = $null
        $escapedUsername = $null
        
        return ($result -eq 0)
    }
    catch {
        Write-InstallLog "Error setting service credentials: $_" -Type Error
        return $false
    }
    finally {
        # Ensure cleanup happens even if an error occurs
        if ($null -ne $BSTR) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        }
        
        # Clear variables
        if (Get-Variable -Name plainPassword -ErrorAction SilentlyContinue) {
            $plainPassword = $null
        }
        
        if (Get-Variable -Name escapedPassword -ErrorAction SilentlyContinue) {
            $escapedPassword = $null
        }
        
        if (Get-Variable -Name escapedUsername -ErrorAction SilentlyContinue) {
            $escapedUsername = $null
        }
    }
}

#endregion

#region Main Script

# Set execution policy for the current process
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force -ErrorAction Stop
} catch {
    # Only log if not a duplicate message about execution policy change
    if ($_.Exception.Message -notmatch "execution policy change") {
        Write-InstallLog "Failed to set execution policy: $_" -Type Warning
        Write-InstallLog "This is normal if not running as administrator or if policy is restricted." -Type Warning
    }
}

# Ensure running as administrator
if (-not (Test-Administrator)) {
    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error
    Exit 1
}

Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info
Write-InstallLog "Installation base: $InstallBase" -Type Info
Write-InstallLog "Script Path: $ScriptPath" -Type Info
Write-InstallLog "Config Path: $ConfigPath" -Type Info

# Verify NSSM exists
if (-not (Test-Path $NSSMPath)) {
    Write-InstallLog "NSSM not found at $NSSMPath." -Type Error
    
    # Try to find NSSM in common locations
    $nssmPaths = @(
        "C:\Program Files\nssm\nssm.exe",
        "C:\Program Files (x86)\nssm\nssm.exe",
        "C:\Windows\System32\nssm.exe",
        "C:\tools\nssm\nssm.exe"
    )
    
    foreach ($path in $nssmPaths) {
        if (Test-Path $path) {
            $NSSMPath = $path
            Write-InstallLog "Found NSSM at: $NSSMPath" -Type Success
            break
        }
    }
    
    if (-not (Test-Path $NSSMPath)) {
        Write-InstallLog "NSSM not found. Would you like to download it? (Y/N)" -Type Warning
        
        $response = "N"  # Default to No
        if (!$NoPrompt) {
            $response = Read-Host
        }
        
        if ($response -eq "Y" -or $response -eq "y") {
            try {
                # Create temp directory
                $tempDir = Join-Path $env:TEMP "nssm_download"
                if (Test-Path $tempDir) {
                    Remove-Item -Path $tempDir -Force -Recurse -ErrorAction SilentlyContinue
                }
                New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
                
                # Download NSSM
                $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
                $zipFile = Join-Path $tempDir "nssm.zip"
                
                Write-InstallLog "Downloading NSSM from $nssmUrl..." -Type Info
                Invoke-WebRequest -Uri $nssmUrl -OutFile $zipFile
                
                # Extract the ZIP
                Write-InstallLog "Extracting NSSM..." -Type Info
                Expand-Archive -Path $zipFile -DestinationPath $tempDir -Force
                
                # Find the right executable based on architecture
                $nssmDir = Get-ChildItem -Path $tempDir -Filter "nssm-*" -Directory | Select-Object -First 1
                $nssmWin64 = Join-Path $nssmDir.FullName "win64\nssm.exe"
                $nssmWin32 = Join-Path $nssmDir.FullName "win32\nssm.exe"
                
                if (Test-Path $nssmWin64) {
                    $nssmExe = $nssmWin64
                }
                else {
                    $nssmExe = $nssmWin32
                }
                
                # Create the directory if not exists
                $nssmInstallDir = "C:\Program Files\nssm"
                if (!(Test-Path $nssmInstallDir)) {
                    New-Item -ItemType Directory -Path $nssmInstallDir -Force | Out-Null
                }
                
                # Copy to the program files
                $NSSMPath = Join-Path $nssmInstallDir "nssm.exe"
                Copy-Item -Path $nssmExe -Destination $NSSMPath -Force
                
                # Verify copy with improved retry logic and exponential backoff
                $retries = 3
                $delay = 1
                $success = $false
                
                while ($retries -gt 0 -and -not $success) {
                    if (Test-Path $NSSMPath) {
                        $success = $true
                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success
                    }
                    else {
                        $retries--
                        if ($retries -gt 0) {
                            Write-InstallLog "NSSM installation check failed. Retrying ($retries attempts left)..." -Type Warning
                            Start-Sleep -Seconds $delay
                            # Double the delay each time (exponential backoff)
                            $delay *= 2
                        }
                    }
                }
                
                if (-not $success) {
                    Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error
                    # Clean up temp directory
                    Remove-Item -Path $tempDir -Force -Recurse -ErrorAction SilentlyContinue
                    # Also clean up any partial installation
                    Remove-Item -Path $nssmInstallDir -Force -Recurse -ErrorAction SilentlyContinue
                    Exit 1
                }
                
                # Clean up temp directory
                Remove-Item -Path $tempDir -Force -Recurse -ErrorAction SilentlyContinue
            }
            catch {
                # Add more detailed error information based on the type of exception
                if ($_.Exception.GetType().Name -eq "WebException" -and $null -ne $_.Exception.Response) {
                    Write-InstallLog "Error downloading NSSM. Status code: $($_.Exception.Response.StatusCode) - $($_.Exception.Response.StatusDescription)" -Type Error
                } else {
                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error
                }
                
                Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error
                
                # Clean up temp directory
                if (Test-Path $tempDir) {
                    Remove-Item -Path $tempDir -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
                }
                
                # Also clean up any partial installation
                if (Test-Path $nssmInstallDir) {
                    Remove-Item -Path $nssmInstallDir -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue
                }
                
                Exit 1
            }
        }
        else {
            Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error
            Exit 1
        }
    }
}

# Verify script exists
if (-not (Test-Path $ScriptPath)) {
    Write-InstallLog "KeePassBackupService.ps1 script not found at $ScriptPath" -Type Error
    
    # Prompt to choose location
    if (!$NoPrompt) {
        Write-InstallLog "Would you like to specify the location? (Y/N)" -Type Warning
        $response = Read-Host
        
        if ($response -eq "Y" -or $response -eq "y") {
            $scriptDir = Split-Path -Parent $ScriptPath
            
            # Create the directory if it doesn't exist
            if (!(Test-Path $scriptDir)) {
                try {
                    New-Item -ItemType Directory -Path $scriptDir -Force | Out-Null
                    Write-InstallLog "Created directory: $scriptDir" -Type Success
                }
                catch {
                    Write-InstallLog "Failed to create directory: $_" -Type Error
                    Exit 1
                }
            }
            
            # Create or copy the script
            Write-InstallLog "Select the KeePassBackupService.ps1 file to install:" -Type Info
            
            # Load Windows forms for file dialog - with proper error handling
            try {
                # Check if already loaded
                if (-not ([System.Type]::GetType("System.Windows.Forms.OpenFileDialog"))) {
                    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
                }
                
                $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"
                $openFileDialog.Title = "Select KeePassBackupService.ps1"
                
                if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                    Copy-Item -LiteralPath $openFileDialog.FileName -Destination $ScriptPath -Force
                    Write-InstallLog "Copied script to $ScriptPath" -Type Success
                }
                else {
                    Write-InstallLog "Script selection canceled. Installation aborted." -Type Error
                    Exit 1
                }
            }
            catch {
                Write-InstallLog "Error showing file dialog: $_" -Type Error
                Write-InstallLog "Please manually copy your KeePassBackupService.ps1 file to $ScriptPath" -Type Error
                Exit 1
            }
        }
        else {
            Write-InstallLog "Script is required for installation. Installation aborted." -Type Error
            Exit 1
        }
    }
    else {
        Write-InstallLog "Script is required for installation. Installation aborted." -Type Error
        Exit 1
    }
}

# 1. Check for and stop existing service
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-InstallLog "Stopping existing service..." -Type Warning
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    
    Write-InstallLog "Removing existing service..." -Type Warning
    & $NSSMPath remove $ServiceName confirm
    Start-Sleep -Seconds 2
}

# 2. Create event log source with improved error handling and timeout
Write-InstallLog "Registering event log source..." -Type Info
try {
    # First check if the source already exists to avoid unnecessary operations
    if ([System.Diagnostics.EventLog]::SourceExists($ServiceName)) {
        Write-InstallLog "Event log source already exists." -Type Info
    } else {
        $eventLogTimeout = 5
        $startTime = Get-Date
        
        while (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {
            if ((New-TimeSpan -Start $startTime).TotalSeconds -ge $eventLogTimeout) {
                Write-InstallLog "Timeout while creating event log source." -Type Warning
                break
            }
            
            try {
                [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")
                Write-InstallLog "Event log source created successfully." -Type Success
                break
            }
            catch {
                # If we get a specific error about the source existing, break out
                if ($_.Exception.Message -match "already exists") {
                    Write-InstallLog "Event log source already exists." -Type Info
                    break
                }
                Start-Sleep -Seconds 1
            }
        }
    }
} 
catch [System.Security.SecurityException] {
    Write-InstallLog "Permission denied for event log source creation." -Type Warning
    Write-InstallLog "This is not critical and the service may still run properly." -Type Warning
}
catch {
    Write-InstallLog "Event log source creation failed: $_" -Type Warning
    Write-InstallLog "This is not critical and the service may still run properly." -Type Warning
}

# 3. Get service credentials
$serviceCred = Get-SecureCredential

# 4. Install the service with NSSM
Write-InstallLog "Installing service using NSSM..." -Type Info
$scriptDirectory = Split-Path -Parent $ScriptPath

# Create logs directory in the Data folder
$dataDir = Join-Path (Split-Path -Parent $scriptDirectory) "Data"
# Define proper log directory
$rootDir = Split-Path -Parent -Path $scriptDirectory
$dataDir = Join-Path -Path $rootDir -ChildPath "Data" 
$logsDir = Join-Path -Path $dataDir -ChildPath "Logs"

# Create it if it doesn't exist
if (-not (Test-Path -Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}

# Install the service
& "$NSSMPath" install $ServiceName "powershell.exe"

# Configure service parameters
& "$NSSMPath" set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"`"`"$ScriptPath`"`"`""
& "$NSSMPath" set $ServiceName DisplayName "$DisplayName"
& "$NSSMPath" set $ServiceName Description "$Description"
& "$NSSMPath" set $ServiceName AppDirectory "$scriptDirectory"
& "$NSSMPath" set $ServiceName AppStdout "$logsDir\nssm_stdout.log"
& "$NSSMPath" set $ServiceName AppStderr "$logsDir\nssm_stderr.log"

# Set service account with retry logic for more resilience
if ($serviceCred) {
    $retries = 3
    $delay = 1
    $success = $false
    
    while ($retries -gt 0 -and -not $success) {
        $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred
        
        if ($success) {
            Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success
            break
        }
        else {
            $retries--
            if ($retries -gt 0) {
                Write-InstallLog "Failed to set service credentials. Retrying... ($retries attempts left)" -Type Warning
                Start-Sleep -Seconds $delay
                # Double the delay each time (exponential backoff)
                $delay *= 2
            }
        }
    }
    
    if (-not $success) {
        Write-InstallLog "Failed to set service credentials (NSSM exit code: $LASTEXITCODE). Falling back to LocalSystem account." -Type Warning
        & $NSSMPath set $ServiceName ObjectName "LocalSystem"
    }
    
    # Explicitly remove credentials from memory
    $serviceCred = $null
}
else {
    # Use LocalSystem account
    & $NSSMPath set $ServiceName ObjectName "LocalSystem"
    Write-InstallLog "Service configured to run as LocalSystem" -Type Info
}

# Configure service startup
& $NSSMPath set $ServiceName Start SERVICE_AUTO_START
& $NSSMPath set $ServiceName AppNoConsole 1
& $NSSMPath set $ServiceName AppStopMethodSkip 0
& $NSSMPath set $ServiceName AppStopMethodConsole 1500
& $NSSMPath set $ServiceName AppStopMethodWindow 1500
& $NSSMPath set $ServiceName AppStopMethodThreads 1500

# 5. Set service failure actions
Write-InstallLog "Configuring service failure actions..." -Type Info
& $NSSMPath reset $ServiceName AppExit
& $NSSMPath set $ServiceName AppRestartDelay 60000  # 60 seconds
& $NSSMPath set $ServiceName AppThrottle 60000      # 60 seconds

# 6. Give the script file explicit permissions with better error handling
Write-InstallLog "Setting file permissions..." -Type Info
try {
    $acl = Get-Acl -LiteralPath $ScriptPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl -Path $ScriptPath -AclObject $acl -ErrorAction Stop
    
    # If service account is not LocalSystem, give it permissions too
    if ($null -ne $Credential -and $Credential.UserName -ne "LocalSystem") {
        $acl = Get-Acl -LiteralPath $ScriptPath
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Credential.UserName, "FullControl", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $ScriptPath -AclObject $acl -ErrorAction Stop
    }
} catch {
    Write-InstallLog "Warning: Failed to set permissions on script file: $_" -Type Warning
    Write-InstallLog "The service may still run if the account has sufficient permissions." -Type Warning
}

# 7. Create configuration directory if it doesn't exist
$configDir = Split-Path -Parent $ConfigPath
if (!(Test-Path $configDir)) {
    try {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
        Write-InstallLog "Created configuration directory: $configDir" -Type Info
    } catch {
        Write-InstallLog "Failed to create configuration directory: $_" -Type Warning
    }
}

# 8. Create configuration if it doesn't exist, with improved security for sensitive parameters
if (!(Test-Path $ConfigPath) -and !$NoPrompt) {
    Write-InstallLog "Creating initial configuration..." -Type Info
    
    # Import config module if available
    $configModulePath = Join-Path -Path (Split-Path -Parent $scriptDirectory) -ChildPath "Modules\KeePassBackupConfigManager.psm1"
    if (Test-Path $configModulePath) {
        Import-Module $configModulePath -Force
        
        # Get configuration values from user
        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx)" -Type Info
        $sourcePath = Read-Host
        
        Write-InstallLog "Local backup directory:" -Type Info
        $backupPath = Read-Host
        
        Write-InstallLog "Enable USB backup? (Y/N)" -Type Info
        $enableUsb = (Read-Host) -eq "Y"
        
        # Create configuration
        try {
            $configParams = @{
                SourcePath = $sourcePath
                LocalBackupPath = $backupPath
                EnableUSBBackup = $enableUsb
            }
            
            # Only add these if USB is enabled
            if ($enableUsb) {
                Write-InstallLog "USB drive label (e.g., BACKUP)" -Type Info
                $driveLabel = Read-Host
                
                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info
                $enableBitLocker = (Read-Host) -eq "Y"
                
                $configParams.USBDriveLabel = $driveLabel
                $configParams.BitLockerUSB = $enableBitLocker
                
                # If BitLocker is enabled, ask for a password but handle it securely
                if ($enableBitLocker) {
                    Write-InstallLog "Do you want to set a BitLocker password? (Y/N)" -Type Info
                    $setBitLockerPassword = (Read-Host) -eq "Y"
                    
                    if ($setBitLockerPassword) {
                        $bitLockerPassword = Read-Host -AsSecureString -Prompt "Enter BitLocker password"
                        
                        # Convert SecureString to encrypted standard string for storage in config
                        if ($null -ne $bitLockerPassword -and $bitLockerPassword.Length -gt 0) {
                            $configParams.BitLockerPassword = ConvertFrom-SecureString -SecureString $bitLockerPassword
                        }
                    }
                }
            }
            
            # Create the configuration
            New-KeePassBackupConfig @configParams -ConfigPath $ConfigPath -Force
            Write-InstallLog "Configuration created successfully" -Type Success
        }
        catch {
            Write-InstallLog "Error creating configuration: $_" -Type Error
            Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning
        }
    }
    else {
        Write-InstallLog "Configuration module not found at $configModulePath" -Type Warning
        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning
    }
}

# Ensure Core directory exists and copy Core scripts
$coreDir = Join-Path -Path $scriptDirectory -ChildPath "Core"
if (!(Test-Path $coreDir)) {
    try {
        New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
        Write-InstallLog "Created Core directory: $coreDir" -Type Info
    }
    catch {
        Write-InstallLog "Failed to create Core directory: $_" -Type Error
    }
}

# Copy Core scripts if available, using LiteralPath for better handling of special characters
$sourceScriptDir = Split-Path -Parent $ScriptPath
$sourceCoreDir = Join-Path -Path $sourceScriptDir -ChildPath "Core"
if (Test-Path $sourceCoreDir) {
    try {
        Copy-Item -LiteralPath "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
        Write-InstallLog "Copied Core scripts to $coreDir" -Type Info
    }
    catch {
        Write-InstallLog "Failed to copy Core scripts: $_" -Type Warning
    }
}
else {
    Write-InstallLog "Source Core directory not found at $sourceCoreDir" -Type Warning
}

# 9. Start the service
Write-InstallLog "Starting service..." -Type Info
Start-Service -Name $ServiceName -ErrorAction SilentlyContinue

# 10. Verify service is running with improved retry logic and timeout
$timeout = 15  # Seconds to wait for service to start
$startTime = Get-Date
$serviceRunning = $false

Write-InstallLog "Waiting for service to start (timeout: $timeout seconds)..." -Type Info

do {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($null -eq $service) {
        Write-InstallLog "Service not found. Check installation logs for errors." -Type Error
        break
    }
    
    if ($service.Status -eq 'Running') {
        $serviceRunning = $true
        
        # Also verify the startup type for completeness
        try {
            $startupType = (Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'").StartMode
            Write-InstallLog "Service startup type: $startupType" -Type Info
        } catch {
            Write-InstallLog "Could not verify service startup type: $_" -Type Warning
        }
        
        Write-InstallLog "SUCCESS: Service started successfully!" -Type Success
        break
    }
    
    if ((New-TimeSpan -Start $startTime).TotalSeconds -ge $timeout) {
        Write-InstallLog "WARNING: Service failed to start within timeout period. Current status: $($service.Status)" -Type Error
        Write-InstallLog "NSSM exit code from last operation: $LASTEXITCODE" -Type Error
        Write-InstallLog "Check the following logs for errors:" -Type Warning
        Write-InstallLog "Event Viewer - Windows Logs - Application" -Type Warning
        Write-InstallLog "NSSM stderr logs at $logsDir\nssm_stderr.log" -Type Warning
        
        # Check NSSM stderr log with improved formatting, using LiteralPath
        if (Test-Path -LiteralPath "$logsDir\nssm_stderr.log") {
            Write-InstallLog "NSSM stderr log content:" -Type Info
            $logContent = Get-Content -LiteralPath "$logsDir\nssm_stderr.log" -Tail 20
            $lineNumber = 1
            foreach ($line in $logContent) {
                Write-InstallLog "Line ${lineNumber}: $line" -Type Info
                $lineNumber++
            }
        }
        break
    }
    
    Start-Sleep -Seconds 1
} while (-not $serviceRunning)

Write-InstallLog "Installation completed." -Type Success

#endregion