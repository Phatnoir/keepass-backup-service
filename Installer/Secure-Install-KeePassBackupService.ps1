# Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion
" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion
" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion
" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion
" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }


    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion
" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}




    # Ensure Core directory exists and copy Core scripts
    $coreDir = Join-Path $scriptDirectory "Core"
    if (!(Test-Path $coreDir)) {
        try {
            New-Item -ItemType Directory -Path $coreDir -Force | Out-Null
            Write-ServiceLog "Created Core directory: $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to create Core directory: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Error
        }
    }

    # Copy Core scripts if available
    $sourceScriptDir = Split-Path -Parent $sourcePath
    $sourceCoreDir = Join-Path $sourceScriptDir "Core"
    
    if (Test-Path $sourceCoreDir) {
        try {
            Copy-Item -Path "$sourceCoreDir\*.ps1" -Destination $coreDir -Force
            Write-ServiceLog "Copied Core scripts to $coreDir" -Type Information
        }
        catch {
            Write-ServiceLog "Failed to copy Core scripts: # Secure-Install-KeePassBackupService.ps1

# Enhanced secure installation script with credential prompting



param(

    [Parameter(Mandatory=$false)]

    [string]$ScriptPath = "C:\\Program Files\\KeePassBackupService\\src\\KeePassBackupService.ps1",

    

    [Parameter(Mandatory=$false)]

    [string]$ConfigPath = "C:\\Program Files\\KeePassBackupService\\Config\\config.json",

    

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

    

    # Color selection

    $foregroundColor = switch ($Type) {

        'Info'    { 'White' }

        'Warning' { 'Yellow' }

        'Error'   { 'Red' }

        'Success' { 'Green' }

        default   { 'White' }

    }

    

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

    

    try {

        # Create a temporary file for the password

        $tempPwFile = Join-Path $env:TEMP "svc_$([Guid]::NewGuid().ToString()).tmp"

        

        # Use SecureString methods to minimize plaintext exposure

        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)

        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

        

        # Write password to temp file with no encoding conversion to minimize memory usage

        [System.IO.File]::WriteAllText($tempPwFile, $plainPassword)

        

        # Free the BSTR memory immediately

        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        

        # Clear the variable

        $plainPassword = $null

        [System.GC]::Collect()

        

        # Set the service account

        & $NSSMPath set $ServiceName ObjectName $Credential.UserName "`"@$tempPwFile`""

        $result = $LASTEXITCODE

        

        # Securely delete the temp file by overwriting with random data

        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

        $bytes = New-Object byte[] (100 * 1024) # 100 KB of random data

        $rng.GetBytes($bytes)

        [System.IO.File]::WriteAllBytes($tempPwFile, $bytes)

        

        # Delete the file

        Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        

        # Force garbage collection again

        [System.GC]::Collect()

        

        return ($result -eq 0)

    }

    catch {

        Write-InstallLog "Error setting service credentials: $_" -Type Error

        

        # Ensure temp file is deleted even on error

        if (Test-Path $tempPwFile) {

            Remove-Item -Path $tempPwFile -Force -ErrorAction SilentlyContinue

        }

        

        return $false

    }

}



#endregion



#region Main Script



# Ensure running as administrator

if (-not (Test-Administrator)) {

    Write-InstallLog "This script must be run as Administrator. Please restart with admin privileges." -Type Error

    Exit 1

}



Write-InstallLog "Starting KeePass Backup Service installation..." -Type Info



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

        

        if (!$NoPrompt) {

            $response = Read-Host

            if ($response -eq "Y" -or $response -eq "y") {

                try {

                    # Create temp directory

                    $tempDir = Join-Path $env:TEMP "nssm_download"

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

                    

                    # Verify copy

                    if (Test-Path $NSSMPath) {

                        Write-InstallLog "NSSM installed successfully at: $NSSMPath" -Type Success

                    }

                    else {

                        Write-InstallLog "Failed to install NSSM. Please install it manually." -Type Error

                        Exit 1

                    }

                }

                catch {

                    Write-InstallLog "Error downloading or installing NSSM: $_" -Type Error

                    Write-InstallLog "Please install NSSM manually from https://nssm.cc" -Type Error

                    Exit 1

                }

            }

            else {

                Write-InstallLog "NSSM is required for service installation. Please install it manually." -Type Error

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

            

            # Load Windows forms for file dialog

            Add-Type -AssemblyName System.Windows.Forms

            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog

            $openFileDialog.Filter = "PowerShell Scripts (*.ps1)|*.ps1|All files (*.*)|*.*"

            $openFileDialog.Title = "Select KeePassBackupService.ps1"

            

            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {

                Copy-Item -Path $openFileDialog.FileName -Destination $ScriptPath -Force

                Write-InstallLog "Copied script to $ScriptPath" -Type Success

            }

            else {

                Write-InstallLog "Script selection canceled. Installation aborted." -Type Error

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



# 2. Create event log source

Write-InstallLog "Registering event log source..." -Type Info

if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) {

    try {

        [System.Diagnostics.EventLog]::CreateEventSource($ServiceName, "Application")

        Write-InstallLog "Event log source created successfully." -Type Success

        Start-Sleep -Seconds 2  # Allow time for event source registration

    }

    catch {

        Write-InstallLog "Failed to create event log source: $_" -Type Warning

        # Continue anyway - not critical

    }

}



# 3. Get service credentials

$serviceCred = Get-SecureCredential



# 4. Install the service with NSSM

Write-InstallLog "Installing service using NSSM..." -Type Info

$scriptDirectory = Split-Path -Parent $ScriptPath



# Create logs directory

$logsDir = Join-Path $scriptDirectory "Logs"

if (-not (Test-Path -Path $logsDir)) {

    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null

}



# Install the service

& $NSSMPath install $ServiceName "powershell.exe"



# Configure service parameters

& $NSSMPath set $ServiceName AppParameters "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

& $NSSMPath set $ServiceName DisplayName $DisplayName

& $NSSMPath set $ServiceName Description $Description

& $NSSMPath set $ServiceName AppDirectory $scriptDirectory

& $NSSMPath set $ServiceName AppStdout "$logsDir\nssm_stdout.log"

& $NSSMPath set $ServiceName AppStderr "$logsDir\nssm_stderr.log"



# Set service account - using more secure password handling

if ($serviceCred) {

    $success = Set-SecureServicePassword -ServiceName $ServiceName -NSSMPath $NSSMPath -Credential $serviceCred

    

    if ($success) {

        Write-InstallLog "Service configured to run as $($serviceCred.UserName)" -Type Success

    }

    else {

        Write-InstallLog "Failed to set service credentials. Falling back to LocalSystem account." -Type Warning

        & $NSSMPath set $ServiceName ObjectName "LocalSystem"

    }

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



# 6. Give the script file explicit permissions

Write-InstallLog "Setting file permissions..." -Type Info

$acl = Get-Acl $ScriptPath

$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")

$acl.SetAccessRule($accessRule)

Set-Acl $ScriptPath $acl



# If service account is not LocalSystem, give it permissions too

if ($serviceCred) {

    $acl = Get-Acl $ScriptPath

    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceCred.UserName, "FullControl", "Allow")

    $acl.SetAccessRule($accessRule)

    Set-Acl $ScriptPath $acl

}



# 7. Create configuration if it doesn't exist

if (!(Test-Path $ConfigPath) -and !$NoPrompt) {

    Write-InstallLog "Creating initial configuration..." -Type Info

    

    # Import config module if available

    $configModulePath = Join-Path (Split-Path -Parent $scriptDirectory) "Modules\KeePassBackupConfigManager.psm1"

    if (Test-Path $configModulePath) {

        Import-Module $configModulePath -Force

        

        # Get configuration values from user

        Write-InstallLog "KeePass database file path (e.g., C:\Users\Username\OneDrive\KeePass.kdbx):" -Type Info

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

                Write-InstallLog "USB drive label (e.g., 'BACKUP')" -Type Info

                $driveLabel = Read-Host

                

                Write-InstallLog "Enable BitLocker for USB? (Y/N)" -Type Info

                $enableBitLocker = (Read-Host) -eq "Y"

                

                $configParams.USBDriveLabel = $driveLabel

                $configParams.EnableBitLocker = $enableBitLocker

                $configParams.BitLockerUSB = $enableBitLocker

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

        Write-InstallLog "Configuration module not found. Using default settings." -Type Warning

        Write-InstallLog "You'll need to create the configuration manually after installation" -Type Warning

    }

}



# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion
" -Type Warning
        }
    }
    else {
        Write-ServiceLog "Source Core directory not found at $sourceCoreDir" -Type Warning
    }

# 8. Start the service

Write-InstallLog "Starting service..." -Type Info

Start-Service -Name $ServiceName



# 9. Verify service is running

Start-Sleep -Seconds 5  # Give it time to start

$service = Get-Service -Name $ServiceName

if ($service.Status -eq 'Running') {

    Write-InstallLog "SUCCESS: Service started successfully!" -Type Success

}

else {

    Write-InstallLog "WARNING: Service failed to start. Current status: $($service.Status)" -Type Error

    Write-InstallLog "Check the following logs for errors:" -Type Warning

    Write-InstallLog "- Event Viewer > Windows Logs > Application" -Type Warning

    Write-InstallLog "- $logsDir\nssm_stderr.log" -Type Warning

    

    # Check NSSM stderr log

    if (Test-Path "$logsDir\nssm_stderr.log") {

        Write-InstallLog "`nNSSM stderr log content:" -Type Info

        Get-Content "$logsDir\nssm_stderr.log" -Tail 20

    }

    

    # Get the latest errors from the Event Log

    Write-InstallLog "`nLatest relevant event log entries:" -Type Info

    try {

        Get-EventLog -LogName Application -Newest 5 -Source $ServiceName -ErrorAction SilentlyContinue | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No event log entries found for $ServiceName" -Type Warning

    }

    

    try {

        Get-EventLog -LogName System -Source "Service Control Manager" -Newest 5 | 

            Where-Object {$_.Message -like "*$ServiceName*"} | 

            Format-Table -Property TimeGenerated, EntryType, Message -Wrap

    }

    catch {

        Write-InstallLog "No Service Control Manager entries found for $ServiceName" -Type Warning

    }

}



Write-InstallLog "Installation completed." -Type Success



#endregion

