# KeePass Backup Service Configuration GUI
# A simple GUI for managing KeePass Backup Service configuration

# Load necessary assemblies for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Function to find the correct configuration path relative to the script
function Get-ConfigurationPath {
    try {
        # Try to determine the script directory
        $scriptPath = $PSScriptRoot
        if ([string]::IsNullOrEmpty($scriptPath)) {
            Write-Host "Cannot determine script path from PSScriptRoot"
            $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
            if ([string]::IsNullOrEmpty($scriptPath)) {
                Write-Host "Cannot determine script path from MyInvocation either"
                return "C:\Program Files\KeePassBackup\Config\config.json"
            }
        }
        
        Write-Host "Script directory determined as: $scriptPath"
        
        # Move up one directory to get project root
        $projectRoot = Split-Path -Parent $scriptPath
        Write-Host "Project root determined as: $projectRoot"
        
        # Config path should be in the Config folder
        $configPath = Join-Path -Path $projectRoot -ChildPath "Config\config.json"
        Write-Host "Config path determined as: $configPath"
        
        return $configPath
    }
    catch {
        Write-Host "Error determining configuration path: $_"
        # Fallback to hardcoded path
        return "C:\Program Files\KeePassBackup\Config\config.json"
    }
}

# Import the configuration module
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrEmpty($scriptDir)) {
        $scriptDir = "C:\Program Files\KeePassBackup\Tools"
        Write-Host "Warning: Using hardcoded script directory: $scriptDir"
    }
}

$projectRoot = Split-Path -Parent $scriptDir
if ([string]::IsNullOrEmpty($projectRoot)) {
    $projectRoot = "C:\Program Files\KeePassBackup"
    Write-Host "Warning: Using hardcoded project root: $projectRoot"
}

$modulePath = Join-Path -Path $projectRoot -ChildPath "Modules\KeePassBackupConfigManager.psm1"

try {
    Import-Module $modulePath -ErrorAction Stop
    Write-Host "Configuration module loaded successfully from: $modulePath"
}
catch {
    [System.Windows.Forms.MessageBox]::Show("Failed to load configuration module: $_`n`nModule path tried: $modulePath", 
    "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit
}

# Get the configuration path
$configPath = Get-ConfigurationPath
Write-Host "Configuration path: $configPath"

# Try to load existing configuration
$config = $null
try {
    # Try to use the module function first
    try {
        $config = Get-KeePassBackupConfig -ConfigPath $configPath
        Write-Host "Loaded existing configuration using module function"
    }
    catch {
        Write-Host "Module function failed, trying direct file read: $_"
        
        # Fallback to direct file reading
        if (Test-Path -Path $configPath) {
            $configContent = Get-Content -Path $configPath -Raw -ErrorAction Stop
            $jsonObject = ConvertFrom-Json -InputObject $configContent -ErrorAction Stop
            
            # Convert to hashtable
            $config = @{}
            foreach ($prop in $jsonObject.PSObject.Properties) {
                $config[$prop.Name] = $prop.Value
            }
            Write-Host "Loaded existing configuration via direct file read"
        }
        else {
            throw "Configuration file not found at $configPath"
        }
    }
    
    # Ensure default values for retention policy if missing or invalid
    if ($null -eq $config.RetentionDays -or $config.RetentionDays -lt 1) {
        $config.RetentionDays = 7
        Write-Host "Setting default RetentionDays to 7"
    }
    
    if ($null -eq $config.RetentionWeeks -or $config.RetentionWeeks -lt 1) {
        $config.RetentionWeeks = 4
        Write-Host "Setting default RetentionWeeks to 4"
    }
    
    if ($null -eq $config.RetentionMonths -or $config.RetentionMonths -lt 1) {
        $config.RetentionMonths = 6
        Write-Host "Setting default RetentionMonths to 6"
    }
    
    # Ensure AutoLockAfterBackup is properly defined
    if ($null -eq $config.AutoLockAfterBackup) {
        $config.AutoLockAfterBackup = $true
        Write-Host "Setting default AutoLockAfterBackup to true"
    }
}
catch {
    Write-Host "No existing configuration found or error loading it: $_"
    
    # Create default configuration if none exists
    $config = @{
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
        AutoLockAfterBackup = $true
    }
}

# Create form
$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = "KeePass Backup Service Configuration"
$script:form.Size = New-Object System.Drawing.Size(700, 650)
$script:form.StartPosition = "CenterScreen"
$script:form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$script:form.MaximizeBox = $false
$script:form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Create a TabControl
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(670, 550)

# Tab pages
$tabGeneral = New-Object System.Windows.Forms.TabPage
$tabGeneral.Text = "General"
$tabUSB = New-Object System.Windows.Forms.TabPage
$tabUSB.Text = "USB Backup"
$tabBitLocker = New-Object System.Windows.Forms.TabPage
$tabBitLocker.Text = "BitLocker"
$tabRetention = New-Object System.Windows.Forms.TabPage
$tabRetention.Text = "Retention Policy"

$tabControl.Controls.Add($tabGeneral)
$tabControl.Controls.Add($tabUSB)
$tabControl.Controls.Add($tabBitLocker)
$tabControl.Controls.Add($tabRetention)

# Helper function to create a label
function New-Label {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 150
    )
    
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point($X, $Y)
    $label.Size = New-Object System.Drawing.Size($Width, 20)
    $label.Text = $Text
    return $label
}

# Helper function to create a text box
function New-TextBox {
    param(
        [string]$Text,
        [int]$X,
        [int]$Y,
        [int]$Width = 300
    )
    
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point($X, $Y)
    $textBox.Size = New-Object System.Drawing.Size($Width, 20)
    $textBox.Text = $Text
    return $textBox
}

# Helper function to create a checkbox
function New-CheckBox {
    param(
        [string]$Text,
        [bool]$Checked,
        [int]$X,
        [int]$Y,
        [int]$Width = 200
    )
    
    $checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.Location = New-Object System.Drawing.Point($X, $Y)
    $checkBox.Size = New-Object System.Drawing.Size($Width, 20)
    $checkBox.Text = $Text
    $checkBox.Checked = $Checked
    return $checkBox
}

# Helper function to create a browse button
function New-BrowseButton {
    param(
        [int]$X,
        [int]$Y,
        [System.Windows.Forms.TextBox]$TextBox,
        [bool]$IsFolder = $true
    )
    
    $button = New-Object System.Windows.Forms.Button
    $button.Location = New-Object System.Drawing.Point($X, $Y)
    $button.Size = New-Object System.Drawing.Size(75, 23)
    $button.Text = "Browse..."
    
    # Store both the textbox and the IsFolder value in the Tag property as a custom object
    $button.Tag = New-Object PSObject -Property @{
        TextBox = $TextBox
        IsFolder = $IsFolder
    }
    
    # Script block to handle click
    $clickAction = {
        param($sender, $e)
        
        # Get the clicked button
        $clickedButton = $sender
        
        # Extract data from the Tag property
        $associatedTextBox = $clickedButton.Tag.TextBox
        $isFolder = $clickedButton.Tag.IsFolder
        
        if ($associatedTextBox -eq $null) {
            [System.Windows.Forms.MessageBox]::Show(
                "Could not determine which textbox is associated with this button.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
            return
        }
        
        if ($isFolder) {
            # Use a folder browser dialog for directories
            $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
            $folderBrowser.Description = "Select a folder"
            $folderBrowser.ShowNewFolderButton = $true
            
            # Try to set initial directory if the textbox has a valid path
            if (![string]::IsNullOrWhiteSpace($associatedTextBox.Text) -and 
                (Test-Path -Path $associatedTextBox.Text -ErrorAction SilentlyContinue)) {
                $folderBrowser.SelectedPath = $associatedTextBox.Text
            }
            
            if ($folderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $associatedTextBox.Text = $folderBrowser.SelectedPath
            }
        } 
        else {
            # Use a file dialog for files
            $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
            $openFileDialog.Filter = "KeePass Database (*.kdbx)|*.kdbx|All files (*.*)|*.*"
            $openFileDialog.Title = "Select KeePass Database"
            
            # Try to set initial directory if the textbox has a valid path
            if (![string]::IsNullOrWhiteSpace($associatedTextBox.Text)) {
                $initialDir = Split-Path -Path $associatedTextBox.Text -Parent
                if (Test-Path -Path $initialDir -PathType Container) {
                    $openFileDialog.InitialDirectory = $initialDir
                }
            }
            
            if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $associatedTextBox.Text = $openFileDialog.FileName
            }
        }
    }
    
    # Add the event handler
    $button.add_Click($clickAction)
    
    return $button
}

# Helper function to create a numeric up/down control
function New-NumericUpDown {
    param(
        [double]$Value,
        [int]$X,
        [int]$Y,
        [int]$Width = 80,
        [double]$Minimum = 1,
        [double]$Maximum = 100,
        [double]$Increment = 1,
        [int]$DecimalPlaces = 0
    )
    
    $numericUpDown = New-Object System.Windows.Forms.NumericUpDown
    $numericUpDown.Location = New-Object System.Drawing.Point($X, $Y)
    $numericUpDown.Size = New-Object System.Drawing.Size($Width, 20)
    $numericUpDown.Minimum = $Minimum
    $numericUpDown.Maximum = $Maximum
    $numericUpDown.Value = $Value
    $numericUpDown.Increment = $Increment
    $numericUpDown.DecimalPlaces = $DecimalPlaces
    return $numericUpDown
}

# Helper function to create a combobox
function New-ComboBox {
    param(
        [string[]]$Items,
        [string]$SelectedItem,
        [int]$X,
        [int]$Y,
        [int]$Width = 150
    )
    
    $comboBox = New-Object System.Windows.Forms.ComboBox
    $comboBox.Location = New-Object System.Drawing.Point($X, $Y)
    $comboBox.Size = New-Object System.Drawing.Size($Width, 20)
    $comboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    
    foreach ($item in $Items) {
        [void]$comboBox.Items.Add($item)
    }
    
    if ($SelectedItem) {
        $comboBox.SelectedItem = $SelectedItem
    } elseif ($comboBox.Items.Count -gt 0) {
        $comboBox.SelectedIndex = 0
    }
    
    return $comboBox
}

# ------------------------
# General Tab Controls
# ------------------------
$lblSourcePath = New-Label -Text "KeePass Database Path:" -X 20 -Y 20
$txtSourcePath = New-TextBox -Text $config.SourcePath -X 180 -Y 20 -Width 370
$btnBrowseSource = New-BrowseButton -X 570 -Y 20 -TextBox $txtSourcePath -IsFolder $false

$lblLocalBackupPath = New-Label -Text "Local Backup Path:" -X 20 -Y 60
$txtLocalBackupPath = New-TextBox -Text $config.LocalBackupPath -X 180 -Y 60 -Width 370
$btnBrowseBackup = New-BrowseButton -X 570 -Y 60 -TextBox $txtLocalBackupPath -IsFolder $true

$lblBackupInterval = New-Label -Text "Backup Interval (hours):" -X 20 -Y 100
$numBackupInterval = New-NumericUpDown -Value $config.BackupIntervalHours -X 180 -Y 100 -Minimum 1 -Maximum 168 -DecimalPlaces 1

$lblLogLevel = New-Label -Text "Log Level:" -X 20 -Y 140
$cmbLogLevel = New-ComboBox -Items @("Error (1)", "Warning (2)", "Information (3)", "Debug (4)") -X 180 -Y 140
$cmbLogLevel.SelectedIndex = [math]::Min(($config.LogLevel - 1), 3)  # 0-based index

# Add configuration path display
$lblConfigPath = New-Label -Text "Configuration File:" -X 20 -Y 180
$txtConfigPath = New-TextBox -Text $configPath -X 180 -Y 180 -Width 370
$txtConfigPath.ReadOnly = $true

# Add controls to the General tab
$tabGeneral.Controls.Add($lblSourcePath)
$tabGeneral.Controls.Add($txtSourcePath)
$tabGeneral.Controls.Add($btnBrowseSource)
$tabGeneral.Controls.Add($lblLocalBackupPath)
$tabGeneral.Controls.Add($txtLocalBackupPath)
$tabGeneral.Controls.Add($btnBrowseBackup)
$tabGeneral.Controls.Add($lblBackupInterval)
$tabGeneral.Controls.Add($numBackupInterval)
$tabGeneral.Controls.Add($lblLogLevel)
$tabGeneral.Controls.Add($cmbLogLevel)
$tabGeneral.Controls.Add($lblConfigPath)
$tabGeneral.Controls.Add($txtConfigPath)

# ------------------------
# USB Backup Tab Controls
# ------------------------
$gbUSBOptions = New-Object System.Windows.Forms.GroupBox
$gbUSBOptions.Location = New-Object System.Drawing.Point(20, 20)
$gbUSBOptions.Size = New-Object System.Drawing.Size(610, 100)
$gbUSBOptions.Text = "USB Backup Status"

# Create radio buttons for clearer USB backup selection
$rbUSBEnable = New-Object System.Windows.Forms.RadioButton
$rbUSBEnable.Location = New-Object System.Drawing.Point(20, 30)
$rbUSBEnable.Size = New-Object System.Drawing.Size(200, 20)
$rbUSBEnable.Text = "Enable USB Backup"
$rbUSBEnable.Checked = $config.EnableUSBBackup

$rbUSBDisable = New-Object System.Windows.Forms.RadioButton
$rbUSBDisable.Location = New-Object System.Drawing.Point(20, 60)
$rbUSBDisable.Size = New-Object System.Drawing.Size(200, 20)
$rbUSBDisable.Text = "Disable USB Backup"
$rbUSBDisable.Checked = -not $config.EnableUSBBackup

# Add help text
$lblUSBDescription = New-Object System.Windows.Forms.Label
$lblUSBDescription.Location = New-Object System.Drawing.Point(250, 30)
$lblUSBDescription.Size = New-Object System.Drawing.Size(350, 60)
$lblUSBDescription.Text = "USB backup will create a copy of your KeePass database on connected USB drives matching your criteria below, in addition to the local backup."

$gbUSBOptions.Controls.Add($rbUSBEnable)
$gbUSBOptions.Controls.Add($rbUSBDisable)
$gbUSBOptions.Controls.Add($lblUSBDescription)

$lblUSBDriveLetter = New-Label -Text "USB Drive Letter (optional):" -X 20 -Y 140
$txtUSBDriveLetter = New-TextBox -Text $config.USBDriveLetter -X 200 -Y 140 -Width 60
$lblUSBDriveLetterHelp = New-Label -Text "(leave empty to auto-detect)" -X 280 -Y 140 -Width 200

$lblUSBDriveLabel = New-Label -Text "USB Drive Label:" -X 20 -Y 180
$txtUSBDriveLabel = New-TextBox -Text $config.USBDriveLabel -X 200 -Y 180

$lblUSBBackupPath = New-Label -Text "USB Backup Folder:" -X 20 -Y 220
$txtUSBBackupPath = New-TextBox -Text $config.USBBackupPath -X 200 -Y 220

# USB controls enable/disable logic
$updateUSBControlState = {
    $enabled = $rbUSBEnable.Checked
    $txtUSBDriveLetter.Enabled = $enabled
    $txtUSBDriveLabel.Enabled = $enabled
    $txtUSBBackupPath.Enabled = $enabled
    $lblUSBDriveLetter.Enabled = $enabled
    $lblUSBDriveLabel.Enabled = $enabled
    $lblUSBBackupPath.Enabled = $enabled
    $lblUSBDriveLetterHelp.Enabled = $enabled
}

$rbUSBEnable.add_CheckedChanged($updateUSBControlState)
$rbUSBDisable.add_CheckedChanged($updateUSBControlState)

# Initial state
& $updateUSBControlState

# Add controls to the USB tab
$tabUSB.Controls.Add($gbUSBOptions)
$tabUSB.Controls.Add($lblUSBDriveLetter)
$tabUSB.Controls.Add($txtUSBDriveLetter)
$tabUSB.Controls.Add($lblUSBDriveLetterHelp)
$tabUSB.Controls.Add($lblUSBDriveLabel)
$tabUSB.Controls.Add($txtUSBDriveLabel)
$tabUSB.Controls.Add($lblUSBBackupPath)
$tabUSB.Controls.Add($txtUSBBackupPath)

# ------------------------
# BitLocker Tab Controls
# ------------------------
$chkEnableBitLocker = New-CheckBox -Text "Enable BitLocker Encryption" -Checked $config.EnableBitLocker -X 20 -Y 20 -Width 250
$chkBitLockerUSB = New-CheckBox -Text "Enable BitLocker for USB Drives" -Checked $config.BitLockerUSB -X 20 -Y 60 -Width 250

# Create a simple checkbox for auto-lock setting instead of radio buttons
$chkAutoLock = New-CheckBox -Text "Auto-Lock Drives After Backup" -Checked $config.AutoLockAfterBackup -X 20 -Y 100 -Width 300

# BitLocker Key Path controls
$lblBitLockerKeyPath = New-Label -Text "BitLocker Key Path:" -X 20 -Y 140
$txtBitLockerKeyPath = New-TextBox -Text $config.BitLockerKeyPath -X 180 -Y 140 -Width 370
$btnBrowseBitLockerPath = New-BrowseButton -X 570 -Y 140 -TextBox $txtBitLockerKeyPath -IsFolder $true

# BitLocker controls enable/disable logic
$updateBitLockerControlState = {
    $chkBitLockerUSB.Enabled = $chkEnableBitLocker.Checked
    $chkAutoLock.Enabled = $chkEnableBitLocker.Checked
    $lblBitLockerKeyPath.Enabled = $chkEnableBitLocker.Checked
    $txtBitLockerKeyPath.Enabled = $chkEnableBitLocker.Checked
    $btnBrowseBitLockerPath.Enabled = $chkEnableBitLocker.Checked
}

$chkEnableBitLocker.add_CheckedChanged($updateBitLockerControlState)
# Initial state
& $updateBitLockerControlState

# Add controls to the BitLocker tab
$tabBitLocker.Controls.Add($chkEnableBitLocker)
$tabBitLocker.Controls.Add($chkBitLockerUSB)
$tabBitLocker.Controls.Add($chkAutoLock)
$tabBitLocker.Controls.Add($lblBitLockerKeyPath)
$tabBitLocker.Controls.Add($txtBitLockerKeyPath)
$tabBitLocker.Controls.Add($btnBrowseBitLockerPath)

# ------------------------
# Retention Policy Tab Controls
# ------------------------
$lblRetentionDays = New-Label -Text "Keep all backups for (days):" -X 20 -Y 20 -Width 200
$numRetentionDays = New-NumericUpDown -Value $(if ($config.RetentionDays -lt 1) { 7 } else { $config.RetentionDays }) -X 240 -Y 20 -Minimum 1 -Maximum 90

$lblRetentionWeeks = New-Label -Text "Keep weekly backups for (weeks):" -X 20 -Y 60 -Width 200
$numRetentionWeeks = New-NumericUpDown -Value $(if ($config.RetentionWeeks -lt 1) { 4 } else { $config.RetentionWeeks }) -X 240 -Y 60 -Minimum 1 -Maximum 52

$lblRetentionMonths = New-Label -Text "Keep monthly backups for (months):" -X 20 -Y 100 -Width 200
$numRetentionMonths = New-NumericUpDown -Value $config.RetentionMonths -X 240 -Y 100 -Minimum 1 -Maximum 60

# Description label
$lblRetentionDescription = New-Object System.Windows.Forms.Label
$lblRetentionDescription.Location = New-Object System.Drawing.Point(20, 150)
$lblRetentionDescription.Size = New-Object System.Drawing.Size(600, 60)
$lblRetentionDescription.Text = "Retention Policy: The service keeps all backups for the specified number of days. After that, it keeps one backup per week for the specified number of weeks, and then one backup per month for the specified number of months."

# Add controls to the Retention Policy tab
$tabRetention.Controls.Add($lblRetentionDays)
$tabRetention.Controls.Add($numRetentionDays)
$tabRetention.Controls.Add($lblRetentionWeeks)
$tabRetention.Controls.Add($numRetentionWeeks)
$tabRetention.Controls.Add($lblRetentionMonths)
$tabRetention.Controls.Add($numRetentionMonths)
$tabRetention.Controls.Add($lblRetentionDescription)

# ------------------------
# Button Panel
# ------------------------
$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Location = New-Object System.Drawing.Point(510, 570)
$btnSave.Size = New-Object System.Drawing.Size(80, 30)
$btnSave.Text = "Save"
$btnSave.add_Click({
    # Update config object
    $config.SourcePath = $txtSourcePath.Text
    $config.LocalBackupPath = $txtLocalBackupPath.Text
    $config.EnableUSBBackup = $rbUSBEnable.Checked
    $config.USBDriveLetter = $txtUSBDriveLetter.Text
    $config.USBBackupPath = $txtUSBBackupPath.Text
    $config.USBDriveLabel = $txtUSBDriveLabel.Text
    $config.EnableBitLocker = $chkEnableBitLocker.Checked
    $config.BitLockerUSB = $chkBitLockerUSB.Checked
    $config.BitLockerKeyPath = $txtBitLockerKeyPath.Text
    $config.BackupIntervalHours = $numBackupInterval.Value
    $config.RetentionDays = [int]$numRetentionDays.Value
    $config.RetentionWeeks = [int]$numRetentionWeeks.Value
    $config.RetentionMonths = [int]$numRetentionMonths.Value
    $config.LogLevel = [int]($cmbLogLevel.SelectedIndex + 1)
    $config.AutoLockAfterBackup = $chkAutoLock.Checked
    
    try {
        # Get the config path displayed in the UI
        $configPath = $txtConfigPath.Text
        
        # Debug output - helps identify where it's trying to save
        Write-Host "Attempting to save configuration to: $configPath"
        
        # Ensure directory exists
        $configDir = Split-Path -Path $configPath -Parent
        if (![string]::IsNullOrEmpty($configDir) -and !(Test-Path -Path $configDir)) {
            Write-Host "Creating directory: $configDir"
            New-Item -ItemType Directory -Path $configDir -Force -ErrorAction Stop | Out-Null
        }
        
        # Try direct file writing with specific error handling
        try {
            $configJson = ConvertTo-Json -InputObject $config -Depth 3
            Set-Content -Path $configPath -Value $configJson -Force -ErrorAction Stop
            Write-Host "Configuration saved successfully with direct file writing"
            
            # Show success message with the path for verification
            [System.Windows.Forms.MessageBox]::Show("Configuration saved successfully to:`n$configPath", "Success", 
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            
            # Close the form
            $script:form.Close()
        }
        catch [System.UnauthorizedAccessException] {
            Write-Host "Access denied. Need to run as administrator."
            [System.Windows.Forms.MessageBox]::Show(
                "Access denied when trying to save the configuration.`n`nPlease run this application as administrator to save to this location: $configPath", 
                "Access Denied", 
                [System.Windows.Forms.MessageBoxButtons]::OK, 
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
        catch {
            $errorMsg = $_
            Write-Host "Direct file writing failed: $errorMsg"
            
            # Try using the module as a fallback
            try {
                # Check if the Set-KeePassBackupConfig function exists
                if (Get-Command -Name Set-KeePassBackupConfig -ErrorAction SilentlyContinue) {
                    Set-KeePassBackupConfig @config -ConfigPath $configPath -ErrorAction Stop
                    
                    [System.Windows.Forms.MessageBox]::Show(
                        "Configuration saved successfully using module function to:`n$configPath", 
                        "Success", 
                        [System.Windows.Forms.MessageBoxButtons]::OK, 
                        [System.Windows.Forms.MessageBoxIcon]::Information
                    )
                    
                    $script:form.Close()
                } else {
                    throw "Module function Set-KeePassBackupConfig not found"
                }
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show(
                    "Error saving configuration: $errorMsg`n`nFallback also failed: $_`n`nPlease run this application as administrator if you're trying to save to a protected folder.", 
                    "Error", 
                    [System.Windows.Forms.MessageBoxButtons]::OK, 
                    [System.Windows.Forms.MessageBoxIcon]::Error
                )
            }
        }
    } 
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Error preparing configuration: $_", 
            "Error", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

# Add form controls
$script:form.Controls.Add($tabControl)
$script:form.Controls.Add($btnSave)

# Center the form on the screen
$script:form.StartPosition = "CenterScreen"

# Show the form
$script:form.Add_Shown({$script:form.Activate()})
[void]$script:form.ShowDialog()