# KeePass Backup Service Configuration GUI
# A simple GUI for managing KeePass Backup Service configuration

# Configuration constants and default paths
$script:DEFAULT_CONFIG = @{
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
    EnableUSBPrune = $true
}

# Load necessary assemblies for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Initialize Tooltip helper
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.AutoPopDelay = 5000
$toolTip.InitialDelay = 500
$toolTip.ReshowDelay = 500
$toolTip.ShowAlways = $true

# Function to add tooltips to controls
function Add-ToolTip {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.Control]$Control,
        
        [Parameter(Mandatory=$true)]
        [string]$Text
    )
    
    $toolTip.SetToolTip($Control, $Text)
}

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
                # Assume the script is in the Tools directory, get parent for project root
                return "$env:ProgramFiles\KeePassBackup\Config\config.json"
            }
        }
        
        Write-Host "Script directory determined as: $scriptPath"
        
        # Assume script is in Tools directory, move up one level to get project root
        $projectRoot = Split-Path -Parent $scriptPath
        Write-Host "Project root determined as: $projectRoot"
        
        # Config path should be in the Config folder
        $configPath = Join-Path -Path $projectRoot -ChildPath "Config\config.json"
        Write-Host "Config path determined as: $configPath"
        
        return $configPath
    }
    catch {
        Write-Host "Error determining configuration path: $_"
        # Fallback to user profile if program files might not be writable
        return "$env:LOCALAPPDATA\KeePassBackup\Config\config.json"
    }
}

# Function to validate configuration
function Test-ConfigurationStructure {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config
    )
    
    $isValid = $true
    $requiredKeys = @(
        "SourcePath", 
        "LocalBackupPath", 
        "EnableUSBBackup", 
        "BackupIntervalHours", 
        "RetentionDays", 
        "RetentionWeeks", 
        "RetentionMonths"
    )
    
    foreach ($key in $requiredKeys) {
        if (-not $Config.ContainsKey($key)) {
            Write-Host "Configuration is missing required key: $key"
            $isValid = $false
            
            # Add missing key with default value
            $Config[$key] = $script:DEFAULT_CONFIG[$key]
        }
    }
    
    # Ensure all keys from DEFAULT_CONFIG exist in the config
    foreach ($key in $script:DEFAULT_CONFIG.Keys) {
        if (-not $Config.ContainsKey($key)) {
            Write-Host "Configuration is missing key (adding default): $key"
            $Config[$key] = $script:DEFAULT_CONFIG[$key]
        }
    }
    
    # Type validation for numeric values
    if ($Config.BackupIntervalHours -is [string]) {
        [double]$Config.BackupIntervalHours = [double]::Parse($Config.BackupIntervalHours)
    }
    
    if ($Config.RetentionDays -is [string]) {
        [int]$Config.RetentionDays = [int]::Parse($Config.RetentionDays)
    }
    
    if ($Config.RetentionWeeks -is [string]) {
        [int]$Config.RetentionWeeks = [int]::Parse($Config.RetentionWeeks)
    }
    
    if ($Config.RetentionMonths -is [string]) {
        [int]$Config.RetentionMonths = [int]::Parse($Config.RetentionMonths)
    }
    
    # Ensure boolean values are actually booleans
    $boolKeys = @("EnableUSBBackup", "EnableBitLocker", "BitLockerUSB", "AutoLockAfterBackup", "EnableUSBPrune")
    foreach ($key in $boolKeys) {
        if ($Config.ContainsKey($key) -and $Config[$key] -isnot [bool]) {
            # Convert string representation to boolean
            if ($Config[$key] -is [string]) {
                $Config[$key] = [System.Convert]::ToBoolean($Config[$key])
            } else {
                $Config[$key] = $Config[$key] -eq $true
            }
        }
    }
    
    return $isValid
}

# Function to validate file and folder paths
function Test-PathValidity {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.TextBox]$TextBox,
        [bool]$MustExist = $false,
        [bool]$IsFile = $false
    )
    
    $path = $TextBox.Text.Trim()
    $invalid = $false
    
    # Check for invalid characters
    if ($path -match '[<>"|?*]') {
        $invalid = $true
    }
    
    # Check if path exists when required
    if (-not $invalid -and $MustExist) {
        if ($IsFile) {
            $invalid = -not (Test-Path -Path $path -PathType Leaf)
        } else {
            $invalid = -not (Test-Path -Path $path -PathType Container)
        }
    }
    
    # Visual feedback
    if ($invalid) {
        $TextBox.BackColor = [System.Drawing.Color]::LightPink
    } else {
        $TextBox.BackColor = [System.Drawing.SystemColors]::Window
    }
    
    return -not $invalid
}

# Import the configuration module
$scriptDir = $PSScriptRoot
if ([string]::IsNullOrEmpty($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ([string]::IsNullOrEmpty($scriptDir)) {
        $scriptDir = "$env:ProgramFiles\KeePassBackup\Tools"
        Write-Host "Warning: Using fallback script directory: $scriptDir"
    }
}

$projectRoot = Split-Path -Parent $scriptDir
if ([string]::IsNullOrEmpty($projectRoot)) {
    $projectRoot = "$env:ProgramFiles\KeePassBackup"
    Write-Host "Warning: Using fallback project root: $projectRoot"
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
    
    # Validate configuration structure and set defaults if needed
    $valid = Test-ConfigurationStructure -Config $config
    if (-not $valid) {
        Write-Host "Configuration was incomplete or invalid, defaults were applied for missing values."
    }
	
	# Ensure EnableUSBPrune is properly defined
	if ($null -eq $config.EnableUSBPrune) {
		$config.EnableUSBPrune = $true  # or $false depending on your default
		Write-Host "Setting default EnableUSBPrune to true"
	}
}
catch {
    Write-Host "No existing configuration found or error loading it: $_"
    
    # Create default configuration if none exists
    $config = $script:DEFAULT_CONFIG.Clone()
}

# Create form and buttons early so they can be referenced
$script:form = New-Object System.Windows.Forms.Form
$script:form.Text = "KeePass Backup Service Configuration"
$script:form.Size = New-Object System.Drawing.Size(700, 650)
$script:form.StartPosition = "CenterScreen"
$script:form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$script:form.MaximizeBox = $false
$script:form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Create the buttons early
$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Location = New-Object System.Drawing.Point(510, 570)
$btnSave.Size = New-Object System.Drawing.Size(80, 30)
$btnSave.Text = "&Save"

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Location = New-Object System.Drawing.Point(600, 570)
$btnCancel.Size = New-Object System.Drawing.Size(80, 30)
$btnCancel.Text = "&Cancel"

# Set default buttons
$script:form.AcceptButton = $btnSave
$script:form.CancelButton = $btnCancel

# Create a TabControl
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(670, 550)
$tabControl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor 
                     [System.Windows.Forms.AnchorStyles]::Left -bor 
                     [System.Windows.Forms.AnchorStyles]::Right -bor 
                     [System.Windows.Forms.AnchorStyles]::Bottom

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

# Add path validation to textboxes
$txtSourcePath.Add_TextChanged({
    Test-PathValidity -TextBox $txtSourcePath -MustExist $false -IsFile $true
})

$txtLocalBackupPath.Add_TextChanged({
    Test-PathValidity -TextBox $txtLocalBackupPath -MustExist $false
})

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
$chkEnableUSB = New-CheckBox -Text "Enable USB Backup" -Checked $config.EnableUSBBackup -X 20 -Y 20 -Width 200

# Add help text
$lblUSBDescription = New-Object System.Windows.Forms.Label
$lblUSBDescription.Location = New-Object System.Drawing.Point(250, 20)
$lblUSBDescription.Size = New-Object System.Drawing.Size(350, 60)
$lblUSBDescription.Text = "USB backup will create a copy of your KeePass database on connected USB drives matching your criteria below, in addition to the local backup."

$lblUSBDriveLetter = New-Label -Text "USB Drive Letter (optional):" -X 20 -Y 100
$txtUSBDriveLetter = New-TextBox -Text $config.USBDriveLetter -X 200 -Y 100 -Width 60
$lblUSBDriveLetterHelp = New-Label -Text "(leave empty to auto-detect)" -X 280 -Y 100 -Width 200

# Add validation to USB drive letter textbox
$txtUSBDriveLetter.Add_TextChanged({
    if ($txtUSBDriveLetter.Text.Length -gt 1) {
        $txtUSBDriveLetter.Text = $txtUSBDriveLetter.Text.Substring(0, 1).ToUpper()
        $txtUSBDriveLetter.SelectionStart = 1
    } elseif ($txtUSBDriveLetter.Text.Length -eq 1) {
        $txtUSBDriveLetter.Text = $txtUSBDriveLetter.Text.ToUpper()
        $txtUSBDriveLetter.SelectionStart = 1
    }
})

$lblUSBDriveLabel = New-Label -Text "USB Drive Label:" -X 20 -Y 140
$txtUSBDriveLabel = New-TextBox -Text $config.USBDriveLabel -X 200 -Y 140

$lblUSBBackupPath = New-Label -Text "USB Backup Folder:" -X 20 -Y 180
$txtUSBBackupPath = New-TextBox -Text $config.USBBackupPath -X 200 -Y 180

# Add USB Prune checkbox
$chkEnableUSBPrune = New-CheckBox -Text "Apply retention policy to USB backups" -Checked $config.EnableUSBPrune -X 20 -Y 220 -Width 350

# USB controls enable/disable logic
$updateUSBControlState = {
    $enabled = $chkEnableUSB.Checked
    $txtUSBDriveLetter.Enabled = $enabled
    $txtUSBDriveLabel.Enabled = $enabled
    $txtUSBBackupPath.Enabled = $enabled
    $lblUSBDriveLetter.Enabled = $enabled
    $lblUSBDriveLabel.Enabled = $enabled
    $lblUSBBackupPath.Enabled = $enabled
    $lblUSBDriveLetterHelp.Enabled = $enabled
    $chkEnableUSBPrune.Enabled = $enabled
}

$chkEnableUSB.add_CheckedChanged($updateUSBControlState)

# Initial state
$null = & $updateUSBControlState

# Add controls to the USB tab
$tabUSB.Controls.Add($chkEnableUSB)
$tabUSB.Controls.Add($lblUSBDescription)
$tabUSB.Controls.Add($lblUSBDriveLetter)
$tabUSB.Controls.Add($txtUSBDriveLetter)
$tabUSB.Controls.Add($lblUSBDriveLetterHelp)
$tabUSB.Controls.Add($lblUSBDriveLabel)
$tabUSB.Controls.Add($txtUSBDriveLabel)
$tabUSB.Controls.Add($lblUSBBackupPath)
$tabUSB.Controls.Add($txtUSBBackupPath)
$tabUSB.Controls.Add($chkEnableUSBPrune)

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

# Add path validation to BitLocker key path
$txtBitLockerKeyPath.Add_TextChanged({
    Test-PathValidity -TextBox $txtBitLockerKeyPath -MustExist $false
})

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
$null = & $updateBitLockerControlState

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
# Status Bar for Messages
# ------------------------
$statusStrip = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Spring = $true
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$statusStrip.Items.Add($statusLabel)

# Function to update status message
function Update-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $statusLabel.Text = $Message
    
    switch ($Type) {
        'Info'    { $statusStrip.BackColor = [System.Drawing.SystemColors]::Control }
        'Success' { $statusStrip.BackColor = [System.Drawing.Color]::FromArgb(230, 255, 230) } # Light green
        'Warning' { $statusStrip.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 200) } # Light yellow
        'Error'   { $statusStrip.BackColor = [System.Drawing.Color]::FromArgb(255, 220, 220) } # Light red
    }
}

# Function to reset controls to default values
function Reset-ControlsToDefaults {
    # General Tab
    $txtSourcePath.Text = $script:DEFAULT_CONFIG.SourcePath
    $txtLocalBackupPath.Text = $script:DEFAULT_CONFIG.LocalBackupPath
    $numBackupInterval.Value = $script:DEFAULT_CONFIG.BackupIntervalHours
    $cmbLogLevel.SelectedIndex = $script:DEFAULT_CONFIG.LogLevel - 1
    
    # USB Tab
    $chkEnableUSB.Checked = $script:DEFAULT_CONFIG.EnableUSBBackup
    $txtUSBDriveLetter.Text = $script:DEFAULT_CONFIG.USBDriveLetter
    $txtUSBDriveLabel.Text = $script:DEFAULT_CONFIG.USBDriveLabel
    $txtUSBBackupPath.Text = $script:DEFAULT_CONFIG.USBBackupPath
    $chkEnableUSBPrune.Checked = $script:DEFAULT_CONFIG.EnableUSBPrune
    
    # BitLocker Tab
    $chkEnableBitLocker.Checked = $script:DEFAULT_CONFIG.EnableBitLocker
    $chkBitLockerUSB.Checked = $script:DEFAULT_CONFIG.BitLockerUSB
    $chkAutoLock.Checked = $script:DEFAULT_CONFIG.AutoLockAfterBackup
    $txtBitLockerKeyPath.Text = $script:DEFAULT_CONFIG.BitLockerKeyPath
    
    # Retention Tab
    $numRetentionDays.Value = $script:DEFAULT_CONFIG.RetentionDays
    $numRetentionWeeks.Value = $script:DEFAULT_CONFIG.RetentionWeeks
    $numRetentionMonths.Value = $script:DEFAULT_CONFIG.RetentionMonths
    
    # Update dependent controls state
    $null = & $updateUSBControlState
	$null = & $updateBitLockerControlState
}

# ------------------------
# Button Panel
# ------------------------
$btnReset = New-Object System.Windows.Forms.Button
$btnReset.Location = New-Object System.Drawing.Point(20, 570)
$btnReset.Size = New-Object System.Drawing.Size(120, 30)
$btnReset.Text = "&Reset to Defaults"
$btnReset.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$btnReset.add_Click({
    $result = [System.Windows.Forms.MessageBox]::Show(
        "Are you sure you want to reset all settings to their default values?",
        "Reset to Defaults",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        Reset-ControlsToDefaults
        Update-StatusMessage -Message "All settings reset to default values." -Type Success
    }
})

# Test Configuration Button
$btnTest = New-Object System.Windows.Forms.Button
$btnTest.Location = New-Object System.Drawing.Point(150, 570)
$btnTest.Size = New-Object System.Drawing.Size(150, 30)
$btnTest.Text = "&Test Configuration"
$btnTest.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left
$btnTest.Add_Click({
    # This will verify that paths exist, permissions are correct, etc.
    $isValid = $true
    $messages = @()
    
    # Test source path
    if (![string]::IsNullOrEmpty($txtSourcePath.Text) -and !(Test-Path -Path $txtSourcePath.Text -PathType Leaf)) {
        $isValid = $false
        $messages += "KeePass database file not found: $($txtSourcePath.Text)"
    }
    
    # Test local backup path
    if (![string]::IsNullOrEmpty($txtLocalBackupPath.Text) -and !(Test-Path -Path $txtLocalBackupPath.Text -PathType Container)) {
        try {
            # Try to create the directory
            New-Item -Path $txtLocalBackupPath.Text -ItemType Directory -Force -ErrorAction Stop | Out-Null
            $messages += "Created local backup directory: $($txtLocalBackupPath.Text)"
        }
        catch {
            $isValid = $false
            $messages += "Cannot create local backup directory: $($txtLocalBackupPath.Text). $($_)"
        }
    }
    
    # Test BitLocker key path if enabled
    if ($chkEnableBitLocker.Checked -and ![string]::IsNullOrEmpty($txtBitLockerKeyPath.Text) -and 
        !(Test-Path -Path $txtBitLockerKeyPath.Text -PathType Container)) {
        try {
            # Try to create the directory
            New-Item -Path $txtBitLockerKeyPath.Text -ItemType Directory -Force -ErrorAction Stop | Out-Null
            $messages += "Created BitLocker key directory: $($txtBitLockerKeyPath.Text)"
        }
        catch {
            $isValid = $false
            $messages += "Cannot create BitLocker key directory: $($txtBitLockerKeyPath.Text). $($_)"
        }
    }
    
    # Show test results
    if ($isValid) {
        $messageText = "Configuration test passed!`n`n"
        if ($messages.Count -gt 0) {
            $messageText += [string]::Join("`n", $messages)
        } else {
            $messageText += "All paths are valid and accessible."
        }
        
        [System.Windows.Forms.MessageBox]::Show($messageText, "Test Successful", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Information)
    }
    else {
        $messageText = "Configuration test failed! Please fix the following issues:`n`n"
        $messageText += [string]::Join("`n", $messages)
        [System.Windows.Forms.MessageBox]::Show($messageText, "Test Failed", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
})

$btnSave.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
$btnSave.add_Click({
    # Update config object
    $config.SourcePath = $txtSourcePath.Text
    $config.LocalBackupPath = $txtLocalBackupPath.Text
    $config.EnableUSBBackup = $chkEnableUSB.Checked
    $config.USBDriveLetter = $txtUSBDriveLetter.Text
    $config.USBBackupPath = $txtUSBBackupPath.Text
    $config.USBDriveLabel = $txtUSBDriveLabel.Text
    $config.EnableBitLocker = $chkEnableBitLocker.Checked
    $config.BitLockerUSB = $chkBitLockerUSB.Checked
    $config.EnableUSBPrune = $chkEnableUSBPrune.Checked
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
            
            # Show success message
            Update-StatusMessage -Message "Configuration saved successfully to: $configPath" -Type Success
            
            [System.Windows.Forms.MessageBox]::Show("Configuration saved successfully to:`n$configPath", "Success", 
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            
            # Close the form
            $script:form.Close()
        }
        catch [System.UnauthorizedAccessException] {
            Write-Host "Access denied. Need to run as administrator."
            Update-StatusMessage -Message "Access denied. Try running as administrator." -Type Error
            
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
            Update-StatusMessage -Message "Error saving configuration: $errorMsg" -Type Error
            
            # Try using the module as a fallback
            try {
                # Check if the Set-KeePassBackupConfig function exists
                if (Get-Command -Name Set-KeePassBackupConfig -ErrorAction SilentlyContinue) {
                    Set-KeePassBackupConfig @config -ConfigPath $configPath -ErrorAction Stop
                    
                    Update-StatusMessage -Message "Configuration saved successfully using module function." -Type Success
                    
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
                Update-StatusMessage -Message "Failed to save configuration. Try running as administrator." -Type Error
                
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
        Update-StatusMessage -Message "Error preparing configuration: $_" -Type Error
        
        [System.Windows.Forms.MessageBox]::Show(
            "Error preparing configuration: $_", 
            "Error", 
            [System.Windows.Forms.MessageBoxButtons]::OK, 
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
    }
})

$btnCancel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
$btnCancel.Add_Click({ 
    # Close the form without saving - the form closing event will handle unsaved changes confirmation
    $script:form.Close() 
})

# Handle form closing to confirm unsaved changes
$script:form.Add_FormClosing({
    param($sender, $e)
    
    # Determine if any changes were made
    if ($txtSourcePath.Text -ne $config.SourcePath -or
        $txtLocalBackupPath.Text -ne $config.LocalBackupPath -or
        $chkEnableUSB.Checked -ne $config.EnableUSBBackup -or
        $txtUSBDriveLetter.Text -ne $config.USBDriveLetter -or
        $txtUSBBackupPath.Text -ne $config.USBBackupPath -or
        $txtUSBDriveLabel.Text -ne $config.USBDriveLabel -or
        $chkEnableBitLocker.Checked -ne $config.EnableBitLocker -or
        $chkBitLockerUSB.Checked -ne $config.BitLockerUSB -or
        $chkEnableUSBPrune.Checked -ne $config.EnableUSBPrune -or
        $txtBitLockerKeyPath.Text -ne $config.BitLockerKeyPath -or
        $numBackupInterval.Value -ne $config.BackupIntervalHours -or
        [int]$numRetentionDays.Value -ne $config.RetentionDays -or
        [int]$numRetentionWeeks.Value -ne $config.RetentionWeeks -or
        [int]$numRetentionMonths.Value -ne $config.RetentionMonths -or
        ([int]$cmbLogLevel.SelectedIndex + 1) -ne $config.LogLevel -or
        $chkAutoLock.Checked -ne $config.AutoLockAfterBackup) {
        
        # Changes detected, ask for confirmation
        if ($sender -eq $btnSave) {
            # If save button was clicked, don't show confirmation
            return
        }
        
        $result = [System.Windows.Forms.MessageBox]::Show(
            "You have unsaved changes. Are you sure you want to close without saving?",
            "Unsaved Changes",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        
        if ($result -eq [System.Windows.Forms.DialogResult]::No) {
            $e.Cancel = $true  # Prevent form from closing
        }
    }
})

# Handle Escape key to close the form
$script:form.KeyPreview = $true
$script:form.Add_KeyDown({
    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
        $script:form.Close()
    }
})

# Add tooltips to controls
# General Tab Tooltips
Add-ToolTip -Control $txtSourcePath -Text "The full path to your KeePass database file (.kdbx) that will be backed up."
Add-ToolTip -Control $btnBrowseSource -Text "Browse your computer for the KeePass database file."
Add-ToolTip -Control $txtLocalBackupPath -Text "The folder where local backups will be stored. Ensure you have write permissions to this location."
Add-ToolTip -Control $btnBrowseBackup -Text "Browse your computer for the local backup folder."
Add-ToolTip -Control $numBackupInterval -Text "How often the service will create backups, in hours. Lower values mean more frequent backups."
Add-ToolTip -Control $cmbLogLevel -Text "Controls how much detail is included in logs. Higher levels include more information but create larger log files."
Add-ToolTip -Control $txtConfigPath -Text "Location of the configuration file. This is where your settings will be saved."

# USB Backup Tab Tooltips
Add-ToolTip -Control $chkEnableUSB -Text "Enable to create backup copies on compatible USB drives in addition to local backups."
Add-ToolTip -Control $txtUSBDriveLetter -Text "Specify a particular USB drive letter (e.g., 'E'). Leave empty to automatically detect drives based on label."
Add-ToolTip -Control $txtUSBDriveLabel -Text "The volume name of the USB drive to identify. Only drives with this label will be used for backups."
Add-ToolTip -Control $txtUSBBackupPath -Text "The folder on the USB drive where backups will be stored. Will be created if it doesn't exist."
Add-ToolTip -Control $chkEnableUSBPrune -Text "When enabled, the retention policy will also apply to USB backups. Otherwise, USB backups are kept indefinitely."

# BitLocker Tab Tooltips
Add-ToolTip -Control $chkEnableBitLocker -Text "Enable BitLocker encryption support for securing backup drives."
Add-ToolTip -Control $chkBitLockerUSB -Text "When enabled, USB drives will be encrypted with BitLocker before backing up data to them."
Add-ToolTip -Control $chkAutoLock -Text "Automatically lock BitLocker-protected drives after backup is complete for improved security."
Add-ToolTip -Control $txtBitLockerKeyPath -Text "The folder where BitLocker recovery keys will be stored. Keep this location secure!"
Add-ToolTip -Control $btnBrowseBitLockerPath -Text "Browse your computer for the BitLocker keys folder."

# Retention Policy Tab Tooltips
Add-ToolTip -Control $numRetentionDays -Text "Number of days to keep all backups. All backups within this period will be preserved."
Add-ToolTip -Control $numRetentionWeeks -Text "After the daily retention period, only one backup per week will be kept for this many weeks."
Add-ToolTip -Control $numRetentionMonths -Text "After the weekly retention period, only one backup per month will be kept for this many months."
Add-ToolTip -Control $lblRetentionDescription -Text "This tiered retention policy helps manage disk space while maintaining a useful backup history."

# Button Tooltips
Add-ToolTip -Control $btnSave -Text "Save all configuration settings and close this window."
Add-ToolTip -Control $btnCancel -Text "Close without saving any changes."
Add-ToolTip -Control $btnReset -Text "Reset all settings to their default values."
Add-ToolTip -Control $btnTest -Text "Test configuration settings by verifying paths and permissions."

# Add form controls
$script:form.Controls.Add($tabControl)
$script:form.Controls.Add($btnReset)
$script:form.Controls.Add($btnTest)
$script:form.Controls.Add($btnSave)
$script:form.Controls.Add($btnCancel)
$script:form.Controls.Add($statusStrip)

# Display initial status message
Update-StatusMessage -Message "Ready to configure KeePass Backup Service." -Type Info

# Show the form
$script:form.Add_Shown({$script:form.Activate()})
[void]$script:form.ShowDialog() 