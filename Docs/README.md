# KeePass Backup Service

A robust Windows service for automated KeePass database backups with BitLocker encryption and USB drive support.

## Features

- **Automated Backups**: Schedule backups at configurable intervals
- **Multiple Backup Locations**: Back up to both local storage and USB drives
- **BitLocker Integration**: Encrypt USB drives automatically for enhanced security
- **Smart Retention Policy**: Configurable retention for daily, weekly, and monthly backups
- **Retention Management**: Apply retention policies to both local and USB backups independently
- **Secure Logging**: Detailed logs with both file and Windows Event Log support
- **No Hardcoded Credentials**: Security-focused installation with proper credential management
- **Configuration Management**: Flexible JSON-based configuration with both GUI and PowerShell module support
- **OneDrive Support**: Back up KeePass databases stored in OneDrive
- **Auto-Lock**: Automatically lock BitLocker-protected drives after backup completion

## Project Structure

The project follows a modular structure for better maintainability and security:

```
KeePassBackupService/
├── src/                                 # Source code
│   ├── KeePassBackupService.ps1         # Main service entry point
│   └── Core/                           
│       ├── BitLocker.ps1                # BitLocker encryption handling
│       ├── Backup.ps1                   # Backup logic
│       └── Logging.ps1                  # Logging functions
│
├── Modules/
│   └── KeePassBackupConfigManager.psm1  # Configuration management module
│
├── Installer/
│   └── Secure-Install-KeePassBackupService.ps1  # Installation utility
│
├── Config/
│   ├── config.sample.json               # Template configuration file
│   └── config.json                      # Actual configuration (gitignored)
│
├── Tools/
│   └── KeePassBackupConfigGUI.ps1       # GUI configuration tool
│
├── Data/                                # Runtime data (gitignored)
│   ├── Logs/                            # Service logs
│   ├── BitLockerKeys/                   # BitLocker recovery keys
│   └── Backups/                         # Local backup storage
│
├── Docs/
│   ├── README.md                        # This file
│   ├── SECURITY.md                      # Security guidance
│   └── CONFIGURATION.md                 # Configuration reference
│
└── .gitignore                           # Git exclusions
```

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher
- .NET Framework 4.7.2 or higher
- BitLocker (optional, for encryption features)
- NSSM (optional, for enhanced service management - will be auto-downloaded if needed)

## Installation

### Option 1: Using the Secure Installation Script

1. Download the latest release from the GitHub releases page
2. Extract the ZIP file to a temporary location
3. Run the `Installer\Secure-Install-KeePassBackupService.ps1` script with administrator privileges:

```powershell
# Run with GUI credential prompt
.\Installer\Secure-Install-KeePassBackupService.ps1

# Or run with the LocalSystem account (not recommended for production)
.\Installer\Secure-Install-KeePassBackupService.ps1 -UseLocalSystem

# Or specify a credential object
$cred = Get-Credential
.\Installer\Secure-Install-KeePassBackupService.ps1 -Credential $cred
```

### Option 2: Manual Installation

1. Place the project files in a permanent location (e.g., `C:\Program Files\KeePassBackupService`)
2. Import the configuration module:
```powershell
Import-Module .\Modules\KeePassBackupConfigManager.psm1
```
3. Create a configuration file:
```powershell
New-KeePassBackupConfig -SourcePath "C:\Users\Username\OneDrive\KeePass.kdbx" -LocalBackupPath "C:\Program Files\KeePassBackupService\Data\Backups"
```
4. Install the service using NSSM:
```powershell
nssm install KeePassBackupService powershell.exe "-NoProfile -ExecutionPolicy Bypass -File C:\Program Files\KeePassBackupService\src\KeePassBackupService.ps1"
```

## Configuration

The service can be configured through multiple methods:

1. **Configuration GUI**: Use the `Tools\KeePassBackupConfigGUI.ps1` script for a user-friendly interface to manage settings
2. **PowerShell Module**: Use the configuration module for scripted management
3. **Direct Editing**: Edit the `Config\config.json` file manually

### Configuration Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| SourcePath | Path to your KeePass database file | (Required) |
| LocalBackupPath | Local folder to store backups | (Required) |
| EnableUSBBackup | Enable backups to USB drives | True |
| EnableUSBPrune | Apply retention policy to USB backups | True |
| USBDriveLetter | Specific USB drive letter | (Auto-detect) |
| USBDriveLabel | USB drive label to look for | "BACKUP" |
| USBBackupPath | Folder on USB drive | "KeePass_Backups" |
| EnableBitLocker | Use BitLocker encryption | False |
| BitLockerUSB | Encrypt USB drives | False |
| BitLockerKeyPath | Path to store recovery keys | Data\BitLockerKeys |
| BackupIntervalHours | Hours between backups | 24 |
| RetentionDays | Days to keep all backups | 7 |
| RetentionWeeks | Weeks to keep weekly backups | 4 |
| RetentionMonths | Months to keep monthly backups | 6 |
| LogLevel | Log detail level (1-4) | 3 |
| AutoLockAfterBackup | Lock BitLocker drives after backup | True |

### Using the Configuration GUI

The service includes a graphical configuration tool for easier setup:

1. Run `Tools\KeePassBackupConfigGUI.ps1` with administrator privileges
2. Configure all options in the tabbed interface
3. Click "Save" to apply settings

### Updating Configuration via PowerShell

You can update the configuration using the PowerShell module:

```powershell
# Import the module
Import-Module .\Modules\KeePassBackupConfigManager.psm1

# Update specific settings
Set-KeePassBackupConfig -BackupIntervalHours 12 -EnableUSBBackup $true -EnableUSBPrune $true
```

## Retention Policy Management

The service implements a smart retention policy for both local and USB backups:

1. **Local Backups**: Always managed according to the configured retention policy
2. **USB Backups**: Can be managed with the same retention policy settings by enabling the `EnableUSBPrune` parameter

When `EnableUSBPrune` is set to `true`, the same retention rules will be applied to backups on USB drives:
- Keep all backups for `RetentionDays` days
- Keep weekly backups for `RetentionWeeks` weeks
- Keep monthly backups for `RetentionMonths` months

This helps maintain consistent storage usage across all backup locations without requiring manual cleanup.

## BitLocker Integration

When BitLocker integration is enabled, the service can:

1. Check if a drive is already encrypted
2. Generate and store recovery keys securely
3. Unlock encrypted drives using stored recovery keys
4. Automatically lock drives after backup completion (if AutoLockAfterBackup is enabled)

Recovery keys are stored in the configured `BitLockerKeyPath` directory with secure permissions.

### BitLocker Recovery Keys

For each BitLocker-protected drive, create a text file named `RecoveryPassword_X.txt` (where X is the drive letter) in the BitLocker key path containing only the recovery password.

For example, for drive E:
- Create file: `Data\BitLockerKeys\RecoveryPassword_E.txt`
- Content: The 48-digit recovery password (e.g., `123456-789012-345678-901234-567890-123456-789012-345678`)

## OneDrive Integration

The service includes special handling for databases stored in OneDrive:

1. Auto-detection of OneDrive paths
2. Sync status verification before backup
3. Handling of sync conflicts

This ensures reliable backups even when the database is stored in a cloud-synchronized folder.

## Logging

Logs are stored in the `Data\Logs` directory by default. The service provides several logging levels:

- **Level 1**: Errors only
- **Level 2**: Errors and warnings
- **Level 3**: Errors, warnings, and information (default)
- **Level 4**: All messages including debug information

The service logs to both the Windows Event Log and a text file for easier troubleshooting.

## Security Best Practices

### BitLocker Recovery Keys
- **Never hardcode BitLocker recovery passwords** in scripts
- Store recovery keys in a secure location with proper access controls
- Consider using a key management solution for enterprise deployments

### File System Security
- Keep all service files in a protected directory with minimal permissions
- Ensure configuration files are only accessible by the service account and administrators
- Regularly audit file permissions on service files

### Service Account
- Use a dedicated service account with minimal permissions
- Do not use a personal account or an account with administrative privileges
- Regularly rotate the service account password

## Troubleshooting

Check the logs for detailed information about any issues:

- Service logs: `Data\Logs\service.log`
- Installation logs: `%TEMP%\KeePassBackup\Install_[YYYY-MM-DD].log`
- NSSM logs: `Data\Logs\nssm_*.log`
- Windows Event Logs: Look for events with source "KeePassBackupService"

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.