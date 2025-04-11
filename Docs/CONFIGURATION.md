# Configuration Guide

## Configuration Parameters

The service can be configured through the interactive installer or by editing the config.json file. All parameters can also be managed through the PowerShell configuration module and the GUI tool.

| Parameter | Description | Default | Type |
|-----------|-------------|---------|------|
| SourcePath | Path to your KeePass database file | (Required) | String |
| LocalBackupPath | Local folder to store backups | (Required) | String |
| EnableUSBBackup | Enable backups to USB drives | False | Boolean |
| EnableUSBPrune | Apply retention policy to USB backups | True | Boolean |
| USBDriveLetter | Specific USB drive letter (leave empty to auto-detect) | "" | String |
| USBDriveLabel | USB drive label to look for when auto-detecting | "BACKUP" | String |
| USBBackupPath | Folder on USB drive where backups will be stored | "KeePass_Backups" | String |
| EnableBitLocker | Use BitLocker encryption | False | Boolean |
| BitLockerUSB | Encrypt USB drives with BitLocker | False | Boolean |
| BitLockerKeyPath | Path to store BitLocker recovery keys | "./Data/BitLockerKeys" | String |
| BackupIntervalHours | Hours between backup checks | 24 | Double |
| RetentionDays | Number of days to keep all backups | 7 | Integer |
| RetentionWeeks | Number of weeks to keep weekly backups | 4 | Integer |
| RetentionMonths | Number of months to keep monthly backups | 6 | Integer |
| LogLevel | Log detail level (1=Error, 2=Warning, 3=Info, 4=Debug) | 3 | Integer |
| AutoLockAfterBackup | Lock BitLocker drives after backup | True | Boolean |

## Retention Policy Management

The service implements a tiered retention policy to manage backup storage efficiently:

1. **Daily Backups**: All backups are kept for the number of days specified in `RetentionDays`
2. **Weekly Backups**: After the daily retention period, one backup per week is kept for the number of weeks specified in `RetentionWeeks`
3. **Monthly Backups**: After the weekly retention period, one backup per month is kept for the number of months specified in `RetentionMonths`

### USB Backup Retention

By default, the retention policy is applied only to local backups. However, with the `EnableUSBPrune` parameter, you can extend the same retention policy to USB backups:

- When `EnableUSBPrune` is `true`, the service will apply the retention policy to USB backups using the same rules as local backups
- When `EnableUSBPrune` is `false`, all USB backups are kept indefinitely (or until manually deleted)

This gives you the flexibility to manage storage usage on USB drives, which is particularly important for drives with limited capacity.

## Using PowerShell Module for Configuration

The `KeePassBackupConfigManager.psm1` module provides commands for managing the configuration:

```powershell
# Create a new configuration
New-KeePassBackupConfig -SourcePath "C:\Path\To\KeePass.kdbx" -LocalBackupPath "C:\Backups" -EnableUSBBackup $true -EnableUSBPrune $true

# Get current configuration
$config = Get-KeePassBackupConfig

# Update configuration
Set-KeePassBackupConfig -EnableUSBPrune $false

# Test configuration validity
Test-KeePassBackupConfig
```

## Configuration GUI Tool

The `KeePassBackupConfigGUI.ps1` tool provides a user-friendly interface for managing the service configuration. The interface includes tabs for:

1. **General**: Basic settings including source file and local backup path
2. **USB Backup**: Options for USB backup including the new USB pruning option
3. **BitLocker**: Settings for BitLocker encryption
4. **Retention Policy**: Configure retention periods for backups

To use the GUI tool, run it with administrator privileges:

```powershell
.\Tools\KeePassBackupConfigGUI.ps1
```

## Configuration File Location

The default configuration path depends on the installation method:

1. **Standard Installation**: `C:\Program Files\KeePassBackup\Config\config.json`
2. **Custom Installation**: The path specified during installation
3. **Manual Configuration**: The path provided to the configuration commands

If the configuration file cannot be found, the service will use default values.