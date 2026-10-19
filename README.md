# RECOVERat

**RECOVERat** is a free, Windows-focused malware inspection and recovery toolkit designed to help users identify suspicious processes, persistence mechanisms, and system modifications.

RECOVERat combines custom PowerShell diagnostic scripts with Microsoft's Sysinternals utilities to assist with manual malware removal.

The toolkit is particularly useful when dealing with:

- Remote Access Trojans (RATs)
- Cryptocurrency miners
- Information stealers
- Suspicious scheduled tasks
- Malicious Windows services
- Registry-based persistence
- WMI event subscriptions
- Unauthorized startup programs

## Features

### PowerShell Diagnostic Scripts

| Script | Description |
|---|---|
| `SERVICECHECK.ps1` | Inspects Windows services and identifies potentially suspicious executables and configurations. |
| `TASKCHECK.ps1` | Examines scheduled tasks for suspicious commands and persistence mechanisms. |
| `DEFENDERCHECK.ps1` | Inspects Microsoft Defender configuration, security status, and exclusions. |
| `STARTUPCHECK.ps1` | Examines registry startup entries and Windows startup folders. |
| `WMICHECK.ps1` | Identifies WMI event filters, consumers, and bindings that could be used for persistence. |

These scripts are designed primarily for inspection, not automatic malware removal.

**Note:** Some diagnostic operations may require administrator privileges. `STARTUPCHECK.ps1` may temporarily load registry hives during inspection.

### Sysinternals Integration

RECOVERat supports several Microsoft Sysinternals utilities.

| Utility | Purpose |
|---|---|
| Process Explorer | Inspect and manage running processes. |
| Process Monitor | Monitor filesystem, registry, and process activity. |
| Autoruns | Identify applications and services configured to start automatically. |
| TCPView | Inspect active network connections and their associated processes. |
| Handle | Identify open file handles and the processes responsible for them. |
| Sigcheck | Inspect executable signatures and file metadata. |

These utilities are developed and maintained by Microsoft.

## Installation

### Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges for certain diagnostic operations
- Internet connection during initial Sysinternals installation
- USB drive (optional, recommended for portable use)

### Step 1: Download RECOVERat

Clone the repository or download its source code as a ZIP file.

Extract the files into a directory of your choice.

Example:

```text
E:\RECOVERat\
```

### Step 2: Install Sysinternals

Run:

```cmd
install.cmd
```

The installer will:

1. Download the official Microsoft Sysinternals Suite.
2. Extract the utilities into the RECOVERat directory.
3. Verify that the required tools are present.
4. Remove the downloaded ZIP file after successful extraction.

The installer downloads directly from Microsoft's official servers.

**RECOVERat does not redistribute Sysinternals binaries.**

### Step 3: Run Diagnostic Scripts

Open PowerShell as Administrator.

Navigate to your RECOVERat directory:

```powershell
cd E:\RECOVERat
```

Run the desired diagnostic script:

```powershell
.\SERVICECHECK.ps1
.\TASKCHECK.ps1
.\DEFENDERCHECK.ps1
.\STARTUPCHECK.ps1
.\WMICHECK.ps1
```

If script execution is restricted, you can run an individual script using:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\SERVICECHECK.ps1"
```

Only execute scripts you have reviewed and trust.

## Recommended Malware Removal Workflow

RECOVERat is intended for manual inspection and recovery.

### Phase 1: Containment

Disconnect the affected computer from the internet and other networks.

Avoid connecting the infected machine to trusted systems.

### Phase 2: Initial Inspection

Use Autoruns to identify suspicious persistence mechanisms.

Run the RECOVERat diagnostic scripts to inspect:

- Windows services
- Scheduled tasks
- Registry startup entries
- Defender configuration
- WMI event subscriptions

### Phase 3: Process Inspection

Use Process Explorer to identify suspicious processes and inspect their executable locations.

Use TCPView to identify active network connections.

Use Process Monitor when additional behavioral information is required.

### Phase 4: Malware Removal

After confirming an executable or persistence entry is malicious, use appropriate removal procedures.

Do not delete unfamiliar system files or disable services solely because they appear in a diagnostic report.

### Phase 5: Verification

After attempting removal:

1. Run Autoruns again.
2. Check for reappearing persistence entries.
3. Reboot the computer.
4. Repeat the diagnostic checks.
5. Run a reputable antivirus scan, such as Microsoft Defender or Malwarebytes.

A clean scan does not guarantee complete eradication.

For confirmed or suspected deep system compromise, reinstalling Windows from trusted installation media may be necessary.

## Important Security Information

RECOVERat is not an antivirus engine.

It does not provide real-time protection or guarantee successful malware removal.

Its diagnostic scripts may produce false positives because legitimate applications frequently use the same Windows mechanisms as malware.

If an information stealer has executed, previously exposed credentials, browser sessions, or other sensitive information may remain compromised even after removing the malware.

Affected credentials should be changed and sessions revoked from a separate trusted device.

## Privacy

RECOVERat's custom diagnostic scripts are intended to inspect local system configuration.

RECOVERat does not require a user account or a remote management service.

The Sysinternals installer downloads utilities from Microsoft's official distribution servers.

Third-party utilities may have their own network activity, telemetry, licensing terms, or privacy policies.

Review third-party software documentation before use.

## Licensing and Third-Party Software

RECOVERat's original scripts are separate from the third-party utilities it supports.

Microsoft Sysinternals utilities remain the property of Microsoft and are governed by Microsoft's respective license terms.

Official Sysinternals website:

https://learn.microsoft.com/en-us/sysinternals/

Sysinternals licensing information:

https://learn.microsoft.com/en-us/sysinternals/license-faq

RECOVERat does not claim ownership of Microsoft Sysinternals or Malwarebytes software.

A license for RECOVERat's original code should be specified separately in the repository.

## Disclaimer

RECOVERat is provided for legitimate system administration, security diagnostics, and malware recovery.

Use it only on computers you own or have authorization to maintain.

Improper removal of system components can cause instability, data loss, or Windows startup failures.

The project is provided without any guarantee of malware detection, successful removal, or system recovery.

**RECOVERat: Inspect. Identify. Remove. Verify.**
