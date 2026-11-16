# SSH Guard

SSH Guard is a defensive, host-local security monitor for Windows. It is designed to help the owner of a laptop understand suspicious files and activity without probing or modifying other machines.

## Status

The first milestone provides:

- Recursive `scan` mode for local files and folders.
- Risk scoring for hidden files, double extensions, executable/script files in common user/temp locations, selected suspicious script indicators, high entropy, and local SHA-256 blocklists.
- `watch` mode using `watchdog` for newly created or modified files.
- Live `dashboard` mode showing every file, severity, score, and detection reason.
- Single-pass file hashing/sample reads for better performance on large folders.

The process, connection, persistence, and live multi-source dashboard modules will be added in later testable milestones.

The Windows desktop GUI is now available with scan choices, a progress bar, a 100/100 local privacy score, and a results table containing every file and detection explanation.

The GUI also supports filtering to risk files, selecting findings, and moving selected files into a local quarantine. Quarantined files are retained for 15 days; a reminder appears 7 days before expiry, and permanent deletion always requires confirmation.

Use **Live system activity** to view running processes, listening ports, and active local connections. The view refreshes every two seconds, identifies the owning process when Windows permits it, and clearly reports unavailable data. It does not probe remote systems or change connections.

Scan results can be exported from the GUI as JSON or CSV for later review or incident notes.

The application is organized into four tabs:

- **Dashboard**: privacy score and scan summary.
- **Scan files**: quick/custom scans, progress, filters, and export.
- **Live activity**: processes sorted by RAM with CPU/RAM values, ports, and connections.
- **Quarantine**: review retained files and restore them to their original locations.

The scanner streams directories with `os.scandir`, skips symbolic links, handles inaccessible folders safely, and avoids building a full in-memory file list before scanning.

## Setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Usage

```powershell
python -m sshguard.cli scan "$env:USERPROFILE\Downloads"
python -m sshguard.cli dashboard "$env:USERPROFILE\Downloads"
python -m sshguard dashboard "$env:USERPROFILE\Downloads"
python -m sshguard.cli watch "$env:USERPROFILE\Downloads"
```

The dashboard keeps every scanned file in the table, including clean and unreadable files. Use `Ctrl+C` to stop safely. To build a Windows console executable:

```powershell
.\build_exe.ps1
.\dist\SSHGuard\SSHGuard.exe dashboard "$env:USERPROFILE\Downloads"
.\dist\SSHGuardGUI\SSHGuardGUI.exe
```

`SSHGuardGUI.exe` is the application-style interface. `SSHGuard.exe` remains the terminal interface.

Use only on systems and files you own or are authorized to inspect. Scanning does not delete or quarantine anything.

## Limitations

This milestone does not claim that a file is malware. Indicators are heuristic and can produce false positives. Some files may be inaccessible without Administrator privileges; those are reported as unreadable. No remote port probing, exploit behavior, credential collection, or automatic response action is included.
