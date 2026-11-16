$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\pyinstaller.exe")) {
    & ".venv\Scripts\python.exe" -m pip install "pyinstaller>=6.0,<7"
}

& ".venv\Scripts\pyinstaller.exe" `
    --noconfirm `
    --clean `
    --name SSHGuard `
    --console `
    --paths . `
    sshguard\__main__.py

Write-Host "Built dist\SSHGuard\SSHGuard.exe"

& ".venv\Scripts\pyinstaller.exe" `
    --noconfirm `
    --clean `
    --name SSHGuardGUI `
    --windowed `
    --paths . `
    gui_entry.py

Write-Host "Built dist\SSHGuardGUI\SSHGuardGUI.exe"
