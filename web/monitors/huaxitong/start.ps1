# West China Hospital Appointment Monitor - PowerShell Launch Script

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonPath = "C:\Users\jar71\AppData\Local\Microsoft\WindowsApps\python.exe"

Write-Host "Starting appointment monitor..." -ForegroundColor Cyan

# Kill any existing monitor processes
$existingProcesses = Get-Process -Name python* -ErrorAction SilentlyContinue | 
    Where-Object { $_.CommandLine -like "*main.py*" }

if ($existingProcesses) {
    Write-Host "Stopping existing monitor processes..."
    $existingProcesses | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# Start monitor
Set-Location $ScriptDir
Write-Host "Running: $PythonPath main.py" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ("=" * 60)

& $PythonPath main.py
