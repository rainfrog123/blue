# Huayitong appointment monitor — foreground launcher (Windows)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if ($env:HUAYITONG_PYTHON) {
    $Python = $env:HUAYITONG_PYTHON
} else {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source } else { $Python = "python" }
}

Write-Host "Starting huayitong monitor with $Python" -ForegroundColor Cyan
Write-Host "Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ("=" * 60)

& $Python main.py @args
