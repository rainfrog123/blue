# Huaxi Stomatology monitor — foreground launcher (Windows)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if ($env:HXKQ_PYTHON) {
    $Python = $env:HXKQ_PYTHON
} else {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { $Python = $cmd.Source } else { $Python = "python" }
}

Write-Host "Starting hxkq with $Python" -ForegroundColor Cyan
& $Python main.py @args
