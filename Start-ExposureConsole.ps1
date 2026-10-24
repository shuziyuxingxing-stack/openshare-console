$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Get-Command py -ErrorAction SilentlyContinue
if ($python) {
    Start-Process -FilePath $python.Source -ArgumentList @('-3.13', 'control.py') -WorkingDirectory $root -WindowStyle Hidden
} else {
    throw 'Python 3.13 was not found. Install Python 3.13, then run this script again.'
}
Start-Sleep -Milliseconds 700
Start-Process 'http://127.0.0.1:8765'
