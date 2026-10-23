$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Get-Command py -ErrorAction SilentlyContinue
if ($python) {
    Start-Process -FilePath $python.Source -ArgumentList @('-3.13', 'control.py') -WorkingDirectory $root -WindowStyle Hidden
} else {
    throw '找不到 Python 3。请安装 Python 后重试。'
}
Start-Sleep -Milliseconds 700
Start-Process 'http://127.0.0.1:8765'
