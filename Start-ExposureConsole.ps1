[CmdletBinding()]
param([switch]$NoBrowser)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$url = 'http://127.0.0.1:8765/'

function Test-ConsoleReady {
    $response = $null
    try {
        # Loopback requests must bypass system and environment proxies.
        $request = [System.Net.WebRequest]::Create($url)
        $request.Proxy = $null
        $request.Timeout = 1000
        $request.ReadWriteTimeout = 1000
        $response = $request.GetResponse()
        return ($response.StatusCode -eq 200 -and
            $response.Headers['Server'] -like 'ExposureConsole/*')
    } catch {
        return $false
    } finally {
        if ($response) { $response.Close() }
    }
}

if (Test-ConsoleReady) {
    Write-Host "Console is already running: $url"
    if (-not $NoBrowser) { Start-Process $url }
    return
}

# Resolve an actual interpreter, rather than assuming py.exe has Python 3.13.
$python = $null
$probe = 'import sys; sys.exit(1) if not ((3, 11) <= sys.version_info < (4,)) else print(sys.executable)'
foreach ($name in @('py', 'python', 'python3')) {
    $probeArgs = @('-c', $probe)
    if ($name -eq 'py') { $probeArgs = @('-3') + $probeArgs }
    foreach ($command in @(Get-Command $name -CommandType Application -ErrorAction SilentlyContinue)) {
        try {
            $output = @(& $command.Source @probeArgs 2>$null)
            if ($LASTEXITCODE -eq 0 -and $output.Count -eq 1 -and
                (Test-Path -LiteralPath $output[0] -PathType Leaf)) {
                $python = [string]$output[0]
                break
            }
        } catch {
            # A missing runtime or a broken launcher should allow the next candidate.
        }
    }
    if ($python) { break }
}
if (-not $python) {
    throw 'Python 3.11 or newer was not found. Install Python, then run this script again. Use py -0p to list installed runtimes.'
}

$dataRoot = $env:LOCALAPPDATA
if (-not $dataRoot) { $dataRoot = [Environment]::GetFolderPath('LocalApplicationData') }
$logDir = Join-Path $dataRoot 'ExposureConsole\control'
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stdout = Join-Path $logDir 'console.stdout.log'
$stderr = Join-Path $logDir 'console.stderr.log'
Write-Host "Starting console with $python"
$process = Start-Process -FilePath $python -ArgumentList @('-X', 'utf8', '-u', 'control.py') `
    -WorkingDirectory $root -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr
# Keep the handle open so Windows PowerShell 5.1 can read an exited child's code.
$null = $process.Handle

$timer = [Diagnostics.Stopwatch]::StartNew()
while ($timer.Elapsed.TotalSeconds -lt 20) {
    if ($process.HasExited) {
        $process.WaitForExit()
        $detail = Get-Content -LiteralPath $stderr -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        throw "Console exited with code $($process.ExitCode).`n$detail`nStartup logs: $stdout ; $stderr"
    }
    if (Test-ConsoleReady) {
        Write-Host "Console is ready: $url"
        if (-not $NoBrowser) { Start-Process $url }
        return
    }
    Start-Sleep -Milliseconds 200
}
throw "Console did not become ready within 20 seconds. Startup logs: $stdout ; $stderr"
