param(
    [ValidateRange(1024,65535)][int]$Port = 8001,
    [string]$PythonExecutable,
    [switch]$InstallDependencies,
    [switch]$Server
)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    $appPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    $newEnvironment = -not (Test-Path -LiteralPath $appPython)
    if ($newEnvironment) {
        if ($PythonExecutable) {
            $hostPython = $PythonExecutable
            $hostArguments = @()
        } elseif (Get-Command py.exe -ErrorAction SilentlyContinue) {
            $hostPython = 'py.exe'
            $hostArguments = @('-3')
        } elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
            $hostPython = 'python.exe'
            $hostArguments = @()
        } else {
            throw 'Install Python 3.11 or later, or pass -PythonExecutable with its full path.'
        }
        & $hostPython @hostArguments -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
        if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or later is required. Select it with -PythonExecutable.' }
        & $hostPython @hostArguments -m venv .venv
        if ($LASTEXITCODE -ne 0) { throw 'Python could not create the local NetGuard environment.' }
    }
    & $appPython -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
    if ($LASTEXITCODE -ne 0) { throw 'This .venv uses Python older than 3.11. Rename it and rerun with a supported -PythonExecutable.' }
    # Windows PowerShell 5.1 strips double quotes from native arguments, so the Python snippets use single quotes.
    $requirementsHash = & $appPython -c 'import hashlib; from pathlib import Path; print(hashlib.sha256(Path(''requirements.txt'').read_bytes()).hexdigest())'
    if ($LASTEXITCODE -ne 0 -or -not $requirementsHash) { throw 'Could not read requirements.txt.' }
    $installedHashPath = Join-Path $PSScriptRoot '.venv\.netguard-requirements.sha256'
    # An empty hash file reads as $null, which has no Trim() method.
    $installedRaw = if (Test-Path -LiteralPath $installedHashPath) { Get-Content -LiteralPath $installedHashPath -Raw } else { $null }
    $installedHash = if ($installedRaw) { $installedRaw.Trim() } else { '' }
    & $appPython -c 'import importlib.util, sys; sys.exit(0 if all(importlib.util.find_spec(p) for p in (''fastapi'', ''uvicorn'', ''sqlalchemy'', ''pydantic'', ''cryptography'', ''netmiko'', ''pysnmp'', ''webview'', ''reportlab'', ''netaddr'')) else 1)'
    $missingDependencies = $LASTEXITCODE -ne 0
    if ($newEnvironment -or $InstallDependencies -or $missingDependencies -or $installedHash -ne $requirementsHash) {
        & $appPython -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'Dependency setup failed. Check the connection, then rerun with -InstallDependencies.' }
        Set-Content -LiteralPath $installedHashPath -Value $requirementsHash -Encoding ascii
    }
    if ($Server) {
        & $appPython netguard.py --server --port $Port
    } else {
        Write-Host 'Starting the NetGuard desktop application. First sign-in: admin / admin (change it in Settings).'
        & $appPython netguard.py --port $Port
    }
    if ($LASTEXITCODE -ne 0) { throw 'NetGuard could not start. See the message above.' }
} finally {
    Pop-Location
}
