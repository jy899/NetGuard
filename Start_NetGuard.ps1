param(
    [ValidateRange(1024,65535)][int]$Port = 8001,
    [string]$PythonExecutable,
    [switch]$InstallDependencies,
    [switch]$Server
)
$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    $venv = Join-Path $PSScriptRoot '.venv'
    $appPython = Join-Path $venv 'Scripts\python.exe'

    function Find-HostPython {
        if ($PythonExecutable) { return ,@($PythonExecutable) }
        if (Get-Command py.exe -ErrorAction SilentlyContinue) { return ,@('py.exe', '-3') }
        if (Get-Command python.exe -ErrorAction SilentlyContinue) { return ,@('python.exe') }
        throw 'Install Python 3.11 or later from python.org (tick "Add python.exe to PATH"), or pass -PythonExecutable with its full path.'
    }

    function New-AppEnvironment {
        $hostCommand = Find-HostPython
        $hostPython = $hostCommand[0]
        $hostArguments = @($hostCommand | Select-Object -Skip 1)
        & $hostPython @hostArguments -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
        if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or later is required. Select it with -PythonExecutable.' }
        if (Test-Path -LiteralPath $venv) {
            # Keep the broken environment aside instead of deleting it.
            $aside = "$venv.broken-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Write-Host "Rebuilding the NetGuard environment (the old one is kept as $(Split-Path -Leaf $aside))."
            Move-Item -LiteralPath $venv -Destination $aside
        }
        & $hostPython @hostArguments -m venv $venv
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $appPython)) { throw 'Python could not create the local NetGuard environment.' }
    }

    # Windows PowerShell 5.1 turns a native program's stderr into a terminating error when output is redirected
    # under ErrorActionPreference Stop, so the quiet checks run with Continue.
    function Invoke-Quiet {
        $ErrorActionPreference = 'Continue'
        & $appPython @args *> $null
        return ($LASTEXITCODE -eq 0)
    }
    function Test-Pip { return (Invoke-Quiet -m pip --version) }

    $newEnvironment = -not (Test-Path -LiteralPath $appPython)
    if (-not $newEnvironment) {
        # A copied or moved .venv can point at a Python that no longer exists.
        if (-not (Invoke-Quiet -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)')) { $newEnvironment = $true }
    }
    if ($newEnvironment) { New-AppEnvironment }

    # pip can be missing (environment created with --without-pip, an interrupted install, a store or embedded Python).
    if (-not (Test-Pip)) {
        Write-Host 'pip is missing from the NetGuard environment; installing it with ensurepip.'
        $null = Invoke-Quiet -m ensurepip --upgrade --default-pip
        if (-not (Test-Pip)) {
            if ($newEnvironment) { throw 'This Python has no pip (ensurepip failed). Install Python from python.org and rerun with -PythonExecutable.' }
            New-AppEnvironment
            $newEnvironment = $true
            if (-not (Test-Pip)) { $null = Invoke-Quiet -m ensurepip --upgrade --default-pip }
            if (-not (Test-Pip)) { throw 'This Python has no pip (ensurepip failed). Install Python from python.org and rerun with -PythonExecutable.' }
        }
    }

    # Windows PowerShell 5.1 strips double quotes from native arguments, so the Python snippets use single quotes.
    $requirementsHash = & $appPython -c 'import hashlib; from pathlib import Path; print(hashlib.sha256(Path(''requirements.txt'').read_bytes()).hexdigest())'
    if ($LASTEXITCODE -ne 0 -or -not $requirementsHash) { throw 'Could not read requirements.txt.' }
    $installedHashPath = Join-Path $venv '.netguard-requirements.sha256'
    # An empty hash file reads as $null, which has no Trim() method.
    $installedRaw = if (Test-Path -LiteralPath $installedHashPath) { Get-Content -LiteralPath $installedHashPath -Raw } else { $null }
    $installedHash = if ($installedRaw) { $installedRaw.Trim() } else { '' }
    & $appPython -c 'import importlib.util, sys; sys.exit(0 if all(importlib.util.find_spec(p) for p in (''fastapi'', ''uvicorn'', ''sqlalchemy'', ''pydantic'', ''cryptography'', ''netmiko'', ''pysnmp'', ''webview'', ''reportlab'', ''netaddr'', ''psutil'')) else 1)'
    $missingDependencies = $LASTEXITCODE -ne 0
    if ($newEnvironment -or $InstallDependencies -or $missingDependencies -or $installedHash -ne $requirementsHash) {
        Write-Host 'Installing NetGuard dependencies (first start needs an internet connection)...'
        & $appPython -m pip install --disable-pip-version-check -r requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'Dependency setup failed. Check the internet connection, then run Start_NetGuard.cmd -InstallDependencies.' }
        Set-Content -LiteralPath $installedHashPath -Value $requirementsHash -Encoding ascii
    }
    if ($Server) {
        & $appPython netguard.py --server --port $Port
    } else {
        Write-Host 'Starting NetGuard. Default NetGuard login: admin / admin'
        & $appPython netguard.py --port $Port
    }
    if ($LASTEXITCODE -ne 0) { throw 'NetGuard could not start. See the message above.' }
} finally {
    Pop-Location
}
