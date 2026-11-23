# parrot-mcp Windows installer (PowerShell 5.1+)
# Usage:  .\install.ps1
# If script execution is blocked on your machine:
#         powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# Creates a project venv (.venv) and installs parrot-mcp into it from the
# source folder.

$ErrorActionPreference = "Stop"

function Find-Python {
    foreach ($cmd in @("py", "python", "python3")) {
        if (Get-Command $cmd -ErrorAction SilentlyContinue) { return $cmd }
    }
    Write-Host "ERROR: Python not found. Install Python 3.10+ from https://www.python.org/downloads/" -ForegroundColor Red
    Write-Host "and tick 'Add python.exe to PATH' during setup, then re-run this script." -ForegroundColor Red
    exit 1
}

function Invoke-Python {
    # `py` launcher needs -3 to guarantee Python 3; python/python3 need nothing
    param([string[]]$Arguments)
    if ($script:PyCmd -eq "py") { & py -3 @Arguments }
    else { & $script:PyCmd @Arguments }
}

$PyCmd = Find-Python

Invoke-Python -Arguments @("-c", "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)")
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Python 3.10+ is required (found an older version)." -ForegroundColor Red
    exit 1
}
Write-Host "[1/4] Python 3.10+ found ($PyCmd)" -ForegroundColor Green

Write-Host "[2/4] Creating virtual environment .venv ..."
Invoke-Python -Arguments @("-m", "venv", ".venv")
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: venv creation failed." -ForegroundColor Red; exit 1 }

$pip = ".\.venv\Scripts\pip.exe"
if (-not (Test-Path $pip)) { Write-Host "ERROR: .venv\Scripts\pip.exe not found." -ForegroundColor Red; exit 1 }
& $pip install --upgrade pip -q

Write-Host "[3/4] Installing parrot-mcp from source ..."
& $pip install -q .
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: pip install failed." -ForegroundColor Red; exit 1 }

Write-Host "[4/4] Verifying ..."
$exe = ".\.venv\Scripts\parrot-mcp.exe"
if (-not (Test-Path $exe)) {
    Write-Host "ERROR: install finished but .venv\Scripts\parrot-mcp.exe is missing." -ForegroundColor Red
    exit 1
}
& $exe --version
Write-Host ""
Write-Host "Done. Next steps (PowerShell, from this folder):" -ForegroundColor Cyan
Write-Host '  $env:PARROT_MCP_TARGET = "docker"'
Write-Host '  $env:PARROT_MCP_DOCKER_IMAGE = "parrotsec/security:latest"'
Write-Host '  $env:PARROT_MCP_AUTH_TOKEN = "testtoken"          # only for --transport http'
Write-Host '  .\.venv\Scripts\parrot-mcp.exe --transport http --host 127.0.0.1 --port 8420'
Write-Host ""
Write-Host "Or use Claude Desktop (stdio, no terminal needed): copy" -ForegroundColor Cyan
Write-Host "examples\claude_desktop_windows.json into" -ForegroundColor Cyan
Write-Host "%APPDATA%\Claude\claude_desktop_config.json (fix the command path). See WINDOWS.md." -ForegroundColor Cyan
