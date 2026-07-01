#Requires -Version 5.0
<#
.SYNOPSIS
    DEVOPS_driver — Setup Wizard & Launcher
.DESCRIPTION
    From fresh git clone to running GUI:
    1. Check Python 3.10+ and Node.js
    2. Install Python & OVOIDA dependencies
    3. Interactive API key configuration
    4. Launch GUI (launcher.py)
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"
$PROJECT_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  DEVOPS_driver — Setup Wizard" -ForegroundColor Cyan
    Write-Host "  Windows Kernel Driver BYOVD Analysis Platform" -ForegroundColor DarkCyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Msg)
    Write-Host " [*] $Msg" -ForegroundColor Yellow
}

function Write-Ok {
    param([string]$Msg)
    Write-Host " [OK] $Msg" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Msg)
    Write-Host " [!!] $Msg" -ForegroundColor Red
}

# ─── Step 1: Check Python ───────────────────────────────────────────────────
function Test-Python {
    Write-Step "Checking Python..."
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) {
        Write-Fail "Python not found."
        Write-Host "     Please install Python 3.10+ from https://www.python.org/downloads/" -ForegroundColor White
        Write-Host "     Make sure to check 'Add Python to PATH' during installation." -ForegroundColor White
        exit 1
    }
    $verStr = & python --version 2>&1
    if ($verStr -match '(\d+)\.(\d+)') {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
            Write-Fail "Python $verStr found, but 3.10+ is required."
            Write-Host "     Please upgrade Python to 3.10 or later." -ForegroundColor White
            exit 1
        }
        Write-Ok "Python $verStr"
    } else {
        Write-Fail "Unable to parse Python version."
        exit 1
    }
}

# ─── Step 2: Check Node.js ──────────────────────────────────────────────────
function Test-Node {
    Write-Step "Checking Node.js..."
    $node = Get-Command node -ErrorAction SilentlyContinue
    if (-not $node) {
        Write-Fail "Node.js not found."
        Write-Host "     Please install Node.js from https://nodejs.org/" -ForegroundColor White
        Write-Host "     LTS version recommended." -ForegroundColor White
        exit 1
    }
    $verStr = & node --version 2>&1
    Write-Ok "Node.js $verStr"
}

# ─── Step 3: Install Python dependencies ────────────────────────────────────
function Install-PythonDeps {
    Write-Step "Installing Python dependencies (pip install -e .)..."
    Push-Location $PROJECT_ROOT
    try {
        & python -m pip install -e . 2>&1 | Out-String | Write-Verbose
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "pip install failed. Check output above for details."
            exit 1
        }
        Write-Ok "Python dependencies installed."
    }
    finally {
        Pop-Location
    }
}

# ─── Step 4: Install OVOIDA dependencies + build ────────────────────────────
function Install-Ovoida {
    $ovoidaDir = Join-Path $PROJECT_ROOT "components\ovoida"
    if (-not (Test-Path $ovoidaDir)) {
        Write-Fail "OVOIDA directory not found: $ovoidaDir"
        exit 1
    }

    Write-Step "Installing OVOIDA dependencies (npm install)..."
    Push-Location $ovoidaDir
    try {
        & npm install 2>&1 | Out-String | Write-Verbose
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "npm install failed."
            exit 1
        }
        Write-Ok "OVOIDA npm packages installed."

        Write-Step "Building OVOIDA (npm run build)..."
        & npm run build 2>&1 | Out-String | Write-Verbose
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "npm run build failed."
            exit 1
        }
        Write-Ok "OVOIDA built successfully."
    }
    finally {
        Pop-Location
    }
}

# ─── Step 5: Validate OVOIDA binary ─────────────────────────────────────────
function Test-OvoidaBinary {
    $bin = Join-Path $PROJECT_ROOT "components\ovoida\dist\bin\ovogogogo.js"
    if (-not (Test-Path $bin)) {
        Write-Fail "OVOIDA binary not found: $bin"
        Write-Host "     Build may have failed. Run manually: cd components\ovoida && npm run build" -ForegroundColor White
        exit 1
    }
    Write-Ok "OVOIDA binary ready: $bin"
}

# ─── Step 6: API Key Configuration ──────────────────────────────────────────
function Mask-Key {
    param([string]$Key)
    if ($Key.Length -gt 8) {
        return $Key.Substring(0, 4) + "..." + $Key.Substring($Key.Length - 4)
    }
    return "***"
}

function Configure-ApiKey {
    $configDir = Join-Path $env:USERPROFILE ".devops_driver"
    $configPath = Join-Path $configDir "config.json"

    if (Test-Path $configPath) {
        $cfg = Get-Content $configPath -Raw | ConvertFrom-Json
        $url = $cfg.ov_api_url
        $mask = Mask-Key $cfg.ov_api_key
        Write-Ok "API config found: $url | Key: $mask"
        $answer = Read-Host "Modify API config? (y/N)"
        if ($answer -ne "y" -and $answer -ne "Y") {
            return
        }
    } else {
        Write-Step "No API configuration found. Setup wizard:"
        if (-not (Test-Path $configDir)) {
            New-Item -ItemType Directory -Path $configDir | Out-Null
        }
    }

    Write-Host ""
    Write-Host "  API Endpoint URL (default: https://api.deepseek.com/v1):" -ForegroundColor White
    $url = Read-Host "  "
    if ([string]::IsNullOrWhiteSpace($url)) {
        $url = "https://api.deepseek.com/v1"
    }

    Write-Host ""
    Write-Host "  API Key (input will be hidden):" -ForegroundColor White
    $sec = Read-Host "  " -AsSecureString
    $key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))

    if ([string]::IsNullOrWhiteSpace($key)) {
        Write-Fail "API Key cannot be empty."
        exit 1
    }

    Write-Host ""
    Write-Host "  Model name (default: deepseek-chat):" -ForegroundColor White
    $model = Read-Host "  "
    if ([string]::IsNullOrWhiteSpace($model)) {
        $model = "deepseek-chat"
    }

    $json = @{
        ov_api_url  = $url
        ov_api_key  = $key
        ov_model    = $model
    } | ConvertTo-Json -Depth 3

    $json | Out-File -FilePath $configPath -Encoding utf8
    Write-Ok "API config saved to $configPath"
}

# ─── Step 7: Launch GUI ─────────────────────────────────────────────────────
function Launch-Gui {
    Write-Step "Launching GUI..."
    Push-Location $PROJECT_ROOT
    try {
        & python launcher.py
    }
    finally {
        Pop-Location
    }
}

# ─── Main ───────────────────────────────────────────────────────────────────
Write-Banner
Test-Python
Test-Node
Install-PythonDeps
Install-Ovoida
Test-OvoidaBinary
Configure-ApiKey
Write-Host ""
Launch-Gui
