# PowerShell Multi-Arch Build Script for TeleWEB
$ErrorActionPreference = "Stop"

$GoPath = "C:\Program Files\Go\bin\go.exe"
if (-not (Test-Path $GoPath)) {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) {
        $GoPath = $cmd.Source
    } else {
        Write-Error "Go compiler not found."
    }
}

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $RootDir "src"
$BinDir = Join-Path $RootDir "bin"

$Targets = @(
    @{ Arch = "arm64";  GOOS = "linux"; GOARCH = "arm64"; GOARM = "";  OutDir = "$BinDir\arm64"  },
    @{ Arch = "arm";    GOOS = "linux"; GOARCH = "arm";   GOARM = "7"; OutDir = "$BinDir\arm"    },
    @{ Arch = "x86";    GOOS = "linux"; GOARCH = "386";   GOARM = "";  OutDir = "$BinDir\x86"    },
    @{ Arch = "x86_64"; GOOS = "linux"; GOARCH = "amd64"; GOARM = "";  OutDir = "$BinDir\x86_64" }
)

Write-Host "Building TeleWEB for all target architectures..." -ForegroundColor Cyan

foreach ($target in $Targets) {
    $archName = $target.Arch
    Write-Host "`n>>> Building for $archName (GOOS=$($target.GOOS), GOARCH=$($target.GOARCH)$(if($target.GOARM){", GOARM=" + $target.GOARM}))" -ForegroundColor Yellow
    
    if (-not (Test-Path $target.OutDir)) {
        New-Item -ItemType Directory -Path $target.OutDir -Force | Out-Null
    }
    
    $outBin = Join-Path $target.OutDir "tgws"
    
    $env:CGO_ENABLED = "0"
    $env:GOOS = $target.GOOS
    $env:GOARCH = $target.GOARCH
    if ($target.GOARM) {
        $env:GOARM = $target.GOARM
    } else {
        Remove-Item Env:\GOARM -ErrorAction SilentlyContinue
    }
    
    Push-Location $SrcDir
    try {
        & $GoPath build -trimpath -ldflags="-s -w" -o $outBin .
        if ($LASTEXITCODE -ne 0) {
            throw "Build failed for $archName"
        }
        $fi = Get-Item $outBin
        Write-Host "  Success: $outBin ($([math]::Round($fi.Length / 1MB, 2)) MB / $($fi.Length) bytes)" -ForegroundColor Green
    }
    finally {
        Pop-Location
    }
}

# Copy arm64 as default bin/tgws
Copy-Item -Path "$BinDir\arm64\tgws" -Destination "$BinDir\tgws" -Force
Write-Host "`nDefault bin\tgws updated from arm64." -ForegroundColor Green
Write-Host "All 4 architectures built successfully!" -ForegroundColor Cyan

# Package Magisk module archive
$PackScript = Join-Path $RootDir "package_zip.py"
if (Test-Path $PackScript) {
    Write-Host "`n>>> Packaging Magisk/KernelSU/APatch module..." -ForegroundColor Yellow
    python $PackScript --skip-build
}

