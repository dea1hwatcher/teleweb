# TeleWEB Universal Multi-Platform Build Script
# Builds all 14 release targets in one run:
# 1. Android Magisk/KernelSU/APatch Multi-Arch Module (ARM64, ARM, x86, x86_64)
# 2. Windows Desktop (amd64, 386, arm64) standalone executables & archives
# 3. Linux Desktop (amd64, arm64) archives with installers
param(
    [switch]$SkipAndroid = $false,
    [switch]$SkipDesktop = $false
)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $RootDir "src"
$BinDir = Join-Path $RootDir "bin"
$DistDir = Join-Path $RootDir "dist"

# Terminate any running local development instances of tgws before building
Get-Process -Name "tgws*", "teleweb*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 1. Locate Go compiler
$GoPath = "go"
if (Test-Path "C:\Program Files\Go\bin\go.exe") {
    $GoPath = "C:\Program Files\Go\bin\go.exe"
} else {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) {
        $GoPath = $cmd.Source
    } else {
        Write-Error "Go compiler not found in PATH or standard locations."
    }
}

# 2. Locate Python interpreter
$PythonCmd = "python"
if (-not (Get-Command $PythonCmd -ErrorAction SilentlyContinue)) {
    $pyCandidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python314\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "C:\Program Files\Python314\python.exe",
        "C:\Program Files\Python313\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\WorkBuddyAI\resources\vendor\python\python.exe"
    )
    foreach ($c in $pyCandidates) {
        if (Test-Path $c) { $PythonCmd = $c; break }
    }
}

# 3. Resolve Current Version from module.prop
$Version = "v0.2.2"
$ModulePropPath = Join-Path $RootDir "module.prop"
if (Test-Path $ModulePropPath) {
    Get-Content $ModulePropPath | ForEach-Object {
        if ($_ -match '^\s*version\s*=\s*(.+)$') {
            $raw = $matches[1].Trim()
            if ($raw -notmatch '^v') { $raw = "v$raw" }
            $Version = $raw
        }
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " TeleWEB Universal Multi-Platform Build: $Version" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Go compiler:   $GoPath"
Write-Host " Python:        $PythonCmd"
Write-Host " Output root:   $DistDir"
Write-Host ""

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

Add-Type -AssemblyName System.IO.Compression

# Helper: safe copy with retry (handles transient AV/Defender file locks)
function Safe-Copy([string]$src, [string]$dst) {
    for ($i = 0; $i -lt 5; $i++) {
        try {
            Copy-Item $src $dst -Force -ErrorAction Stop
            return
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    Copy-Item $src $dst -Force
}

# Helper: zip directory with forward slashes
function Pack-Zip([string]$sourceDir, [string]$zipFile) {
    if (Test-Path $zipFile) { Remove-Item $zipFile -Force }
    $zipStream = [System.IO.File]::Create($zipFile)
    $archive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in Get-ChildItem $sourceDir -Recurse -File) {
            $rel = $f.FullName.Substring($sourceDir.Length + 1).Replace('\', '/')
            $entry = $archive.CreateEntry($rel, [System.IO.Compression.CompressionLevel]::Optimal)
            $es = $entry.Open()
            $fs = [System.IO.File]::OpenRead($f.FullName)
            try { $fs.CopyTo($es) } finally { $fs.Dispose(); $es.Dispose() }
        }
    } finally {
        $archive.Dispose()
        $zipStream.Dispose()
    }
}

$tarExe = if ($env:SystemRoot) { Join-Path $env:SystemRoot "System32\tar.exe" } else { "tar" }
$hasTar = [bool](Get-Command $tarExe -ErrorAction SilentlyContinue)

# ==============================================================================
# PHASE 1: Android Magisk/KernelSU/APatch Multi-Arch Module
# ==============================================================================
if (-not $SkipAndroid) {
    Write-Host "`n>>> [1/3] Building Android Multi-Arch Module ($Version)..." -ForegroundColor Yellow

    $AndroidTargets = @(
        @{ Arch = "arm64";  GOOS = "linux"; GOARCH = "arm64"; GOARM = "";  OutDir = "$BinDir\arm64"  },
        @{ Arch = "arm";    GOOS = "linux"; GOARCH = "arm";   GOARM = "7"; OutDir = "$BinDir\arm"    },
        @{ Arch = "x86";    GOOS = "linux"; GOARCH = "386";   GOARM = "";  OutDir = "$BinDir\x86"    },
        @{ Arch = "x86_64"; GOOS = "linux"; GOARCH = "amd64"; GOARM = "";  OutDir = "$BinDir\x86_64" }
    )

    foreach ($target in $AndroidTargets) {
        $archName = $target.Arch
        Write-Host "  * Compiling Android binary for $archName (GOOS=$($target.GOOS), GOARCH=$($target.GOARCH)$(if($target.GOARM){", GOARM=" + $target.GOARM}))..." -NoNewline

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
            if ($LASTEXITCODE -ne 0) { throw "Android build failed for $archName" }
            $fi = Get-Item $outBin
            Write-Host " [OK] ($([math]::Round($fi.Length / 1MB, 2)) MB)" -ForegroundColor Green
        } finally {
            Pop-Location
        }
    }

    # Package module archive via package_zip.py
    $PackScript = Join-Path $RootDir "package_zip.py"
    if (Test-Path $PackScript) {
        Write-Host "  * Packaging module ZIP via package_zip.py..." -ForegroundColor Cyan
        & $PythonCmd $PackScript --skip-build
        if ($LASTEXITCODE -ne 0) { throw "Failed to package module zip" }

        # Stage archive to $DistDir
        $expectedZipName = "teleweb-$Version-multiarch.zip"
        $rootZip = Join-Path $RootDir $expectedZipName
        if (Test-Path $rootZip) {
            Safe-Copy $rootZip (Join-Path $DistDir $expectedZipName)
            Write-Host "  [OK] Staged $expectedZipName to $DistDir" -ForegroundColor Green
        }
    }
}

# ==============================================================================
# PHASE 2: Windows Desktop Packages (amd64, 386, arm64)
# ==============================================================================
if (-not $SkipDesktop) {
    Write-Host "`n>>> [2/3] Building Windows Desktop Packages..." -ForegroundColor Yellow

    if (Test-Path "$RootDir\icon.png") {
        Copy-Item "$RootDir\icon.png" "$SrcDir\app_icon.png" -Force
    }

    $winTargets = @(
        @{ Arch = "amd64"; Driver = $true },
        @{ Arch = "386";   Driver = $true },
        @{ Arch = "arm64"; Driver = $false }
    )

    foreach ($t in $winTargets) {
        $arch = $t.Arch
        Write-Host "  * Compiling Windows $arch (nativegui)..." -NoNewline
        $dir = Join-Path $DistDir "teleweb-windows-$arch"
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null

        $env:CGO_ENABLED = "0"
        $env:GOOS = "windows"
        $env:GOARCH = $arch
        Remove-Item Env:\GOARM -ErrorAction SilentlyContinue

        $outExe = Join-Path $dir "tgws.exe"
        Push-Location $SrcDir
        try {
            & $GoPath build -trimpath -ldflags="-s -w -H=windowsgui" -tags nativegui -o $outExe .
            if ($LASTEXITCODE -ne 0) { throw "Windows build failed for $arch" }
            $fi = Get-Item $outExe
            Write-Host " [OK] ($([math]::Round($fi.Length / 1MB, 2)) MB)" -ForegroundColor Green
        } finally {
            Pop-Location
        }

        if ($t.Driver) {
            Copy-Item (Join-Path $SrcDir "drivers\$arch\*") $dir -Force
            Copy-Item (Join-Path $SrcDir "drivers\LICENSE") (Join-Path $dir "WinDivert-LICENSE.txt") -Force
        }
        Copy-Item (Join-Path $RootDir "desktop\windows\install.ps1") $dir -Force

        # Single-file exe asset
        $singleExe = Join-Path $DistDir "tgws-windows-$arch.exe"
        Safe-Copy $outExe $singleExe

        # Archives
        $zip = "$dir.zip"
        Pack-Zip $dir $zip
        if ($hasTar) {
            $tgz = "$dir.tar.gz"
            if (Test-Path $tgz) { Remove-Item $tgz -Force }
            & $tarExe -czf $tgz -C $DistDir "teleweb-windows-$arch"
        }
        Write-Host "  [OK] Packed teleweb-windows-$arch (.zip / .tar.gz)" -ForegroundColor Green
    }

    # ==============================================================================
    # PHASE 3: Linux Desktop Packages (amd64, arm64)
    # ==============================================================================
    Write-Host "`n>>> [3/3] Building Linux Desktop Packages..." -ForegroundColor Yellow

    foreach ($arch in @("amd64", "arm64")) {
        Write-Host "  * Compiling Linux $arch..." -NoNewline
        $dir = Join-Path $DistDir "teleweb-linux-$arch"
        if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null

        $env:CGO_ENABLED = "0"
        $env:GOOS = "linux"
        $env:GOARCH = $arch
        Remove-Item Env:\GOARM -ErrorAction SilentlyContinue

        $outBin = Join-Path $dir "tgws"
        Push-Location $SrcDir
        try {
            & $GoPath build -trimpath -ldflags="-s -w" -o $outBin .
            if ($LASTEXITCODE -ne 0) { throw "Linux build failed for $arch" }
            $fi = Get-Item $outBin
            Write-Host " [OK] ($([math]::Round($fi.Length / 1MB, 2)) MB)" -ForegroundColor Green
        } finally {
            Pop-Location
        }

        Copy-Item (Join-Path $RootDir "desktop\linux\install.sh") $dir -Force
        Copy-Item (Join-Path $RootDir "desktop\linux\uninstall.sh") $dir -Force

        # Archives
        $zip = "$dir.zip"
        Pack-Zip $dir $zip
        if ($hasTar) {
            $tgz = "$dir.tar.gz"
            if (Test-Path $tgz) { Remove-Item $tgz -Force }
            & $tarExe -czf $tgz -C $DistDir "teleweb-linux-$arch"
        }
        Write-Host "  [OK] Packed teleweb-linux-$arch (.zip / .tar.gz)" -ForegroundColor Green
    }
}

# ==============================================================================
# PHASE 4: Verification & Asset Accounting
# ==============================================================================
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Release Asset Verification (dist/)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$assets = Get-ChildItem $DistDir -File | Where-Object {
    $_.Name -match '\.(zip|tar\.gz|exe)$'
} | Sort-Object Name

foreach ($a in $assets) {
    $sizeMB = [math]::Round($a.Length / 1MB, 2)
    Write-Host ("  {0,-38} {1,8} MB" -f $a.Name, $sizeMB) -ForegroundColor Green
}

Write-Host "------------------------------------------------------------"
Write-Host " Total release assets in dist/: $($assets.Count)" -ForegroundColor Cyan
if ($assets.Count -ge 14) {
    Write-Host " [SUCCESS] Full set of 14 release assets assembled successfully!" -ForegroundColor Green
} else {
    Write-Warning " Found $($assets.Count) assets (expected 14). Please review the build log."
}
