# TeleWEB Windows build script.
# Windows: amd64/386/arm64 — standalone tgws.exe (WinUI 3 GUI + embedded WinDivert driver).
# Produces packages under dist/.
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $RootDir "src"
$DistDir = Join-Path $RootDir "dist"

$GoPath = "go"
if (Test-Path "C:\Program Files\Go\bin\go.exe") { $GoPath = "C:\Program Files\Go\bin\go.exe" }

function Build-Target([string]$goos, [string]$goarch, [string]$outFile, [string]$tags = "") {
    Write-Host ">>> $goos/$goarch -> $outFile" -ForegroundColor Yellow
    $env:CGO_ENABLED = "0"
    $env:GOOS = $goos
    $env:GOARCH = $goarch
    $ldflags = "-s -w"
    if ($goos -eq "windows" -and $tags -match "nativegui") {
        # GUI subsystem: double-clicking opens the window without a console
        # behind it. CLI output still works, because startConsole attaches the
        # process to the console it was launched from.
        $ldflags += " -H=windowsgui"
    }
    $buildArgs = @("build", "-trimpath", "-ldflags", $ldflags)
    if ($tags -ne "") { $buildArgs += @("-tags", $tags) }
    $buildArgs += @("-o", $outFile, ".")
    Push-Location $SrcDir
    & $GoPath @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "build failed for $goos/$goarch" }
    Pop-Location
}

if (Test-Path "$RootDir\icon.png") {
    Copy-Item "$RootDir\icon.png" "$SrcDir\app_icon.png" -Force
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
Get-ChildItem $DistDir -File -Filter "tgws-windows-*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# ---- Windows (standalone exe per architecture) ----
# amd64/386 get transparent mode (embedded WinDivert); arm64 has no WinDivert driver.
$winTargets = @(
    @{ Arch = "amd64"; Driver = $true },
    @{ Arch = "386";   Driver = $true },
    @{ Arch = "arm64"; Driver = $false }
)
foreach ($t in $winTargets) {
    $arch = $t.Arch
    $dir = Join-Path $DistDir "teleweb-windows-$arch"
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Build-Target "windows" $arch (Join-Path $dir "tgws.exe") "nativegui"
    if ($t.Driver) {
        Copy-Item (Join-Path $SrcDir "drivers\$arch\*") $dir -Force
        Copy-Item (Join-Path $SrcDir "drivers\LICENSE") (Join-Path $dir "WinDivert-LICENSE.txt") -Force
    }
    Copy-Item (Join-Path $RootDir "desktop\windows\install.ps1") $dir -Force
    # Single-file exe asset: driver is embedded in the binary.
    Copy-Item (Join-Path $dir "tgws.exe") (Join-Path $DistDir "tgws-windows-$arch.exe") -Force -ErrorAction SilentlyContinue
}

# ---- Archives ----
Add-Type -AssemblyName System.IO.Compression
$tarExe = if ($env:SystemRoot) { Join-Path $env:SystemRoot "System32\tar.exe" } else { "tar" }
$hasTar = [bool](Get-Command $tarExe -ErrorAction SilentlyContinue)
foreach ($dir in Get-ChildItem $DistDir -Directory) {
    if (-not $env:SystemRoot) {
        # Shell scripts must stay executable inside the Linux packages.
        Get-ChildItem $dir.FullName -Filter "*.sh" | ForEach-Object { chmod +x $_.FullName }
    }
    $zip = "$($dir.FullName).zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    # Both Compress-Archive and ZipFile.CreateFromDirectory emit backslash
    # separators on Windows, which breaks extraction on Linux/macOS. Write the
    # entries explicitly with forward slashes.
    $zipStream = [System.IO.File]::Create($zip)
    $archive = New-Object System.IO.Compression.ZipArchive($zipStream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in Get-ChildItem $dir.FullName -Recurse -File) {
            $rel = $f.FullName.Substring($dir.FullName.Length + 1).Replace('\', '/')
            $entry = $archive.CreateEntry($rel, [System.IO.Compression.CompressionLevel]::Optimal)
            $es = $entry.Open()
            $fs = [System.IO.File]::OpenRead($f.FullName)
            try { $fs.CopyTo($es) } finally { $fs.Dispose(); $es.Dispose() }
        }
    } finally {
        $archive.Dispose()
        $zipStream.Dispose()
    }
    $tgz = "$($dir.FullName).tar.gz"
    if (Test-Path $tgz) { Remove-Item $tgz -Force }
    if ($hasTar) {
        & $tarExe -czf $tgz -C $DistDir $dir.Name
    } else {
        Write-Warning "tar not found; skipping $($dir.Name).tar.gz"
    }
    Write-Host "packed $($dir.Name)" -ForegroundColor Green
}

Write-Host "`nDesktop packages ready in $DistDir" -ForegroundColor Cyan
