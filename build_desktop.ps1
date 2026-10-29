# TeleWEB desktop build script: Windows (amd64/arm64) and Linux (amd64/arm64).
# Produces self-contained packages under dist/.
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $RootDir "src"
$DistDir = Join-Path $RootDir "dist"
$Webroot = Join-Path $RootDir "webroot"

$GoPath = "go"
if (Test-Path "C:\Program Files\Go\bin\go.exe") { $GoPath = "C:\Program Files\Go\bin\go.exe" }

function Build-Target([string]$goos, [string]$goarch, [string]$outFile) {
    Write-Host ">>> $goos/$goarch -> $outFile" -ForegroundColor Yellow
    $env:CGO_ENABLED = "0"
    $env:GOOS = $goos
    $env:GOARCH = $goarch
    Push-Location $SrcDir
    & $GoPath build -trimpath -ldflags "-s -w" -o $outFile .
    if ($LASTEXITCODE -ne 0) { throw "build failed for $goos/$goarch" }
    Pop-Location
}

function Copy-Common([string]$dest) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item $Webroot (Join-Path $dest "webroot") -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# ---- Windows amd64 (transparent mode via WinDivert) ----
$win64 = Join-Path $DistDir "teleweb-windows-amd64"
if (Test-Path $win64) { Remove-Item $win64 -Recurse -Force }
Copy-Common $win64
Build-Target "windows" "amd64" (Join-Path $win64 "tgws.exe")
Copy-Item (Join-Path $RootDir "desktop\windows\windivert\WinDivert.dll") $win64 -Force
Copy-Item (Join-Path $RootDir "desktop\windows\windivert\WinDivert64.sys") $win64 -Force
Copy-Item (Join-Path $RootDir "desktop\windows\windivert\LICENSE") (Join-Path $win64 "WinDivert-LICENSE.txt") -Force
Copy-Item (Join-Path $RootDir "desktop\windows\install.ps1") $win64 -Force

# ---- Windows arm64 (SOCKS mode only; WinDivert has no arm64 driver) ----
$winArm = Join-Path $DistDir "teleweb-windows-arm64"
if (Test-Path $winArm) { Remove-Item $winArm -Recurse -Force }
Copy-Common $winArm
Build-Target "windows" "arm64" (Join-Path $winArm "tgws.exe")

# ---- Linux amd64 / arm64 (transparent mode via iptables) ----
foreach ($arch in @("amd64", "arm64")) {
    $dir = Join-Path $DistDir "teleweb-linux-$arch"
    if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
    Copy-Common $dir
    Build-Target "linux" $arch (Join-Path $dir "tgws")
    Copy-Item (Join-Path $RootDir "desktop\linux\install.sh") $dir -Force
    Copy-Item (Join-Path $RootDir "desktop\linux\uninstall.sh") $dir -Force
}

# ---- Archives ----
$tarExe = if ($env:SystemRoot) { Join-Path $env:SystemRoot "System32\tar.exe" } else { "tar" }
$hasTar = [bool](Get-Command $tarExe -ErrorAction SilentlyContinue)
foreach ($dir in Get-ChildItem $DistDir -Directory) {
    if (-not $env:SystemRoot) {
        # Shell scripts must stay executable inside the Linux packages.
        Get-ChildItem $dir.FullName -Filter "*.sh" | ForEach-Object { chmod +x $_.FullName }
    }
    $zip = "$($dir.FullName).zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path "$($dir.FullName)\*" -DestinationPath $zip
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
