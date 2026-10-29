# TeleWEB Linux build script.
# Linux: amd64/arm64 — tgws + webroot + installers.
# Produces packages under dist/.
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $RootDir "src"
$DistDir = Join-Path $RootDir "dist"
$Webroot = Join-Path $RootDir "webroot"

$GoPath = "go"
if (Test-Path "C:\Program Files\Go\bin\go.exe") { $GoPath = "C:\Program Files\Go\bin\go.exe" }

function Build-Target([string]$goos, [string]$goarch, [string]$outFile, [string]$tags = "") {
    Write-Host ">>> $goos/$goarch -> $outFile" -ForegroundColor Yellow
    $env:CGO_ENABLED = "0"
    $env:GOOS = $goos
    $env:GOARCH = $goarch
    $buildArgs = @("build", "-trimpath", "-ldflags", "-s -w")
    if ($tags -ne "") { $buildArgs += @("-tags", $tags) }
    $buildArgs += @("-o", $outFile, ".")
    Push-Location $SrcDir
    & $GoPath @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "build failed for $goos/$goarch" }
    Pop-Location
}

function Copy-Common([string]$dest) {
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item $Webroot (Join-Path $dest "webroot") -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

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
