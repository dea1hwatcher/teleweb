# TeleWEB for Windows
# Install (elevated PowerShell, from the extracted package directory):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
# Uninstall:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$Dest = Join-Path $env:ProgramData "teleweb"
$ServiceName = "TeleWEB"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator rights are required. Re-run PowerShell as Administrator."
    }
}

Assert-Admin

if ($Uninstall) {
    if (Test-Path (Join-Path $Dest "tgws.exe")) {
        & (Join-Path $Dest "tgws.exe") stop 2>$null | Out-Null
        & (Join-Path $Dest "tgws.exe") svc-uninstall 2>$null | Out-Null
    }
    sc.exe stop $ServiceName 2>$null | Out-Null
    sc.exe delete $ServiceName 2>$null | Out-Null
    Write-Host "TeleWEB service removed. Files kept in $Dest (delete manually if not needed)."
    exit 0
}

$Src = $PSScriptRoot
foreach ($f in @("tgws.exe", "WinDivert.dll", "WinDivert64.sys")) {
    if (-not (Test-Path (Join-Path $Src $f))) {
        throw "Missing $f next to install.ps1"
    }
}

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item (Join-Path $Src "tgws.exe") $Dest -Force
Copy-Item (Join-Path $Src "WinDivert.dll") $Dest -Force
Copy-Item (Join-Path $Src "WinDivert64.sys") $Dest -Force
if (Test-Path (Join-Path $Src "webroot")) {
    Copy-Item (Join-Path $Src "webroot") $Dest -Recurse -Force
}

# Remove a previously running console instance before service registration.
& (Join-Path $Dest "tgws.exe") stop 2>$null | Out-Null

& (Join-Path $Dest "tgws.exe") svc-install
sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "TeleWEB installed."
Write-Host ("  state/logs: {0}" -f $Dest)
Write-Host "  status:     $Dest\tgws.exe status"
Write-Host "  webui:      $Dest\tgws.exe webui 127.0.0.1:17842   (open http://127.0.0.1:17842)"
Write-Host "  socks:      $Dest\tgws.exe socks 127.0.0.1:17845   (no-driver alternative; set proxy in Telegram)"
Write-Host ""
Write-Host "Note: the WinDivert kernel driver is installed on first start (signed by the WinDivert maintainer)."
