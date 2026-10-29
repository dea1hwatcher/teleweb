# TeleWEB for Windows
# Install (elevated PowerShell, from the extracted package directory):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
# Uninstall:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$Dest = Join-Path $env:ProgramData "teleweb"
$ServiceName = "TeleWEB"
$RegKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\TeleWEB"

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
    Remove-Item -Path $RegKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "TeleWEB service and Windows registration removed. Files kept in $Dest (delete manually if not needed)."
    exit 0
}

$Src = $PSScriptRoot
if (-not (Test-Path (Join-Path $Src "tgws.exe"))) {
    throw "Missing tgws.exe next to install.ps1"
}
$hasDriver = (Test-Path (Join-Path $Src "WinDivert.dll")) -and (Test-Path (Join-Path $Src "WinDivert64.sys"))

New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item (Join-Path $Src "tgws.exe") $Dest -Force
if ($hasDriver) {
    Copy-Item (Join-Path $Src "WinDivert.dll") $Dest -Force
    Copy-Item (Join-Path $Src "WinDivert64.sys") $Dest -Force
} else {
    Write-Host "WinDivert driver not bundled (Windows ARM64): only SOCKS mode is available." -ForegroundColor Yellow
}
if (Test-Path (Join-Path $Src "webroot")) {
    Copy-Item (Join-Path $Src "webroot") $Dest -Recurse -Force
}

# Remove a previously running console instance before service registration.
& (Join-Path $Dest "tgws.exe") stop 2>$null | Out-Null

& (Join-Path $Dest "tgws.exe") svc-install
sc.exe failure $ServiceName reset= 86400 actions= restart/5000 2>$null | Out-Null
sc.exe config $ServiceName start= delayed-auto 2>$null | Out-Null
sc.exe start $ServiceName | Out-Null
Start-Sleep -Seconds 3

# Register in Windows Settings / Apps & Features (Uninstall Registry Key)
try {
    New-Item -Path $RegKey -Force | Out-Null
    Set-ItemProperty -Path $RegKey -Name "DisplayName" -Value "TeleWEB Transparent WSS Transport" -Force
    Set-ItemProperty -Path $RegKey -Name "DisplayVersion" -Value "0.1.4" -Force
    Set-ItemProperty -Path $RegKey -Name "Publisher" -Value "TeleWEB Open Source" -Force
    Set-ItemProperty -Path $RegKey -Name "InstallLocation" -Value $Dest -Force
    Set-ItemProperty -Path $RegKey -Name "DisplayIcon" -Value "$Dest\tgws.exe,0" -Force
    Set-ItemProperty -Path $RegKey -Name "UninstallString" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$Dest\install.ps1`" -Uninstall" -Force
    Set-ItemProperty -Path $RegKey -Name "QuietUninstallString" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$Dest\install.ps1`" -Uninstall" -Force
    Set-ItemProperty -Path $RegKey -Name "NoModify" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $RegKey -Name "NoRepair" -Value 1 -Type DWord -Force
} catch {
    Write-Warning "Could not register TeleWEB in Windows Programs & Features: $_"
}

Write-Host ""
Write-Host "TeleWEB installed."
Write-Host ("  state/logs: {0}" -f $Dest)
Write-Host "  status:     $Dest\tgws.exe status"
Write-Host "  webui:      $Dest\tgws.exe webui 127.0.0.1:17842   (open http://127.0.0.1:17842)"
Write-Host "  socks:      $Dest\tgws.exe socks 127.0.0.1:17845   (no-driver alternative; set proxy in Telegram)"
Write-Host ""
Write-Host "Note: the WinDivert kernel driver is installed on first start (signed by the WinDivert maintainer)."
