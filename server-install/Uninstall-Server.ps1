<#
.SYNOPSIS
  Удаляет задачу Планировщика и правило брандмауэра Cisco AnyConnect Monitor.
  Папка данных (база, настройки, резервные копии) сохраняется, если не указан -RemoveData.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'CiscoAnyConnectMonitor'),
    [string]$DataDir = (Join-Path $env:ProgramData 'CiscoAnyConnectMonitor'),
    [switch]$RemoveProgram,
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$TaskName = 'CiscoAnyConnectMonitorServer'
$RuleName = 'Cisco AnyConnect Monitor (панель)'
$Target = Join-Path $InstallDir 'CiscoAnyConnectServer.exe'

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Задача $TaskName удалена"
}
Get-Process CiscoAnyConnectServer -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Target } | Stop-Process -Force
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName 'Cisco AnyConnect Monitor (syslog роутера)' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
if ($RemoveProgram -and (Test-Path $InstallDir)) { Remove-Item -Recurse -Force $InstallDir; Write-Host "Удалено: $InstallDir" }
if ($RemoveData -and (Test-Path $DataDir)) {
    Remove-Item -Recurse -Force $DataDir
    Write-Host "Удалено: $DataDir"
} else {
    Write-Host "Данные сохранены: $DataDir"
}
