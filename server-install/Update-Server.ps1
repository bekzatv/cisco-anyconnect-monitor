<#
.SYNOPSIS
  Обновляет Cisco AnyConnect Monitor на сервере до последнего релиза с GitHub одной командой.

.DESCRIPTION
  - узнаёт у GitHub последнюю версию и сравнивает с установленной;
  - скачивает server-package.zip и сверяет контрольную сумму из SHA256SUMS.txt;
  - запускает из него Install-Server.ps1 с теми же параметрами, что при установке
    (порт, доступ из сети, адреса syslog). База и настройки не трогаются.
  Ход обновления пишется в update.log в папке данных.

.EXAMPLE
  & "$env:ProgramFiles\CiscoAnyConnectMonitor\Update-Server.ps1"
.EXAMPLE
  .\Update-Server.ps1 -CheckOnly        # только сказать, есть ли новая версия
.EXAMPLE
  .\Update-Server.ps1 -Version 4.5      # поставить определённую версию (откат)
.EXAMPLE
  .\Update-Server.ps1 -EnableAuto       # обновляться самому каждую ночь в 03:30
  .\Update-Server.ps1 -DisableAuto
#>
[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'CiscoAnyConnectMonitor'),
    [string]$DataDir = (Join-Path $env:ProgramData 'CiscoAnyConnectMonitor'),
    [switch]$CheckOnly,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$EnableAuto,
    [switch]$DisableAuto,
    [string]$AutoAt = '03:30',
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # the progress bar makes downloads many times slower in PowerShell 5.1
$Repo = 'bekzatv/cisco-anyconnect-monitor'
$AutoTaskName = 'CiscoAnyConnectMonitorUpdate'
$UserAgent = 'CiscoAnyConnectMonitor-Updater'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$LogFile = Join-Path $DataDir 'update.log'

function Say([string]$Text, [string]$Color = 'Gray') {
    if (-not $Quiet) { Write-Host $Text -ForegroundColor $Color }
    if ((Test-Path $DataDir) -and -not $DryRun) {
        try { Add-Content -Path $LogFile -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Text" -Encoding UTF8 } catch { }
    }
}

function ConvertTo-Version([string]$Text) {
    $t = ($Text -replace '^[vV]', '').Trim()
    if ($t -notmatch '^\d+(\.\d+){0,3}$') { return $null }
    if ($t -notmatch '\.') { $t += '.0' }
    return [version]$t
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not ($CheckOnly -or $DryRun)) {
    throw 'Запустите PowerShell от имени администратора.'
}

# ---------------------------------------------------------------- automatic updates
if ($EnableAuto) {
    $script = Join-Path $InstallDir 'Update-Server.ps1'
    if (-not (Test-Path $script)) { throw "Не найден $script. Сначала обновите программу этой командой без -EnableAuto." }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -Quiet" -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -Daily -At $AutoAt
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $AutoTaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Force -Description 'Cisco AnyConnect Monitor: установка новых версий с GitHub' | Out-Null
    Say "Автообновление включено: каждый день в $AutoAt сервер сам ставит новую версию, если она вышла. Журнал: $LogFile" 'Green'
    return
}
if ($DisableAuto) {
    Unregister-ScheduledTask -TaskName $AutoTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Say 'Автообновление выключено.' 'Green'
    return
}

try {
    # ---------------------------------------------------------------- what is installed and what is out
    $versionFile = Join-Path $InstallDir 'version.txt'
    $installed = ''
    if (Test-Path $versionFile) { $installed = (Get-Content $versionFile -Raw).Trim() }

    $headers = @{ 'User-Agent' = $UserAgent; 'Accept' = 'application/vnd.github+json' }
    if ($Version) {
        $url = "https://api.github.com/repos/$Repo/releases/tags/v$($Version -replace '^[vV]', '')"
    } else {
        $url = "https://api.github.com/repos/$Repo/releases/latest"
    }
    try {
        $release = Invoke-RestMethod -Uri $url -Headers $headers -TimeoutSec 30
    } catch {
        throw "Не удалось получить список релизов с GitHub ($url): $($_.Exception.Message)"
    }
    $latest = ($release.tag_name -replace '^[vV]', '')
    $shownInstalled = if ($installed) { $installed } else { 'неизвестна' }

    $newer = $true
    if ($installed -and -not $Version) {
        $a, $b = (ConvertTo-Version $latest), (ConvertTo-Version $installed)
        if ($a -and $b) { $newer = $a -gt $b }
    }
    if ($CheckOnly) {
        if ($newer) { Say "Доступна версия $latest (установлена $shownInstalled). Обновить: запустите эту команду без -CheckOnly." 'Yellow' }
        else { Say "Установлена последняя версия ($installed)." 'Green' }
        return
    }
    if (-not $newer -and -not $Force) {
        Say "Установлена последняя версия ($installed), обновлять нечего." 'Green'
        return
    }
    Say "Обновление: $shownInstalled -> $latest" 'Cyan'

    # ---------------------------------------------------------------- download and check
    $zipAsset = $release.assets | Where-Object { $_.name -like '*-server-package.zip' } | Select-Object -First 1
    $sumsAsset = $release.assets | Where-Object { $_.name -eq 'SHA256SUMS.txt' } | Select-Object -First 1
    if (-not $zipAsset) { throw "В релизе $latest нет архива server-package.zip" }

    $work = Join-Path $env:TEMP "vpnmon-update-$latest"
    if (Test-Path $work) { Remove-Item -Recurse -Force $work }
    New-Item -ItemType Directory -Path $work | Out-Null
    $zipPath = Join-Path $work $zipAsset.name
    Say "Скачивание $($zipAsset.name) ($([math]::Round($zipAsset.size / 1MB, 1)) МБ)"
    Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing -Headers @{ 'User-Agent' = $UserAgent } -TimeoutSec 600

    if ($sumsAsset) {
        $sumsPath = Join-Path $work 'SHA256SUMS.txt'
        Invoke-WebRequest -Uri $sumsAsset.browser_download_url -OutFile $sumsPath -UseBasicParsing -Headers @{ 'User-Agent' = $UserAgent }
        $line = Get-Content $sumsPath | Where-Object { $_ -match ('\s' + [regex]::Escape($zipAsset.name) + '$') } | Select-Object -First 1
        if (-not $line) { throw "В SHA256SUMS.txt нет строки для $($zipAsset.name)" }
        $expected = ($line -split '\s+')[0].ToLower()
        $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) { throw "Контрольная сумма архива не совпала: файл повреждён или подменён. Обновление отменено." }
        Say 'Контрольная сумма совпала.'
    } else {
        Say 'В релизе нет SHA256SUMS.txt: архив не проверен.' 'Yellow'
    }

    $package = Join-Path $work 'package'
    Expand-Archive -Path $zipPath -DestinationPath $package -Force
    $installer = Join-Path $package 'Install-Server.ps1'
    if (-not (Test-Path $installer)) { throw "В архиве нет Install-Server.ps1" }

    # ---------------------------------------------------------------- install with the same options as before
    $options = @{}
    $optionsFile = Join-Path $InstallDir 'install-options.json'
    if (Test-Path $optionsFile) {
        $saved = Get-Content $optionsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $saved.PSObject.Properties) { $options[$p.Name] = $p.Value }
    } else {
        # Installed before 4.7: take the port and the access mode from the panel settings.
        $settingsFile = Join-Path $DataDir 'settings.json'
        if (Test-Path $settingsFile) {
            $s = Get-Content $settingsFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($s.web_port) { $options['Port'] = [int]$s.web_port }
            if ($s.web_bind -eq '127.0.0.1') { $options['LocalOnly'] = $true }
        }
    }
    if ($options.ContainsKey('LocalOnly')) { $options['LocalOnly'] = [bool]$options['LocalOnly'] }
    if ($options.ContainsKey('SyslogFrom')) { $options['SyslogFrom'] = [string[]]@($options['SyslogFrom']) }
    $options['InstallDir'] = $InstallDir
    $options['DataDir'] = $DataDir
    if ($DryRun) { $options['DryRun'] = $true }

    & $installer @options
    if ($DryRun) { return }

    $now = ''
    if (Test-Path $versionFile) { $now = (Get-Content $versionFile -Raw).Trim() }
    Say "Готово: установлена версия $(if ($now) { $now } else { $latest })." 'Green'
} catch {
    Say "Обновление не выполнено: $($_.Exception.Message)" 'Red'
    if ($Quiet) { exit 1 }
    throw
} finally {
    if ($work -and (Test-Path $work)) { Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue }
}
