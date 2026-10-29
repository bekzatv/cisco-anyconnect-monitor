<#
.SYNOPSIS
  Устанавливает или обновляет Cisco AnyConnect Monitor на Windows Server как фоновую задачу,
  работающую без входа пользователя.

.DESCRIPTION
  - копирует CiscoAnyConnectServer.exe в папку программы;
  - создаёт папку данных с доступом только для SYSTEM и администраторов;
  - загружает данные, перенесённые с рабочего ПК (-Bundle);
  - регистрирует задачу Планировщика: запуск при старте системы от имени SYSTEM, проверка
    каждые 5 минут (если сервер упал — поднимется; если работает — второй экземпляр не стартует);
  - открывает порт панели в брандмауэре (кроме режима -LocalOnly).
  Повторный запуск без -Bundle обновляет программу и не трогает данные.

.EXAMPLE
  .\Install-Server.ps1 -Bundle C:\Temp\vpnmon-transfer.zip
.EXAMPLE
  .\Install-Server.ps1 -DryRun          # только показать, что будет сделано
#>
[CmdletBinding()]
param(
    [string]$Bundle,
    [string]$Exe,
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'CiscoAnyConnectMonitor'),
    [string]$DataDir = (Join-Path $env:ProgramData 'CiscoAnyConnectMonitor'),
    [int]$Port = 8765,
    [int]$SyslogPort = 514,
    # Private networks by default; narrow it to your routers, e.g. -SyslogFrom 192.168.1.1
    [string[]]$SyslogFrom = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'),
    [switch]$LocalOnly,
    [switch]$Force,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$TaskName = 'CiscoAnyConnectMonitorServer'
$RuleName = 'Cisco AnyConnect Monitor (панель)'
$SyslogRuleName = 'Cisco AnyConnect Monitor (syslog роутера)'
$Target = Join-Path $InstallDir 'CiscoAnyConnectServer.exe'
# Windows PowerShell 5.1 leaves $PSScriptRoot empty inside param() defaults.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Exe) { $Exe = Join-Path $ScriptDir 'CiscoAnyConnectServer.exe' }
if (-not $Bundle -and -not (Test-Path (Join-Path $DataDir 'connection_stats.db'))) {
    # First install started with a double click: use the transfer archive lying next to it.
    # On an update the server already has its data, so an old archive nearby is ignored.
    $found = Get-ChildItem -Path $ScriptDir -Filter 'vpnmon-transfer-*.zip' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($found) {
        $Bundle = $found.FullName
        Write-Host "Найден архив переноса рядом со скриптом: $($found.Name)" -ForegroundColor Green
    }
}

function Step([string]$Text, [scriptblock]$Action) {
    if ($DryRun) { Write-Host "[проверка] $Text" -ForegroundColor Cyan; return }
    Write-Host "-> $Text"
    & $Action
}

# ---------------------------------------------------------------- checks
$os = [Environment]::OSVersion.Version
if ($os.Major -lt 10 -or ($os.Major -eq 10 -and $os.Build -lt 14393)) {
    throw "Нужен Windows Server 2016 или новее (сейчас $os): программа собрана на Python 3.13."
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) {
    throw 'Запустите PowerShell от имени администратора.'
}
if (-not (Test-Path $Exe)) { throw "Не найден $Exe. Положите CiscoAnyConnectServer.exe рядом со скриптом или укажите -Exe." }
if ($Bundle -and -not (Test-Path $Bundle)) { throw "Не найден архив переноса $Bundle" }
$firstInstall = -not (Test-Path (Join-Path $DataDir 'connection_stats.db'))
if ($firstInstall -and -not $Bundle) {
    Write-Warning ('Архив переноса не найден: сервер начнёт с пустой базой. Чтобы перенести историю с ПК, ' +
        'положите vpnmon-transfer-*.zip рядом с Install-Server.bat или укажите -Bundle.')
}
if ($Bundle -and -not $firstInstall -and -not $Force -and -not $DryRun) {
    Write-Host ''
    Write-Host "В $DataDir уже есть база. Заменить её данными из архива $(Split-Path -Leaf $Bundle)?" -ForegroundColor Yellow
    Write-Host 'Текущая база не удаляется, а сохраняется рядом с суффиксом .before-import-<дата>.'
    $answer = Read-Host 'Заменить? (Д/Н)'
    if ($answer -match '^(д|да|y|yes)$') {
        $Force = $true
    } else {
        Write-Host 'Архив не загружается: программа будет обновлена, данные останутся как есть.'
        $Bundle = $null
    }
}

Write-Host ''
Write-Host "Программа:  $InstallDir"
Write-Host "Данные:     $DataDir"
Write-Host "Панель:     порт $Port, $(if ($LocalOnly) { 'только с этого сервера' } else { 'доступ из сети по HTTPS' })"
Write-Host "Часовой пояс сервера: $((Get-TimeZone).DisplayName) — должен совпадать с роутером"
Write-Host ''

# ---------------------------------------------------------------- stop the running copy
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Step 'Остановка работающей задачи' {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}
Step 'Остановка запущенного CiscoAnyConnectServer.exe из папки программы' {
    Get-Process CiscoAnyConnectServer -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $Target } | Stop-Process -Force
    Start-Sleep -Seconds 1
}

# ---------------------------------------------------------------- files
Step "Копирование программы в $InstallDir" {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Force $Exe $Target
}
Step "Папка данных $DataDir (доступ: SYSTEM и администраторы)" {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    # Logins, IP addresses and settings live here: no access for ordinary users.
    & icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'icacls завершился с ошибкой' }
}

if ($Bundle) {
    Step "Загрузка данных из $Bundle" {
        $importArgs = @('--data-dir', "`"$DataDir`"", '--import-bundle', "`"$((Resolve-Path $Bundle).Path)`"", '--quiet', '--port', $Port)
        if (-not $LocalOnly) { $importArgs += '--lan' }
        if ($Force) { $importArgs += '--force' }
        $p = Start-Process -FilePath $Target -ArgumentList $importArgs -Wait -PassThru -WindowStyle Hidden
        $log = Join-Path $DataDir 'server.log'
        if (Test-Path $log) { Get-Content $log -Tail 4 -Encoding UTF8 | ForEach-Object { Write-Host "   $_" } }
        if ($p.ExitCode -ne 0) {
            throw "Импорт не выполнен (код $($p.ExitCode)). Если база уже есть и её нужно заменить — добавьте -Force."
        }
    }
} elseif ($firstInstall) {
    Step 'Начальные настройки панели' {
        $settings = @{ web_port = $Port; web_bind = $(if ($LocalOnly) { '127.0.0.1' } else { '0.0.0.0' }); web_https = -not $LocalOnly }
        $json = $settings | ConvertTo-Json
        [IO.File]::WriteAllText((Join-Path $DataDir 'settings.json'), $json, (New-Object Text.UTF8Encoding $false))
    }
}

# ---------------------------------------------------------------- scheduled task
Step "Задача Планировщика $TaskName (SYSTEM, при старте системы и каждые 5 минут)" {
    $action = New-ScheduledTaskAction -Execute $Target -Argument "--data-dir `"$DataDir`"" -WorkingDirectory $InstallDir
    $atStartup = New-ScheduledTaskTrigger -AtStartup
    $watchdog = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($atStartup, $watchdog) `
        -Principal $principal -Settings $settings -Force `
        -Description 'Cisco AnyConnect Monitor: сбор VPN-сессий и веб-панель' | Out-Null
}

# ---------------------------------------------------------------- firewall
if (-not $LocalOnly) {
    Step "Правило брандмауэра: входящий TCP $Port (домен и частная сеть)" {
        Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Protocol TCP -LocalPort $Port `
            -Action Allow -Profile Domain, Private -Program $Target | Out-Null
    }
}
Step "Правило брандмауэра: входящий UDP $SyslogPort (журнал роутера) только из $($SyslogFrom -join ', ')" {
    Get-NetFirewallRule -DisplayName $SyslogRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName $SyslogRuleName -Direction Inbound -Protocol UDP -LocalPort $SyslogPort `
        -RemoteAddress $SyslogFrom -Action Allow -Profile Any -Program $Target | Out-Null
}

# ---------------------------------------------------------------- start
Step 'Запуск' {
    Start-ScheduledTask -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $deadline) {
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) { break }
        Start-Sleep -Seconds 1
    }
    if (-not (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) {
        Write-Warning "Сервер не начал слушать порт $Port за 40 секунд. Смотрите $DataDir\server.log"
    }
}

if ($DryRun) { Write-Host ''; Write-Host 'Это была проверка: ничего не изменено.' -ForegroundColor Cyan; return }

$scheme = 'http'
$s = Get-Content (Join-Path $DataDir 'settings.json') -Raw -Encoding UTF8 -ErrorAction SilentlyContinue | ConvertFrom-Json
if ($s -and $s.web_https) { $scheme = 'https' }
Write-Host ''
Write-Host 'Готово.' -ForegroundColor Green
Write-Host "Панель: ${scheme}://$($env:COMPUTERNAME):$Port/  (и ${scheme}://127.0.0.1:$Port/ на самом сервере)"
Write-Host ''
Write-Host 'Дальше:'
Write-Host '  1. Откройте панель, войдите прежним паролем (или задайте новый — только с самого сервера).'
Write-Host '  2. Настройки -> Устройства Cisco -> Изменить: введите пароли роутеров заново.'
Write-Host '  3. Настройки -> Telegram: введите токен бота заново (если пользовались).'
Write-Host '  4. Если на роутере SSH разрешён только с определённых адресов (access-class на line vty) —'
Write-Host "     добавьте IP этого сервера."
Write-Host '  5. Остановите сервер на старом ПК (Remove-Autostart.bat), чтобы роутер не опрашивали дважды.'
