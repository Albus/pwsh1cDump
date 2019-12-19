$PSDefaultParameterValues = @{ '*:Encoding' = 'utf8' }
$OutputEncoding = [System.Text.Encoding]::UTF8

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name 'RasIP' -Value '10.12.1.17' `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'IP адрес сервера RAS'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name 'ClusterGUID' -Value '75e25118-be3c-455f-a53d-4a902f1eb256' `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'GUID кластера 1С'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name 'PermissionCode' -Value '75e25118-be3c-455f-a53d-4a902f1eb256' `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Код разрешения подлючатся к заблокированной БД (/UC)'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name '1cFolder' -Value (Join-Path -Path ${Env:\ProgramFiles} `
        -ChildPath '1cv8' -Resolve | Join-Path -ChildPath '8.3.13.1644' -Resolve `
    | Join-Path -ChildPath 'bin' -Resolve) `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Папка (полный путь) где лежат исполняемые файлы 1С'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name '1cBin' -Value (Join-Path -Path $1cFolder -ChildPath '1cv8.exe' -Resolve).ToString() `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Исполняемый файл конфигуратора 1С - 1cv8.exe (полный путь)'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name 'RacBin' -Value (Join-Path -Path $1cFolder -ChildPath 'rac.exe' -Resolve).ToString() `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Исполняемый файл утилиты управления кластером 1С - ras.exe (полный путь)'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name '1cBases' -Value @('uas_ut11') `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Массив имен баз 1С для обработки'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name '1cBasesCredential' -Value (New-Object PSCredential 'Administrator'`
        , $(('01000000d08c9ddf0115d1118c7a00c04fc297eb01000000a284d902d96b3e4bb6956ab0' + `
                '40fdc47c0000000002000000000003660000c000000010000000f88c7c504a1d379d0472' + `
                '4ca327ef24a50000000004800000a000000010000000fd35ecf38e94356435a64884d882' + `
                '45851800000023d3d015a3fe48d51f0ed4d46c1a0ed663955462e1a96dce140000003247' + `
                '7e40a7aceb226b416c4fae2e5065b56ba19c') | ConvertTo-SecureString)).GetNetworkCredential() `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Учетка администратора БД'

Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name '1cBasesUser' -Value $1cBasesCredential.UserName `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Логин администратора БД'
    
Set-Variable -Option ReadOnly -Visibility Public -Force `
    -Scope Script -Name '1cBasesPass' -Value $1cBasesCredential.Password `
    -ErrorAction Stop -WarningAction SilentlyContinue `
    -Description 'Пароль администратора БД'



function rac {
    [OutputType([PSObject[]])]
    param ([string[]]$StdOut)
    $Objects = [PSObject] @{List = [PSObject[]]@() ; Current = $null }
    $Objects.Current = New-Object -TypeName PSObject
    $Objects.List += $Objects.Current
    if (-not [string]::IsNullOrEmpty($StdOut)) {
        foreach ($line in $StdOut.Trim()) {
            if ([string]::IsNullOrWhiteSpace($line)) {
                $Objects.Current = New-Object -TypeName PSObject
                $Objects.List += $Objects.Current
                continue
            }
            else {
                $keyvalue = ($line -split ':', 2, 'SimpleMatch').Trim().trim('"')
                if (-not [string]::IsNullOrWhiteSpace($keyvalue[0])) {
                    $Objects.Current | Add-Member -Type NoteProperty -Name ($keyvalue[0] -replace '-', '_') -Value $keyvalue[1]
                }
            }
        }
    }
    return ($Objects.List | Where-Object { -not [string]::IsNullOrEmpty($_) })
}

function GetSessions {
    [OutputType([PSObject[]])]
    param ([String]$ClusterGUID, [String]$BaseGUID, [String]$RasIP, [String]$RacBin)
    return (rac -stdout (& $RacBin session list --cluster=$ClusterGUID --infobase=$BaseGUID $RasIP)`
    | Where-Object -FilterScript {@('Designer','BackgroundJob','1CV8','1CV8C','COMConnection','WSConnection').Contains($_.app_id)} )
}

function GetConnections {
    [OutputType([PSObject[]])]
    param ([String]$ClusterGUID, [String]$BaseGUID, [String]$BaseUser, [String]$BasePass, [String]$RasIP, [String]$RacBin)
    return (rac -stdout (& $RacBin connection list --cluster=$ClusterGUID --infobase=$BaseGUID --infobase-user=$BaseUser --infobase-pwd=$BasePass $RasIP) `
    | Where-Object -FilterScript {@('Designer','BackgroundJob','1CV8','1CV8C','COMConnection','WSConnection').Contains($_.application)} )
}
function GetBase1cGUID {
    [OutputType([PSObject[]])]
    param ([String]$ClusterGUID, [String]$Base, [String]$RasIP, [String]$RacBin)
    return (rac -StdOut (& $RacBin infobase summary list --cluster=$ClusterGUID $RasIP) | Where-Object { $Base -eq $_.name }).infobase
}
function GetBase1cInfo {
    [OutputType([PSObject[]])]
    param ([String]$ClusterGUID, [String]$BaseGUID, [String]$BaseUser, [String]$BasePass, [String]$RasIP, [String]$RacBin)
    return (rac -stdout (& $RacBin infobase info --cluster=$ClusterGUID --infobase=$BaseGUID --infobase-user=$BaseUser --infobase-pwd=$BasePass $RasIP))
}
function StopProcs {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][PSObject[]]$Objects,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)][string]$RacBin,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)][string]$RasIP,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false)][string]$ClusterGUID
    )
    $Objects | Where-Object -FilterScript { $_.process -ne '00000000-0000-0000-0000-000000000000' } `
    | Select-Object -ExpandProperty 'process' -Unique `
    | ForEach-Object -Process { rac -StdOut (& $RacBin $RasIP process info --cluster=$ClusterGUID --process=$_) } `
    | ForEach-Object -Process { & taskkill.exe /s $_.host /pid $_.pid /t }
}


function SendGram {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true, ValueFromPipeline = $true)][string]$text)
    begin {
        $text = $text.Trim()
        $SmtpPass = ('01000000d08c9ddf0115d1118c7a00c04fc297eb01000000a284d902d96b3e4bb6956ab040fdc47' + `
                'c0000000002000000000003660000c000000010000000965c145d0935e1bd73abc9d448cdbc860000' + `
                '000004800000a0000000100000008bae89c369d4115c0a0cedfb45e41a37180000004f69afea9be17' + `
                'adf0f7c6631e74db57944b0e3fc5e9f459e14000000170b3d0c6887cb490bf8ba10a3a735735456e1d0') | ConvertTo-SecureString    
    }
    process {
        Send-MailMessage -Subject 'Powershell Backuper 1C' -Body $('#UAS2DT @grevinden {0}' -f $text ) `
            -To 'warneverchanges@etlgr.com' -From 'ut_notifier@santens.ru' -SmtpServer 'smtp.santens.ru' -Port 25 `
            -Credential $(New-Object System.Management.Automation.PSCredential('ut_notifier@santens.ru', $SmtpPass)) `
            -Encoding $Global:OutputEncoding -WarningAction SilentlyContinue
    }
    end {
        ' [!] MSG >>> {0} ' -f $text | Write-Host -BackgroundColor DarkBlue -ForegroundColor Yellow
    }
}

Start-Transcript -Path $(Join-Path -Path $PSScriptRoot -ChildPath 'BackUp.log') -Append

foreach ($1cBase in ($1cBases | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
    $1cBaseGUID = GetBase1cGUID -RasIP $RasIP -ClusterGUID $ClusterGUID -Base $1cBase -RacBin $RacBin

    if (-not [string]::IsNullOrWhiteSpace($1cBaseGUID)) {
        while ($true) {
        
            [System.Environment]::NewLine + '=' * 80 + [System.Environment]::NewLine + 'ЭТАП №1: Запрещаем подключения к базе'
            while (@($Base1cInfo.sessions_deny, $Base1cInfo.scheduled_jobs_deny).Contains('off') -or $null -eq $Base1cInfo) {
                Write-Host '>>> Отправка комманды ras для установки блокировки соединений' -ForegroundColor Yellow
                & $RacBin infobase update $RasIP --cluster=$ClusterGUID `
                    --infobase=$1cBaseGUID --infobase-user=$1cBasesUser --infobase-pwd=$1cBasesPass `
                    --sessions-deny='on' --scheduled-jobs-deny='on' --permission-code=$PermissionCode --denied-message='Archiving in progress'
                $Base1cInfo = GetBase1cInfo -RasIP $RasIP -RacBin $RacBin -ClusterGUID $ClusterGUID -BaseGUID $1cBaseGUID -BaseUser $1cBasesUser -BasePass $1cBasesPass
            }
            'База зазблокирована.' | SendGram

            [System.Environment]::NewLine + '=' * 80 + [System.Environment]::NewLine + 'ЭТАП №2: Закрываем сессии'
            foreach ($iter in 1..3) {
                $Sessions = GetSessions -RasIP $RasIP -ClusterGUID $ClusterGUID -BaseGUID $1cBaseGUID -RacBin $RacBin
                if (-not [string]::IsNullOrEmpty($Sessions)) {
                    foreach ($Session in $Sessions) {
                        $SessionGUID = $Session.session
                        & $RacBin session terminate $RasIP --cluster=$clusterGUID --session=$SessionGUID --error-message='Archiving started'
                    }
                }
                else { break }
            }

            [System.Environment]::NewLine + '=' * 80 + [System.Environment]::NewLine + 'ЭТАП №3: Контроль зависших сессий'
            foreach ($iter in 1..3) {
                $Sessions = GetSessions -RasIP $RasIP -ClusterGUID $ClusterGUID -BaseGUID $1cBaseGUID -RacBin $RacBin
                if (-not [string]::IsNullOrEmpty($Sessions)) {
                    Write-Host 'Пытаемся прибить зависшие серверные процессы' -ForegroundColor Red
                    $Sessions | StopProcs -RacBin $RacBin -RasIP $RasIP -ClusterGUID $ClusterGUID
                }
                else {
                    Write-Host 'Зависших сессий не обнаружено' -ForegroundColor Green
                    break
                }
            }

            [System.Environment]::NewLine + '=' * 80 + [System.Environment]::NewLine + 'ЭТАП №4: Закрываем соединения'
            foreach ($iter in 1..3) {
                $Connections = GetConnections -RasIP $RasIP -ClusterGUID $ClusterGUID -BaseGUID $1cBaseGUID -BaseUser $1cBasesUser -BasePass $1cBasesPass -RacBin $RacBin
                if (-not [string]::IsNullOrEmpty($Connections)) {
                    foreach ($Connection in $Connections) {
                        $ConnGUID = $Connection.connection
                        $ProcessGUID = $Connection.process
                        & $RacBin connection disconnect $RasIP --cluster=$clusterGUID --connection=$ConnGUID --process=$ProcessGUID --infobase-user=$1cBasesUser --infobase-pwd=$1cBasesPass
                    }
                }
                else { break }
            }

            [System.Environment]::NewLine + '=' * 80 + [System.Environment]::NewLine + 'ЭТАП №5: Контроль зависших соединений'
            foreach ($iter in 1..3) {
                $Connections = GetConnections -RasIP $RasIP -ClusterGUID $ClusterGUID -BaseGUID $1cBaseGUID -BaseUser $1cBasesUser -BasePass $1cBasesPass -RacBin $RacBin
                if (-not [string]::IsNullOrEmpty($Connections)) {
                    Write-Host 'Пытаемся прибить зависшие серверные процессы' -ForegroundColor Red
                    $Connections | StopProcs -RacBin $RacBin -RasIP $RasIP -ClusterGUID $ClusterGUID
                }
                else {
                    Write-Host 'Зависших соединений не обнаружено' -ForegroundColor Green
                    break
                }
            }

            [System.Environment]::NewLine + '=' * 80 + [System.Environment]::NewLine + 'ЭТАП №6: Запускаем архивацию'
            $Sessions = GetSessions -RasIP $RasIP -ClusterGUID $ClusterGUID -BaseGUID $1cBaseGUID -RacBin $RacBin
            if ([string]::IsNullOrEmpty($Sessions)) {
                $TimeStamp = get-date -uformat %s
                $FileName = "$1cBase--$TimeStamp"
                $FileDt = Join-Path -Path $PSScriptRoot -ChildPath "$FileName.dt"
                $FileLog = Join-Path -Path $PSScriptRoot -ChildPath "$FileName.log"

                $p = New-Object System.Diagnostics.Process
                $p.EnableRaisingEvents = $false
                Register-ObjectEvent -InputObject $p -EventName Exited -Action {
                }

                $p.StartInfo = New-Object System.Diagnostics.ProcessStartInfo
                $p.StartInfo.FileName = $1cBin
                $p.StartInfo.RedirectStandardInput = $false
                $p.StartInfo.RedirectStandardError = $false
                $p.StartInfo.RedirectStandardOutput = $false
                $p.StartInfo.UseShellExecute = $false
                $p.StartInfo.Arguments = "CONFIG /UC$PermissionCode /AU- /DisableStartupMessages /WA- /N$1cBasesUser /P$1cBasesPass /S$RasIP\$1cBase /Out$FileLog /DumpIB$FileDt"
                $start = $p.Start()
                if ($start) {

                    $p.WaitForExit() 
                    $p | Out-File -FilePath $('{0}.exitcode.{1}' -f $FileName, $($p.ExitCode))          
                    if ($p.ExitCode -eq 0) {
                        '{1} ExitCode#{0}' -f $p.ExitCode, $(Get-Content -Path $FileLog) | SendGram 
                        break
                    }
                    else { '{1} ExitCode#{0}' -f $p.ExitCode, $(Get-Content -Path $FileLog) | SendGram }
                }
                else { break }
            }
        }
    }


    [System.Environment]::NewLine + '=' * 80 + [System.Environment]::NewLine + 'ЭТАП №7: Разрешаем подключения к серверу'
    while (@($Base1cInfo.sessions_deny, $Base1cInfo.scheduled_jobs_deny).Contains('on') -or $null -eq $Base1cInfo) {
        Write-Host 'Пауза 60 секунд' -ForegroundColor Gray
        Start-Sleep -Seconds 60
        Write-Host '>>> Отправка комманды ras для снятия блокировки соединений' -ForegroundColor Yellow
        & $RacBin infobase update $RasIP --cluster=$ClusterGUID `
            --infobase=$1cBaseGUID --infobase-user=$1cBasesUser --infobase-pwd=$1cBasesPass `
            --sessions-deny='off' --scheduled-jobs-deny='off' --permission-code='' --denied-message=''
        $Base1cInfo = GetBase1cInfo -RasIP $RasIP -RacBin $RacBin -ClusterGUID $ClusterGUID -BaseGUID $1cBaseGUID -BaseUser $1cBasesUser -BasePass $1cBasesPass   
    }
    'База разблокирована.' | SendGram
}

