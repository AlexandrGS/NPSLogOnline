#https://github.com/AlexandrGS/NPSLogOnline
#Анализируя логи Windows NPS-Radius сервера показывает информацию о активных VPN-сессиях. Логи в DTS-формате. Все пользователи появляются примерно через 5 минут работы скрипта
#Такое время потому что Radius-клиент посялает пакеты о состоянии соединения Radius-серверу примерно каждые 5 минут. Так у моего сервера.
#
Param(
    #Активные файлы NPS-Radius сервера. Должны быть разделены символом из $DelimiterOfFilesList
    $LogFiles = "\\192.168.10.10\c$\Windows\System32\LogFiles\IN2009.log,\\192.168.10.11\c$\Windows\System32\LogFiles\IN2009.log",
    #ОТКЛЮЧЕНО. Сколько строк лога надо прочесть при старте скрипта. Когда сделал обработку нескольких лог файлов почему то перестало работать
    #$CountFirstReadLines = 10,
    #По какому полю упорядочивает выводимые результаты. Допустимые поля берутся из объекта $OneVPNSessionDesc
    $SortVPNSessionsByField = "UserName"
)

#Символы, которые в строке разделяют названия файлов
$DelimiterOfFilesList = ",;"

#
$MaxOnlineSec  = 5*60
$MaxTimeOutSec = 2 * $MaxOnlineSec

$StatusOnline  = "Online"
$StatusWarning = "Простой"
$StatusError   = "Превышено время"

[array]$Script:OnlineVPNSessions = @{}

#Packet-Type
$AccessRequest = 1
$AccessAccept = 2
$AccessReject = 3
$AccountingRequest = 4
$AccountingResponse = 5
$AccessChallenge = 11
$StatusServer = 12
$StatusClient = 13
$DisconnectRequest = 40
$DisconnectACK = 41
$DisconnectNAK = 42
$ChangeOfAuthorizationRequest = 43
$ChangeOfAuthorizationACK = 44
$ChangeOgAuthorizationNAK = 45

#ACCT-Status-Type
$Start = 1
$Stop = 2
$InterimUpdate = 3
$AccountingOn = 7
$AccountingOff = 8

$Script:isDebugOn = $True

function PrintDebug($DebugMsg){
    if ($Script:isDebugOn){
        Write-Host $DebugMsg
    }

}

#Возвращает целое число секунд от 01/01/1970 до текущей даты
function GetDateIntSecFrom1970(){
    [int64]$Result = ((Get-Date -UFormat %s).Split(".,"))[0]
    Return $Result
}

#Подсчитывает сколько в данном числе секунд часов минут секунд
#Получает количество секунд
#Возвращает строку вида 11:23:59 hh:mm:ss
function DurationSecToHourMinSec ([int64]$DurationSec){
    $Result = ""
    $SecInMin = 60
    $SecInHour = 60 * $SecInMin

    if($DurationSec -lt 0){
        Write-Warning "  DurationSecToHourMinSec: Получено неверное число секунд: $DurationSec"
    } else {
        [int]$Hours   = [math]::Truncate( $DurationSec / $SecInHour )
        [int]$Minutes = [math]::Truncate( ($DurationSec % $SecInHour) / $SecInMin )
        [int]$Seconds = $DurationSec % $SecInMin
        $Result = [string]$Hours+ ":" + [string]$Minutes + ":" + [string]$Seconds
    }

    Return $Result    
}

#Удалить из массива с VPN сессиями все завершенные сессии
function PackOnlineVPNSesions(){
    $Script:OnlineVPNSessions = $Script:OnlineVPNSessions  | Where-Object {($_.SessionID -ne "") -and ($_.SessionID -ne $Null ) }
}

#Получает строку с датой временем вида MM/DD/YYYY hh:mm:ss.___ Например 02/01/2020 14:32:05.812
#Возвращаетколичество секунд от 01.01.1970 до этой даты
function ToSecFrom1970([datetime]$DateTime){
    $Result = Get-Date -UFormat %s -Year $DateTime.Year -Month $DateTime.Month -Day $DateTime.Day -Hour $DateTime.Hour -Minute $DateTime.Minute -Second $DateTime.Second -Millisecond $DateTime.Millisecond
    Return $Result
}

#Печать результатов каждые $MinSecBetweenPrintResult сек, если сообщения в логе появляются реже, то с каждым сообщением в логе
[int64]$Script:LastPrintResultSecFrom1970 = GetDateIntSecFrom1970
function PrintOnlineVPNSessions(){
    [int]$MinSecBetweenPrintResult = 5
    [int64]$CurrentSecFrom1970 = GetDateIntSecFrom1970
    if( $CurrentSecFrom1970 - $Script:LastPrintResultSecFrom1970 -ge $MinSecBetweenPrintResult ){
        $Script:LastPrintResultSecFrom1970 = $CurrentSecFrom1970
        PackOnlineVPNSesions
        $Script:OnlineVPNSessions  | Sort-Object -Property $SortVPNSessionsByField | Format-Table -Property UserName,UserDevName,DurationHMS,UserExternalIP,TunnelClientIP,NASServerExternalIP,NASServerInternalIP,RadiusServer,TunnelType,InputOctets,OutputOctets,Status
        Write-Host "Всего" $Script:OnlineVPNSessions.Count "сессий на " (Get-Date)

        #$Script:OnlineVPNSessions | Format-Table -Property UserName,UserDevName,DurationHMS,UserExternalIP
        #Write-Host "Всего" $Script:OnlineVPNSessions.Count "сессий"

        #Format-Table -Property UserName,UserDevName,DurationHMS,UserExternalIP,SessionID
        #|  Select-Object UserName,UserDevName,DurationHMS,UserExternalIP,SessionID
        #Where-Object {($_.SessionID -ne "") -and ($_.SessionID -ne $Null ) } |
        #| Out-GridView -Title "Активные VPN пользователи"
    }
}

#Паралельное чтение из нескольких файлов.
#Взято из http://coderoad.ru
Workflow GetSeveralFilesContent
{
    Param([string[]] $Files)

    ForEach -parallel ($file in $Files)
    {
        Get-Content -Path $file -Tail 0 -Wait
    }
}

#Обновляет поле Status в массиве с описанием каждой VPN-сессии
#Если последняя запись в логе для этой сессии меньше $MaxOnlineSec секунд, то сессия в состоянии $StatusOnline
#Если прошло секунд между $MaxOnlineSec и $MaxTimeOutSec, то стессия в состоянии $StatusWarning
#Если с последней записи в логе прошло больше $MaxTimeOutSec секунд, то сессия в состоянии $StatusError
function UpdateStatusForAllVPNSessions(){
    [int64]$CurrentSecFrom1970 = GetDateIntSecFrom1970
    ForEach($I in $Script:OnlineVPNSessions){
        [int64]$Sec = $CurrentSecFrom1970 - $I.LastActivitySecFrom1970
        if($Sec -ge $MaxTimeOutSec){
            $I.Status = $StatusError + " [" + $Sec + "]"
        }else{
            if($Sec -ge $MaxOnlineSec){
                $I.Status = $StatusWarning + " [" + $Sec + "]"
            }else{
                $I.Status = $StatusOnline + " [" + $Sec + "]"
            }
        }
    }
}

function DeleteSessionFromVPNSessionsArray($XMLOneLineLog){
    $isDeleted = $False
    ForEach($OneVPNSession in $Script:OnlineVPNSessions){
        if($OneVPNSession.SessionID -eq $XMLOneLineLog.Event."Acct-Session-Id"."#text"){
            $OneVPNSession.SessionID = ""
            $Msg = " Удаляю сессию " + $XMLOneLineLog.Event."Acct-Session-Id"."#text" + " пользователя " + $XMLOneLineLog.Event."User-Name"."#text"
            PrintDebug $Msg
            $isDeleted = $True
            Break
        }
    }
    if(-not $isDeleted){
        $Msg = " Cессия " + $XMLOneLineLog.Event."Acct-Session-Id"."#text" + " пользователя " + $XMLOneLineLog.Event."User-Name"."#text" + " не найдена для удаления. Если скрипт работает меньше 10 миут, то это нормально если больше 10 мин, то ошибка в скрипте"
        PrintDebug $Msg
    }
    #PackOnlineVPNSesions Почему-то при вызове отсюда в массиве остается одна пустая запись. Перенес в другое место
}

function UpdateVPNSessionsArray([xml]$XMLOneLine){
    $isVPNSessionInArray = $False
    $AcctSessionID = $XMLOneLine.Event."Acct-Session-Id"."#text"
    $UserName = [string]$XMLOneLine.Event."User-Name"."#text"
    if(($AcctSessionID -eq "") -or ($AcctSessionID -eq $Null)){
#        Write-Warning "В функцию UpdateVPNSessionsArray получен пакет с пустым атрибутом Acct-Session-Id " 
#        Write-Host $XMLOneLine
#        Write-Host $OLL
        return
    }
    ForEach( $I in $Script:OnlineVPNSessions){
        if( $I.SessionID -eq $AcctSessionID ){
            PrintDebug " Обновляю сессию  $AcctSessionID  пользователя $UserName"
            $I.DurationSec  = [int64]$XMLOneLine.Event."Acct-Session-Time"."#text"
            $I.DurationHMS = DurationSecToHourMinSec $I.DurationSec
            $I.RadiusServer        = [string]$XMLOneLine.Event."Computer-Name"."#text"
            if( ($I.TunnelClientIP -eq "") -or ($I.TunnelClientIP -eq $Null) ){
                $I.TunnelClientIP = [string]$XMLOneLine.Event."Framed-IP-Address"."#text";
            }
            $I.InputOctets  = [int64]$XMLOneLine.Event."Acct-Input-Octets"."#text"
            $I.InputPackets = [int64]$XMLOneLine.Event."Acct-Input-Packets"."#text"
            $I.OutputOctets = [int64]$XMLOneLine.Event."Acct-Output-Octets"."#text"
            $I.OutputPackets= [int64]$XMLOneLine.Event."Acct-Output-Packets"."#text"
            $I.LastDateTimeActivity=[string]$XMLOneLine.Event."Timestamp"."#text"
            $I.LastActivitySecFrom1970 = GetDateIntSecFrom1970
            $I.Status = $StatusOnline + "[0]";

            $isVPNSessionInArray = $True
        }
    }
    if( -not $isVPNSessionInArray){
        PrintDebug " Нашел сессию $AcctSessionID пользователя $UserName"
        $OneVPNSessionDesc = New-Object -Type PSObject -Property @{
            UserName            = $UserName;             #Имя пользователя этой сессии
            UserDevName         = [string]$XMLOneLine.Event."Tunnel-Client-Auth-ID"."#text"; #Имя устройства VPN-клиента
            DurationSec         = [int64]$XMLOneLine.Event."Acct-Session-Time"."#text";   #Длительность сессии в секундах. Подсчитывается NAS-сервером
            DurationHMS         = ""; #Длительность сессии в часы:минуты:секунды
            RadiusServer        = [string]$XMLOneLine.Event."Computer-Name"."#text";         #Имя Радиус-сервера, который первым принял эту сессию
            TunnelType          = [string]$XMLOneLine.Event."Tunnel-Assignment-ID"."#text";  #Тип туннеля
            UserExternalIP      = [string]$XMLOneLine.Event."Tunnel-Client-Endpt"."#text";   #Наружный IP адрес VPN-клиента
            NASServerExternalIP = [string]$XMLOneLine.Event."Tunnel-Server-Endpt"."#text";   #Наружный IP адрес NAS сервера-Radius клиента
#            UserExternalIPGeolocation = [string]"";                             #Географическое расположение IP адреса клиента из поля UserExternalIP
            TunnelClientIP      = [string]$XMLOneLine.Event."Framed-IP-Address"."#text";    #IP адрес VPN-клиента внутри VPN-туннеля
            NASServerInternalIP = [string]$XMLOneLine.Event."NAS-IP-Address"."#text";       #IP адрес NAS сервера-Radius клиента внутри VPN-туннеля
            InputOctets         = [int64]$XMLOneLine.Event."Acct-Input-Octets"."#text";     #Число входящих байт
            InputPackets        = [int64]$XMLOneLine.Event."Acct-Input-Packets"."#text";    #Число входящих пакетов
            OutputOctets        = [int64]$XMLOneLine.Event."Acct-Output-Octets"."#text";    #Число исходящих байт
            OutputPackets       = [int64]$XMLOneLine.Event."Acct-Output-Packets"."#text";   #Число исходящих пакетов
            SessionID           = $AcctSessionID;      #Уникальный номер VPN сессии. Соответствует полю Acct-Session-Id.
                                                       #Если пробел или $Null, то этот объект будет пропускаться при обработке
            LastDateTimeActivity    =[string]$XMLOneLine.Event."Timestamp"."#text"; #Время последней записи в логах для этой сессии.
            LastActivitySecFrom1970 = GetDateIntSecFrom1970 ; #Время последней записи в логах для этой сессии. В секундах с 01.01.1970
            Status = $StatusOnline + "[0]";
        }
        $OneVPNSessionDesc.DurationHMS = DurationSecToHourMinSec $OneVPNSessionDesc.DurationSec
        $Script:OnlineVPNSessions += $OneVPNSessionDesc
    }
}

function HandleOneLineLog([string]$OneLineLog){
    $XMLOneLineLog = [xml]$OneLineLog
    #Если пакет завершения сессии. то удалить запись об этой сессии
    if(($XMLOneLineLog.Event."Packet-Type"."#text" -eq $AccountingRequest) -and ($XMLOneLineLog.Event."Acct-Status-Type"."#text" -eq $Stop) ) {
        DeleteSessionFromVPNSessionsArray $XMLOneLineLog
    }else{
    #Иначе обновить информацию о сессии
        UpdateVPNSessionsArray $XMLOneLineLog
    }
    UpdateStatusForAllVPNSessions
    PrintOnlineVPNSessions
}

Write-Host "Анализ DTS-логов NPS-Radius сервера Windows. Показывает онлайн пользователей. Версия от 04.11.2020"
Write-Host "https://github.com/AlexandrGS/NPSLogOnline"
Write-Warning "Всех пользователей покажет примерно через 5-6 минут работы скрипта"
#Get-Content $LogFiles -Wait -Tail $CountFirstReadLines | ForEach-Object { HandleOneLineLog  $_ }

GetSeveralFilesContent ($LogFiles.Split($DelimiterOfFilesList)) | ForEach-Object { HandleOneLineLog  $_ }
