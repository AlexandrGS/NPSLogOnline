	Скрипт NPSLogOnline.ps1 анализируя логи Windows NPS-Radius сервера и показывает информацию о активных VPN-сессиях. Логи Radius-сервера должны быть в DTS-формате.
	Автор Александр Ситько alexandrDOTsitkoATgmailDOTcom
	На вход подается один или несколько логов RADIUS-сервера. На экран выводится таблица активных сессий, а в самом низу - их количество. Далее скрипт ждет примерно 10 сек. Потом ожидает следующей записи в логах и опять выводит эту таблицу.
	На данный момент показывает имя пользователя, имя хоста пользователя, длительность сессии в часах минутах секундах, внешний IP адрес пользователя, IP адрес пользователя внутри VPN-туннеля, внешний адрес Radius-клиента-NAS-сервера,его же внутренний адрес, имя Radius-сервера, количество входящих и исходящих байт.
	Самый последний столбец - Status. Он показывает как давно в логах Radius-сервера была последняя запись об этой VPN сессии. Слово Online говорит что меньше 5 мин назад, "Простой" говорит что от 5 до 10 мин назад. "Превышено время" - последняя запись об этой сессии была более 10 мин назад. При нормальной работе систем могут быть только два первых сообщения.
	Последнее число в квадратных скобках показывает сколько секунд назад в логах Radius-сервера была последняя запись об этой сессии.
	Если понадобится изменить список выводимых столбцов таблицы, отредактируйте строку "Format-Table -Property UserName,UserDevName,DurationHMS,UserExternalIP, ...". Допустимые поля смотри в коде скрипта в объявлении объекта $OneVPNSessionDesc. Ниже в этом документе я привел фрагмент кода с описанием этого объекта.
	Все пользователи появляются примерно через 5 минут работы скрипта. Такое время потому что Radius-клиент посялает пакеты о состоянии соединения Radius-серверу примерно каждые 5 минут. Так у моего сервера.

Входные параметры:
	-LogFiles               - активные лог-файлы NPS-Radius сервера. Можно указать один или несколько файлов. Должны быть разделены символом запятая
	-SortVPNSessionsByField - по какому полю упорядочивает выводимые результаты. Допустимые поля берутся из того же объекта $OneVPNSessionDesc. По умолчанию упорядочивает по полю имени пользователя (поле UserName)

Описание объекта $OneVPNSessionDesc

$OneVPNSessionDesc = New-Object -Type PSObject -Property @{
	UserName            = $UserName;                                                 #Имя пользователя этой сессии
	UserDevName         = [string]$XMLOneLine.Event."Tunnel-Client-Auth-ID"."#text"; #Имя устройства VPN-клиента
	DurationSec         = [int64]$XMLOneLine.Event."Acct-Session-Time"."#text";   #Длительность сессии в секундах. Подсчитывается NAS-сервером
	DurationHMS         = ""; #Длительность сессии в часы:минуты:секунды
	RadiusServer        = [string]$XMLOneLine.Event."Computer-Name"."#text";         #Имя Радиус-сервера, который первым принял эту сессию
	TunnelType          = [string]$XMLOneLine.Event."Tunnel-Assignment-ID"."#text";  #Тип туннеля
	UserExternalIP      = [string]$XMLOneLine.Event."Tunnel-Client-Endpt"."#text";   #Наружный IP адрес VPN-клиента
	NASServerExternalIP = [string]$XMLOneLine.Event."Tunnel-Server-Endpt"."#text";   #Наружный IP адрес NAS сервера-Radius клиента
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

Примеры

Анализирует файл in2011.log, выходную таблицу упорядочивает по умолчанию по имени пользователя
.\NPSLogOnline.ps1 -LogFiles "c:\Windows\System32\LogFiles\in2011.log"

Анализирует два лог-файла. Упорядочивает выходную таблицу по длительности сессии
.\NPSLogOnline.ps1 -LogFiles "\\192.168.10.10\c$\Windows\System32\LogFiles\in2011.log,\\192.168.10.11\c$\Windows\System32\LogFiles\in2011.log" -SortVPNSessionsByField  "DurationSec"

Анализирует один лог-файл из текущей папки и таблица упорядочивается по количеству входящих байт в сессии
.\NPSLogOnline.ps1 -LogFiles "in2011.log" -SortVPNSessionsByField  "InputOctets "