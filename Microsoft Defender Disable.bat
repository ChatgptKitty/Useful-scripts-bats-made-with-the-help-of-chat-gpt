@echo off
title Disabling Windows Defender & Security Features
echo Stopping Windows Defender services...
timeout /t 2

rem Disable Windows Defender Policies
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

rem Disable Tamper Protection (Requires Safe Mode or Admin Privileges)
reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f

rem Disable Defender Services
for %%s in (
    BFE
    MDCoreSvc
    MpsSvc
    SgrmBroker
    WdBoot
    WdFilter
    WdNisDrv
    WdNisSvc
    WinDefend
) do (
    sc config %%s start= disabled
    net stop %%s
)

rem Disable Windows Defender Context Menu
reg delete "HKLM\Software\Classes\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKLM\Software\Classes\Drive\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKLM\Software\Classes\Directory\shellex\ContextMenuHandlers\EPP" /f

rem Disable Defender Scheduled Tasks
for %%t in (
    "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh"
    "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "Microsoft\Windows\Windows Defender\Windows Defender Verification"
) do (
    schtasks /Change /TN %%t /Disable
)

rem Disable Windows Security Tray Icon
taskkill /f /im SecurityHealthSystray.exe
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f

rem Disable SmartScreen
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /t REG_DWORD /d "0" /f

rem Prevent Defender from Restarting
takeown /f "%ProgramFiles%\Windows Defender" /a /r /d y
icacls "%ProgramFiles%\Windows Defender" /grant Administrators:F /t
attrib +h +s "%ProgramFiles%\Windows Defender"
rd /s /q "%ProgramFiles%\Windows Defender"

rem Block Defender Processes
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

rem Restart Computer (Defender may restart until rebooted)
shutdown /r /t 10
echo Restarting in 10 seconds... Press Ctrl + C to cancel.

pause

