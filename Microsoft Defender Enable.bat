@echo off
title Restoring Windows Defender & Security Features
echo Enabling Windows Defender and security features...
timeout /t 2

rem Restore Defender Policies
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "1" /f

rem Restore Tamper Protection (May require Windows Update)
reg add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "1" /f

rem Restore Defender Services
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
    sc config %%s start= auto
    net start %%s
)

rem Restore Defender Context Menu
reg add "HKLM\Software\Classes\*\shellex\ContextMenuHandlers\EPP" /ve /t REG_SZ /d "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg add "HKLM\Software\Classes\Drive\shellex\ContextMenuHandlers\EPP" /ve /t REG_SZ /d "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg add "HKLM\Software\Classes\Directory\shellex\ContextMenuHandlers\EPP" /ve /t REG_SZ /d "{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f

rem Enable Defender Scheduled Tasks
for %%t in (
    "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh"
    "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "Microsoft\Windows\Windows Defender\Windows Defender Verification"
) do (
    schtasks /Change /TN %%t /Enable
)

rem Restore Windows Security Tray Icon
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /t REG_EXPAND_SZ /d "\"%windir%\system32\SecurityHealthSystray.exe\"" /f
start "" "%windir%\system32\SecurityHealthSystray.exe"

rem Restore SmartScreen
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "RequireAdmin" /f
reg add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /t REG_DWORD /d "1" /f

rem Restore Defender File Permissions (May require Safe Mode)
takeown /f "%ProgramFiles%\Windows Defender" /a /r /d y
icacls "%ProgramFiles%\Windows Defender" /grant SYSTEM:F /t

rem Restore Defender Files (May require Windows Update)
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

rem Restart Computer (Required for full re-enablement)
shutdown /r /t 10
echo Restarting in 10 seconds... Press Ctrl + C to cancel.

pause


