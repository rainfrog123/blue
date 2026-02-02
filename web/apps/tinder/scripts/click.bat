@echo off
echo Changing to ADB directory...
cd /d C:\Users\jar71\Downloads\scrcpy-win64-v2.3.1\scrcpy-win64-v2.3.1
echo Current directory is:
cd
echo.
echo Checking for adb.exe...
if exist adb.exe (
    echo Found adb.exe
) else (
    echo ERROR: adb.exe not found in current directory!
    echo Current directory contents:
    dir
    pause
    exit /b 1
)
echo.
echo Starting click sequence...

:: Check if ADB is available
adb devices | findstr "device$" > nul
if errorlevel 1 (
    echo [%time%] Error: No device connected or ADB not found
    echo Please connect your device and ensure USB debugging is enabled
    pause
    exit /b 1
)

:: Initialize counters
set /a cycles=0
set /a total_clicks=0

:: Clear screen and show instructions
cls
echo ===============================================
echo Automated Clicker - Controls:
echo ===============================================
echo Press Ctrl+C to stop the script
echo Press any key to start...
echo ===============================================
pause > nul

:loop
set /a cycles+=1
cls
echo ===============================================
echo Current Status:
echo Cycles completed: %cycles%
echo Total clicks: %total_clicks%
echo ===============================================

:: First click
echo [%time%] Clicking at 460,782
adb shell input tap 460 782
timeout /t 2 /nobreak > nul
set /a total_clicks+=1

:: Second click
echo [%time%] Clicking at 1093,166
adb shell input tap 1093 166
timeout /t 2 /nobreak > nul
set /a total_clicks+=1

:: Third click
echo [%time%] Clicking at 320,1442
adb shell input tap 320 1442
timeout /t 2 /nobreak > nul
set /a total_clicks+=1

:: Fourth click
echo [%time%] Clicking at 830,1311
adb shell input tap 830 1311
timeout /t 3 /nobreak > nul
set /a total_clicks+=1

:: Add random delay between cycles (2 to 4 seconds)
set /a random_delay=%random% %% 3 + 2
timeout /t %random_delay% /nobreak > nul

echo [%time%] Cycle %cycles% complete
echo ===============================================
echo Press Ctrl+C to stop
echo ===============================================
echo.

:: Check device connection every 5 cycles
if %cycles% equ 5 (
    set /a cycles=0
    adb devices | findstr "device$" > nul
    if errorlevel 1 (
        echo [%time%] Error: Device disconnected
        echo Waiting for device reconnection...
        adb wait-for-device
        echo [%time%] Device reconnected, resuming...
    )
)

goto loop 