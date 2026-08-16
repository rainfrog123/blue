@echo off
setlocal enabledelayedexpansion

:: Navigate to the scrcpy directory
cd C:\Users\jar71\Downloads\scrcpy-win64-v2.3.1\scrcpy-win64-v2.3.1

:: Infinite loop to perform the automated clicks
:loop
    :: Perform the first click and wait for 2 seconds
    adb shell input tap 536 886
    timeout /t 2 >nul

    :: Perform the second click and wait for 2 seconds
    adb shell input tap 1096 144
    timeout /t 2 >nul

    :: Perform the third click and wait for 2 seconds
    adb shell input tap 617 1594
    timeout /t 2 >nul

    :: Perform the fourth click and wait for 4 seconds
    adb shell input tap 801 1433
    timeout /t 4 >nul

:: Loop back to the start
goto loop

:: End of script (not reachable unless the script is manually stopped)
echo Done!
pause
