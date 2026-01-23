@echo off
:: Simple batch file to run a PowerShell script as admin with bypass
:: Usage: Save this file in the same directory as your .ps1 script
:: Set the path to your PowerShell script here
set script_name=TamperGuard.ps1
:: Check if the script exists
if not exist "%script_name%" (
    echo Error: "%script_name%" not found!
    pause
    exit /b 1
)
:: Launch PowerShell as admin to execute the script
powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"%~dp0%script_name%\"' -Verb RunAs"