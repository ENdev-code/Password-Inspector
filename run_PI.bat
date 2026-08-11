@echo off
setlocal

REM ============================================================
REM           Password Inspector - One-Click Launcher
REM  + Sets up the virtual environment (if needed),
REM  + Installs dependencies (if needed),
REM  + Launches the interactive menu.
REM ============================================================

REM Setting terminal window title
title Password Inspector - Setup

echo ================================================================
echo                       PASSWORD INSPECTOR
echo                     One-Click Setup ^& Launch
echo ================================================================
echo
echo One moment, setting things up....
echo.

REM --- Move to the folder this .bat file lives in, regardless of
REM --- where it was double-clicked from ---
cd /d "%~dp0"

REM --- Step 1: Check if Python is installed, if not then prompt to download ---
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python was not found on your system.
    echo Please install Python 3.13+ from https://www.python.org/downloads/
    echo and make sure "Add Python to PATH" is checked during install.
    echo.
    pause
    exit /b 1
) else (
    echo Python version found, moving on...
)

REM --- Step 2: Create virtual environment if it doesn't exist yet ---
if not exist "venv\Scripts\activate.bat" (
    echo [1/3] Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
) else (
    echo [1/3] Virtual environment already exists, skipping creation.
)

REM --- Step 3: Activate the virtual environment ---
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment.
    pause
    exit /b 1
)

REM --- Step 4: Install dependencies (only if requirements.txt changed
REM --- since last install, tracked via a marker file) ---
set "MARKER=venv\.deps_installed"
set "NEEDS_INSTALL=1"

if exist "%MARKER%" (
    fc /b "%MARKER%" requirements.txt >nul 2>nul
    if not errorlevel 1 set "NEEDS_INSTALL=0"
)

if "%NEEDS_INSTALL%"=="1" (
    echo [2/3] Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
    copy /y requirements.txt "%MARKER%" >nul
) else (
    echo [2/3] Dependencies already installed, skipping.
)

REM --- Step 5: Launch Password Inspector's interactive menu ---
echo [3/3] Launching Password Inspector...
echo.
python password_inspector_cli.py

echo.
echo ================================================================
echo   Password Inspector closed. Press any key to exit this window.
echo ================================================================
pause >nul