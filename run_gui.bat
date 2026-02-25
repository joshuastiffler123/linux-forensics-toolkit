@echo off
:: ─────────────────────────────────────────────────────────────────────────────
:: Linux Forensics Toolkit — GUI launcher for Windows
::
:: Usage:
::   Double-click run_gui.bat in File Explorer
::   — or —
::   run_gui.bat   (from any Command Prompt or PowerShell window)
::
:: Requirements: Python 3.8+ on PATH (https://python.org)
::               PyQt6 is installed automatically if missing.
:: ─────────────────────────────────────────────────────────────────────────────
setlocal EnableDelayedExpansion

:: ── Locate Python ─────────────────────────────────────────────────────────────
set PYTHON=

:: Try 'py' launcher first (installed by the official Python installer on Windows)
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set PYTHON=py -3
    goto :found_python
)

:: Fall back to plain python3 / python on PATH
where python3 >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set PYTHON=python3
    goto :found_python
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    :: Confirm it is actually Python 3, not Python 2
    for /f "delims=" %%v in ('python -c "import sys; print(sys.version_info.major)"') do set PYMAJ=%%v
    if "!PYMAJ!"=="3" (
        set PYTHON=python
        goto :found_python
    )
)

echo.
echo  ERROR: Python 3 was not found on your PATH.
echo.
echo  Please install Python 3.8+ from https://www.python.org/downloads/
echo  and make sure "Add Python to PATH" is checked during setup.
echo.
pause
exit /b 1

:found_python
echo  Python found: %PYTHON%

:: ── Check Python version ─────────────────────────────────────────────────────
for /f "delims=" %%v in ('%PYTHON% -c "import sys; print(sys.version)"') do (
    echo  Version: %%v
)

:: ── Check / install PyQt6 ────────────────────────────────────────────────────
echo.
%PYTHON% -c "import PyQt6" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  PyQt6 not found. Installing now...
    echo  ^(You can also run:  pip install PyQt6  to do this manually^)
    echo.
    %PYTHON% -m pip install "PyQt6>=6.4.0"
    if %ERRORLEVEL% neq 0 (
        echo.
        echo  ERROR: Failed to install PyQt6.
        echo  Try running the following manually and then re-launch:
        echo.
        echo      pip install PyQt6
        echo.
        pause
        exit /b 1
    )
    echo  PyQt6 installed successfully.
)

:: ── Launch GUI ────────────────────────────────────────────────────────────────
echo.
echo  Starting Linux Forensics Toolkit GUI...
echo.

:: %~dp0 expands to the directory of this .bat file (with trailing backslash)
%PYTHON% "%~dp0linux_forensics_gui.py"

:: Only pause on non-zero exit so the window stays open if something went wrong
if %ERRORLEVEL% neq 0 (
    echo.
    echo  GUI exited with error code %ERRORLEVEL%.
    pause
)

endlocal
