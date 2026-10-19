@echo off
setlocal EnableExtensions
 title RECOVERat Installer

rem Always work in the same folder as this installer (for example E:\RECOVERat).
pushd "%~dp0" || (
    echo ERROR: Could not access the RECOVERat folder.
    pause
    exit /b 1
)

set "ZIP=%CD%\SysinternalsSuite.zip"
set "URL=https://download.sysinternals.com/files/SysinternalsSuite.zip"

echo ======================================
echo         RECOVERat Installer
echo ======================================
echo Installing Sysinternals Suite into:
echo %CD%
echo.

where curl.exe >nul 2>&1 || (
    echo ERROR: curl.exe is unavailable.
    goto :fail
)

echo Downloading from Microsoft...
curl.exe --fail --location --retry 3 --output "%ZIP%" "%URL%"
if errorlevel 1 (
    echo ERROR: Download failed.
    goto :fail
)

echo.
echo Extracting into RECOVERat...
powershell.exe -NoProfile -Command "try { Expand-Archive -LiteralPath $env:ZIP -DestinationPath (Get-Location).Path -Force -ErrorAction Stop } catch { Write-Error $_; exit 1 }"
if errorlevel 1 (
    echo ERROR: Extraction failed. Keeping ZIP for troubleshooting.
    goto :fail
)

del /q "%ZIP%" >nul 2>&1

echo.
echo Checking essential utilities...
set "MISSING=0"
for %%T in (Autoruns64.exe procexp64.exe Procmon64.exe Tcpview64.exe handle64.exe sigcheck64.exe) do (
    if not exist "%%T" (
        echo Missing: %%T
        set "MISSING=1"
    )
)
rem This is a download and extraction check, not a signature verification.
echo.
echo Installation completed. Tools are in %CD%
echo Run tools only after verifying their Microsoft digital signatures.
popd
pause
exit /b 0

:fail
popd
pause
exit /b 1
