@echo off
setlocal

set "ROOT=%~dp0..\.."
set "JOM_BIN=%ROOT%\Qt\Tools\QtCreator\bin\jom.exe"
set "JOM_ZIP=%ROOT%\.jom_1_1_4.zip"
set "JOM_URL=https://download.qt.io/official_releases/jom/jom_1_1_4.zip"

if exist "%JOM_BIN%" goto done

if not exist "%JOM_ZIP%" (
    curl -LsS --fail -o "%JOM_ZIP%" "%JOM_URL%"
    if ERRORLEVEL 1 goto failed
)

"C:\Program Files\7-Zip\7z.exe" x -aoa -o"%ROOT%\Qt\Tools\QtCreator\bin\" "%JOM_ZIP%"
if ERRORLEVEL 1 goto failed

if not exist "%JOM_BIN%" goto failed

:done

REM dir %~dp0..\..\
REM dir %~dp0..\..\Qt
REM dir %~dp0..\..\Qt\Tools

goto :eof

:failed
echo Failed to install jom.exe
exit /b 1
