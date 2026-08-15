@echo off
setlocal

set "ROOT=%~dp0..\..\"
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
set "ZIP=%ROOT%jom_1_1_4.zip"
set "JOM_EXE=%ROOT%Qt\Tools\QtCreator\bin\jom.exe"

if exist "%JOM_EXE%" goto done

if not exist "%ZIP%" (
  curl -fL -o "%ZIP%" "https://download.qt.io/official_releases/jom/jom_1_1_4.zip" || exit /b 1
)

if not exist "%ROOT%Qt\Tools\QtCreator\bin\" mkdir "%ROOT%Qt\Tools\QtCreator\bin" || exit /b 1
"C:\Program Files\7-Zip\7z.exe" x -aoa -o"%ROOT%Qt\Tools\QtCreator\bin\" "%ZIP%" || exit /b 1

:done
endlocal
exit /b 0
