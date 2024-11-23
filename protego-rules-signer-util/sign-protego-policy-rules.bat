@echo off
setlocal

set "RUN_DIR=%cd%"
set "SCRIPT_DIR=%~dp0"

echo Scrip is running in: %RUN_DIR%
echo Script is located in: %SCRIPT_DIR%

cd "%SCRIPT_DIR%"

mvn clean package exec:java -Dexec.args="%RUN_DIR%"

cd "%RUN_DIR%"
endlocal
