@echo off

echo Running MAS script...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "irm https://get.activated.win | iex"

pause
