
@echo off
setlocal EnableExtensions
title Internet Connection Check

:: ============================================================
:: DETECT WINDOWS LANGUAGE
:: ============================================================

set "LANG_ID=en"

for /f "delims=" %%L in ('powershell.exe -NoProfile -Command "[System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName" 2^>nul') do set "LANG_ID=%%L"

:: ============================================================
:: TRANSLATIONS
:: ============================================================

set "MSG_OK=Internet connection detected. Continuing..."
set "MSG_FAIL=An internet connection is required to continue."
set "MSG_RETRY=Connect to the internet, then press ENTER to try again."
set "MSG_CHECK=Checking internet connection..."

if /i "%LANG_ID%"=="pt" (
    set "MSG_OK=Conexao com a internet detectada. Continuando..."
    set "MSG_FAIL=E necessario ter conexao com a internet para continuar."
    set "MSG_RETRY=Conecte-se a internet e pressione ENTER para tentar novamente."
    set "MSG_CHECK=Verificando conexao com a internet..."
)

if /i "%LANG_ID%"=="es" (
    set "MSG_OK=Conexion a internet detectada. Continuando..."
    set "MSG_FAIL=Se necesita conexion a internet para continuar."
    set "MSG_RETRY=Conectese y pulse ENTER para volver a intentarlo."
    set "MSG_CHECK=Comprobando conexion a internet..."
)

:: ============================================================
:: CHECK INTERNET
:: ============================================================

:CHECK_INTERNET
echo.
echo %MSG_CHECK%

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$urls = @('https://www.microsoft.com','https://www.google.com/generate_204','https://raw.githubusercontent.com'); foreach ($url in $urls) { try { $r = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 5 -MaximumRedirection 5 -UseBasicParsing -ErrorAction Stop; if ([int]$r.StatusCode -ge 200 -and [int]$r.StatusCode -lt 400) { exit 0 } } catch {} }; exit 1" >nul 2>&1

if not errorlevel 1 (
    echo.
    echo [OK] %MSG_OK%
    exit /b 0
)

echo.
echo [!] %MSG_FAIL%
echo %MSG_RETRY%
set "RETRY="
set /p "RETRY=> "
goto CHECK_INTERNET
