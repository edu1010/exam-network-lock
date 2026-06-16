@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ============================================================================
rem  publish.cmd - Genera los .exe self-contained (con .NET embebido) en dist\
rem
rem  Doble clic para actualizar los ejecutables. Cada .exe lleva el runtime de
rem  .NET dentro, asi que corre en maquinas sin .NET instalado.
rem
rem  Uso opcional:  publish.cmd [RID]      (por defecto win-x64)
rem  Ejemplos:      publish.cmd            -> win-x64
rem                 publish.cmd win-x86    -> 32 bits
rem                 publish.cmd win-arm64  -> ARM64
rem ============================================================================

set "RID=%~1"
if "%RID%"=="" set "RID=win-x64"

set "PROJECTS=ExamLockClient ExamConfigGenerator ExamLogVerifier ExamLogVerifierUI"

rem --- Localizar dotnet (PATH o ruta por defecto) ---
set "DOTNET=dotnet"
where dotnet >nul 2>nul
if errorlevel 1 (
  if exist "%ProgramFiles%\dotnet\dotnet.exe" (
    set "DOTNET=%ProgramFiles%\dotnet\dotnet.exe"
  ) else (
    echo [ERROR] No se encontro 'dotnet'. Instala el .NET 8 SDK desde https://dotnet.microsoft.com/download
    echo.
    pause
    exit /b 1
  )
)

echo ============================================================
echo  Publicando exam-network-lock  ^|  RID: %RID%
echo  Salida: %~dp0dist
echo ============================================================
echo.

rem --- Limpiar salida anterior para que dist solo tenga lo nuevo ---
if exist "%~dp0dist" rmdir /s /q "%~dp0dist"

for %%P in (%PROJECTS%) do (
  echo --- %%P ...
  "%DOTNET%" publish "%~dp0%%P\%%P.csproj" -c Release -r %RID% --self-contained true ^
    -p:DebugType=none -p:DebugSymbols=false -o "%~dp0dist\%%P" --nologo -v minimal
  if errorlevel 1 (
    echo.
    echo [ERROR] Fallo al publicar %%P  ^(codigo !errorlevel!^)
    echo.
    pause
    exit /b 1
  )
  echo.
)

echo ============================================================
echo  Listo. Ejecutables generados:
echo ============================================================
powershell -NoProfile -Command "Get-ChildItem '%~dp0dist\*\*.exe' | Select-Object @{N='Exe';E={$_.Name}}, @{N='MB';E={[math]::Round($_.Length/1MB,1)}}, @{N='Ruta';E={$_.FullName}} | Format-Table -AutoSize"

echo.
pause
endlocal
