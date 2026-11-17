@echo off
rem ---------------------------------------------------------------------------
rem Build all Delpheed tools (both 32-bit and 64-bit) into bin\.
rem
rem Supports:
rem   1. Delphi command-line compilers (dcc32 + dcc64, Pro/Enterprise/Architect)
rem   2. Free Pascal (fpc / ppc386 + ppcx64) - used automatically if Delphi
rem      CLI compiling is unavailable (e.g. RAD Studio Community Edition).
rem
rem If you only have RAD Studio Community Edition without FPC, open
rem Delpheed.groupproj in the RAD Studio IDE and choose Project -> Build All.
rem ---------------------------------------------------------------------------
setlocal EnableDelayedExpansion
set OUT=bin
set DCU32=dcu\Win32
set DCU64=dcu\Win64
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%DCU32%" mkdir "%DCU32%"
if not exist "%DCU64%" mkdir "%DCU64%"

set USE_DELPHI=0
where dcc32 >nul 2>nul
if not errorlevel 1 (
  if exist "%OUT%\VMTScan.exe" del /f /q "%OUT%\VMTScan.exe" >nul 2>nul
  dcc32 -B -Q -NSSystem;Winapi -AGenerics.Collections=System.Generics.Collections;Generics.Defaults=System.Generics.Defaults;TlHelp32=Winapi.TlHelp32;WinTypes=Winapi.Windows;WinProcs=Winapi.Windows -E"%OUT%" -NU"%DCU32%" VMTScan.dpr >"%OUT%\dcc_probe.log" 2>&1
  if exist "%OUT%\VMTScan.exe" (
    set USE_DELPHI=1
  ) else (
    type "%OUT%\dcc_probe.log"
  )
  if exist "%OUT%\dcc_probe.log" del /f /q "%OUT%\dcc_probe.log" >nul 2>nul
)

if "%USE_DELPHI%"=="1" goto :build_delphi

rem ---- Try Free Pascal (fpc) ----
set FPC_EXE=
where fpc >nul 2>nul
if not errorlevel 1 (
  for /f "delims=" %%P in ('where fpc') do if "!FPC_EXE!"=="" set FPC_EXE=%%P
)
if "%FPC_EXE%"=="" if exist "C:\FPC\3.2.2\bin\i386-win32\fpc.exe" set "FPC_EXE=C:\FPC\3.2.2\bin\i386-win32\fpc.exe"
if "%FPC_EXE%"=="" if exist "C:\FPC\3.2.2\bin\x86_64-win64\fpc.exe" set "FPC_EXE=C:\FPC\3.2.2\bin\x86_64-win64\fpc.exe"
if "%FPC_EXE%"=="" if exist "C:\lazarus\fpc\3.2.2\bin\x86_64-win64\fpc.exe" set "FPC_EXE=C:\lazarus\fpc\3.2.2\bin\x86_64-win64\fpc.exe"
if "%FPC_EXE%"=="" if exist "C:\lazarus\fpc\3.2.2\bin\i386-win32\fpc.exe" set "FPC_EXE=C:\lazarus\fpc\3.2.2\bin\i386-win32\fpc.exe"

if not "%FPC_EXE%"=="" goto :build_fpc

echo.
echo Neither working Delphi CLI compilers (dcc32/dcc64) nor Free Pascal (fpc) were found.
echo Note: RAD Studio Community Edition disables dcc32/dcc64 command-line compiling.
echo   - In RAD Studio IDE: open Delpheed.groupproj and click Project -^> Build All.
echo   - Or install Free Pascal 3.2.2+ (Win32 + Win64) and re-run build.bat.
exit /b 1

:build_delphi
echo === Building with Delphi (dcc32 / dcc64) ===
set "DFLAGS=-B -Q -NSSystem;Winapi -AGenerics.Collections=System.Generics.Collections;Generics.Defaults=System.Generics.Defaults;TlHelp32=Winapi.TlHelp32;WinTypes=Winapi.Windows;WinProcs=Winapi.Windows"
for %%T in (VMTScan Unpack OEPScan Delpheed) do (
  echo Building 32-bit %%T ...
  if exist "%OUT%\%%T.exe" del /f /q "%OUT%\%%T.exe" >nul 2>nul
  dcc32 %DFLAGS% -E"%OUT%" -NU"%DCU32%" %%T.dpr
  if errorlevel 1 goto :err
  if not exist "%OUT%\%%T.exe" goto :err
)
where dcc64 >nul 2>nul
if errorlevel 1 (
  echo dcc64 not found on PATH - skipping 64-bit tools.
  goto :done
)
for %%T in (VMTScan64 OEPScan64 Delpheed64) do (
  echo Building 64-bit %%T ...
  if exist "%OUT%\%%T.exe" del /f /q "%OUT%\%%T.exe" >nul 2>nul
  dcc64 %DFLAGS% -E"%OUT%" -NU"%DCU64%" %%T.dpr
  if errorlevel 1 goto :err
  if not exist "%OUT%\%%T.exe" goto :err
)
goto :done

:build_fpc
echo === Building with Free Pascal (%FPC_EXE%) ===
for %%D in ("%FPC_EXE%") do set "FPC_DIR=%%~dpD"
set "PATH=%FPC_DIR%;C:\FPC\3.2.2\bin\i386-win32;C:\FPC\3.2.2\bin\x86_64-win64;%PATH%"

for %%T in (VMTScan Unpack OEPScan Delpheed) do (
  echo Building 32-bit %%T ...
  if exist "%OUT%\%%T.exe" del /f /q "%OUT%\%%T.exe" >nul 2>nul
  "%FPC_EXE%" -Pi386 -Twin32 -Mdelphi -O2 -FE"%OUT%" -FU"%DCU32%" %%T.dpr
  if errorlevel 1 goto :err
  if not exist "%OUT%\%%T.exe" goto :err
)

for %%T in (VMTScan64 OEPScan64 Delpheed64) do (
  echo Building 64-bit %%T ...
  if exist "%OUT%\%%T.exe" del /f /q "%OUT%\%%T.exe" >nul 2>nul
  "%FPC_EXE%" -Px86_64 -Twin64 -Mdelphi -O2 -FE"%OUT%" -FU"%DCU64%" %%T.dpr
  if errorlevel 1 goto :err
  if not exist "%OUT%\%%T.exe" goto :err
)

:done
echo.
echo Done. Binaries are in "%OUT%\".
exit /b 0

:err
echo.
echo Build FAILED.
exit /b 1
