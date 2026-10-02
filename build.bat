@echo off
rem ---------------------------------------------------------------------------
rem Build ue5hook.dll, injector.exe and selftest.exe.
rem
rem Two deliberate choices, both learned the hard way on a real target:
rem
rem   * NMake, not "Visual Studio 18 2026". A standalone CMake older than the
rem     installed Visual Studio has no generator for it and rejects that name
rem     with "Could not create named generator". NMake drives the same toolchain
rem     and only needs vcvars to be active.
rem
rem   * vswhere, not a hardcoded install path. vswhere ships with every Visual
rem     Studio 2017+ install, so this script works on someone else's machine.
rem ---------------------------------------------------------------------------
setlocal enabledelayedexpansion

cd /d "%~dp0"

rem ---- locate Visual Studio -------------------------------------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [build] vswhere.exe not found.
    echo [build] Install Visual Studio with the "Desktop development with C++" workload.
    exit /b 1
)

set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if "%VSPATH%"=="" (
    echo [build] No Visual Studio install with the C++ toolset was found.
    echo [build] Add the "Desktop development with C++" workload.
    exit /b 1
)

set "VCVARS=%VSPATH%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [build] vcvars64.bat not found under "%VSPATH%"
    exit /b 1
)
echo [build] Visual Studio: %VSPATH%

call "%VCVARS%" >nul
if errorlevel 1 (
    echo [build] failed to activate the MSVC environment
    exit /b 1
)

rem ---- fetch MinHook if it is not there yet ----------------------------------
if not exist "third_party\minhook\include\MinHook.h" (
    echo [build] MinHook not present, fetching...
    where git >nul 2>nul
    if errorlevel 1 (
        echo [build] git is required to fetch MinHook.
        exit /b 1
    )
    if not exist "third_party" mkdir "third_party"
    git clone --depth 1 https://github.com/TsudaKageyu/minhook.git third_party\minhook
    if errorlevel 1 exit /b 1
)

rem ---- build ----------------------------------------------------------------
cmake -S . -B build -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

cmake --build build
if errorlevel 1 exit /b 1

echo.
echo [build] ok
echo   build\bin\ue5hook.dll
echo   build\bin\injector.exe
echo   build\bin\selftest.exe
endlocal
