@echo off
rem ====================================================================
rem Obscura Cross-Compilation Script (Windows)
rem ====================================================================
rem This script cross-compiles the project for different target platforms.
rem
rem Requirements:
rem - Rust toolchain
rem - cross (cargo install cross)
rem - Docker (for cross-compilation)
rem
rem Usage:
rem   scripts\cross-compile.bat [options] [targets...]
rem
rem Options:
rem   --release      Build in release mode
rem   --all          Build for all supported targets
rem   --package NAME Only build the specified package
rem
rem Targets (if not specified, default is your current platform):
rem   linux-x86_64       Linux (x86_64)
rem   linux-aarch64      Linux (ARM64)
rem   windows-x86_64     Windows (x86_64)
rem   windows-i686       Windows (x86)
rem   android-aarch64    Android (ARM64)
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Define constants
set OUTPUT_DIR=target\cross-compiled

rem Define supported targets
set SUPPORTED_TARGETS=x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-pc-windows-gnu i686-pc-windows-gnu aarch64-linux-android

rem Process arguments
set RELEASE_FLAG=
set PACKAGE_FLAG=
set BUILD_ALL=0
set SELECTED_TARGETS=

:parse_args
if "%1"=="" goto after_args
if "%1"=="--release" (
  set RELEASE_FLAG=--release
  shift
  goto parse_args
)
if "%1"=="--all" (
  set BUILD_ALL=1
  shift
  goto parse_args
)
if "%1"=="--package" (
  set PACKAGE_FLAG=--package %2
  shift
  shift
  goto parse_args
)

rem Check if the argument is a valid target
if "%1"=="linux-x86_64" (
  set SELECTED_TARGETS=%SELECTED_TARGETS% x86_64-unknown-linux-gnu
  shift
  goto parse_args
)
if "%1"=="linux-aarch64" (
  set SELECTED_TARGETS=%SELECTED_TARGETS% aarch64-unknown-linux-gnu
  shift
  goto parse_args
)
if "%1"=="windows-x86_64" (
  set SELECTED_TARGETS=%SELECTED_TARGETS% x86_64-pc-windows-gnu
  shift
  goto parse_args
)
if "%1"=="windows-i686" (
  set SELECTED_TARGETS=%SELECTED_TARGETS% i686-pc-windows-gnu
  shift
  goto parse_args
)
if "%1"=="android-aarch64" (
  set SELECTED_TARGETS=%SELECTED_TARGETS% aarch64-linux-android
  shift
  goto parse_args
)

rem Unknown argument, skip it
shift
goto parse_args

:after_args

rem If --all is specified, build all targets
if %BUILD_ALL%==1 (
  set SELECTED_TARGETS=%SUPPORTED_TARGETS%
)

rem If no targets are specified, build for the current platform
if "%SELECTED_TARGETS%"=="" (
  for /f "tokens=2 delims=:" %%a in ('rustc -Vv ^| findstr host') do set CURRENT_TARGET=%%a
  set CURRENT_TARGET=%CURRENT_TARGET:~1%
  set SELECTED_TARGETS=%CURRENT_TARGET%
)

echo =====================================================================
echo             Cross-compiling Obscura                                  
echo =====================================================================
echo Building for targets: %SELECTED_TARGETS%
echo Release mode: %RELEASE_FLAG%
echo Package: %PACKAGE_FLAG%
echo =====================================================================

rem Check if cross is installed
cross --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo The 'cross' tool is not installed. Installing now...
  cargo install cross
)

rem Check if Docker is running
docker info >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo Error: Docker is not running. Please start Docker and try again.
  exit /b 1
)

rem Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

rem Build for each target
for %%t in (%SELECTED_TARGETS%) do (
  echo.
  echo Building for %%t...
  
  rem Run the build command
  echo Running: cross build --target %%t %RELEASE_FLAG% %PACKAGE_FLAG%
  cross build --target %%t %RELEASE_FLAG% %PACKAGE_FLAG%
  
  if %ERRORLEVEL% NEQ 0 (
    echo Build failed for target: %%t
    goto next_target
  )
  
  rem Determine binary extension
  set BIN_EXT=
  echo %%t | findstr "windows" >nul
  if %ERRORLEVEL% EQU 0 set BIN_EXT=.exe
  
  rem Create target-specific output directory
  set TARGET_OUTPUT_DIR=%OUTPUT_DIR%\%%t
  if not exist "%TARGET_OUTPUT_DIR%" mkdir "%TARGET_OUTPUT_DIR%"
  
  rem Copy the built binaries to the output directory
  if "%RELEASE_FLAG%"=="--release" (
    set BUILD_TYPE=release
  ) else (
    set BUILD_TYPE=debug
  )
  
  echo Copying binaries to %TARGET_OUTPUT_DIR%...
  
  rem Copy all relevant binaries
  for %%f in (target\%%t\%BUILD_TYPE%\*%BIN_EXT%) do (
    if exist "%%f" copy "%%f" "%TARGET_OUTPUT_DIR%\" >nul
  )
  
  echo Build completed for %%t. Binaries available in %TARGET_OUTPUT_DIR%
  
  :next_target
)

echo.
echo Cross-compilation complete!
echo Binaries are available in: %OUTPUT_DIR% 