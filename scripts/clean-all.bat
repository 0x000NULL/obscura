@echo off
rem ====================================================================
rem Obscura Deep Clean Script (Windows)
rem ====================================================================
rem This script performs a deep clean of the project, removing all 
rem build artifacts, temporary files, and other generated content.
rem
rem Requirements:
rem - Rust toolchain
rem - Git
rem
rem Usage:
rem   scripts\clean-all.bat [options]
rem     Options:
rem       --dry-run    Don't delete anything, just show what would be removed
rem       --keep-lock  Preserve the Cargo.lock file
rem       --aggressive Remove additional directories (target, .cargo, etc.)
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Process arguments
set DRY_RUN=0
set KEEP_LOCK=0
set AGGRESSIVE=0

:process_args
if "%1"=="" goto after_args
if "%1"=="--dry-run" (
  set DRY_RUN=1
  shift
  goto process_args
)
if "%1"=="--keep-lock" (
  set KEEP_LOCK=1
  shift
  goto process_args
)
if "%1"=="--aggressive" (
  set AGGRESSIVE=1
  shift
  goto process_args
)
shift
goto process_args

:after_args

echo =====================================================================
echo                Obscura Deep Clean                                    
echo =====================================================================

if %DRY_RUN%==1 (
  echo DRY RUN MODE: No files will be deleted.
)

rem Function equivalent to delete files/directories
:delete
if %DRY_RUN%==1 (
  echo Would remove: %1
  goto :eof
) else (
  if exist "%1" (
    rmdir /s /q "%1" 2>nul || del /f /q "%1" 2>nul
    echo Removed: %1
  )
  goto :eof
)

rem Standard cleanup
echo Cleaning standard build artifacts...
if %DRY_RUN%==0 (
  cargo clean
  echo Cargo clean completed.
) else (
  echo Would run: cargo clean
)

rem Delete target directory (should already be handled by cargo clean but just to be sure)
call :delete "target"

rem Clean coverage reports
echo Cleaning coverage reports...
call :delete "tarpaulin-report.html"
call :delete "tarpaulin-report.json"
call :delete "cobertura.xml"
call :delete "coverage-summary.md"
call :delete "uncovered.json"

rem Clean IDE and editor files
echo Cleaning editor and IDE files...
call :delete ".idea"
call :delete ".vscode\*.log"
call :delete "*.iml"

rem Clean temporary files
echo Cleaning temporary files...
call :delete "*.tmp"
for /r %%i in (*.tmp) do call :delete "%%i"
call :delete "*.bak"
for /r %%i in (*.bak) do call :delete "%%i"
call :delete "*.swp"
for /r %%i in (*.swp) do call :delete "%%i"
call :delete "*~"
for /r %%i in (*~) do call :delete "%%i"

rem Cargo.lock file
if %KEEP_LOCK%==0 (
  echo Cleaning Cargo.lock...
  call :delete "Cargo.lock"
) else (
  echo Keeping Cargo.lock file as requested.
)

rem Aggressive clean
if %AGGRESSIVE%==1 (
  echo Performing aggressive cleanup...
  
  rem Handle cargo registry and cache
  if defined CARGO_HOME (
    echo Cleaning Cargo registry...
    call :delete "%CARGO_HOME%\registry"
    echo Cleaning Cargo cache...
    call :delete "%CARGO_HOME%\git"
  ) else (
    echo Skipping Cargo registry cleanup (CARGO_HOME not set).
  )
  
  rem Remove Rust toolchain artifacts in project
  call :delete "rust-toolchain"
  call :delete "rust-toolchain.toml"
  call :delete ".rustup"
  
  rem Clean documentation output
  call :delete "docs\book\html"
  call :delete "docs\book\epub"
  
  rem Remove generated blockchain data
  if exist "%USERPROFILE%\.obscura" (
    echo Cleaning blockchain data...
    call :delete "%USERPROFILE%\.obscura\devnet"
  )
  
  rem Clean proptest regressions
  call :delete "proptest-regressions"
  for /d /r %%i in (proptest-regressions) do call :delete "%%i"
  
  rem Warning before potentially removing git files
  set /p GIT_CLEAN=Do you want to clean Git cache and ignore untracked files? (y/N) 
  if /i "%GIT_CLEAN%"=="y" (
    echo Cleaning Git repository...
    if %DRY_RUN%==0 (
      git clean -xdf
      echo Git clean completed.
    ) else (
      echo Would run: git clean -xdf
    )
  )
) else (
  echo Skipping aggressive cleanup. Use --aggressive to perform a deeper clean.
)

echo Cleanup complete.
if %DRY_RUN%==1 (
  echo Note: This was a dry run. No files were actually deleted.
) 