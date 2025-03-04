@echo off
rem ====================================================================
rem Obscura CI Local Simulation Script (Windows)
rem ====================================================================
rem This script runs all CI checks locally before pushing to ensure the 
rem build will pass on the CI server.
rem
rem Requirements:
rem - Rust toolchain
rem - Git
rem - cargo-audit (cargo install cargo-audit)
rem - cargo-tarpaulin (cargo install cargo-tarpaulin)
rem
rem Usage:
rem   scripts\ci-local.bat [options]
rem     Options:
rem       --no-tests    Skip running tests
rem       --quick       Run only essential checks (format, lint, build)
rem       --release     Build in release mode
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Process arguments
set SKIP_TESTS=0
set QUICK_MODE=0
set RELEASE_MODE=

:process_args
if "%1"=="" goto after_args
if "%1"=="--no-tests" (
  set SKIP_TESTS=1
  shift
  goto process_args
)
if "%1"=="--quick" (
  set QUICK_MODE=1
  shift
  goto process_args
)
if "%1"=="--release" (
  set RELEASE_MODE=--release
  shift
  goto process_args
)
shift
goto process_args

:after_args

echo =====================================================================
echo                 Running CI Checks Locally                            
echo =====================================================================

rem Track failures
set FAILURES=0
set FAILURE_MSGS=

rem Check if working directory is clean
git status --porcelain > nul
if not errorlevel 1 (
  echo Warning: Working directory not clean. Uncommitted changes may cause issues.
  echo It's recommended to commit or stash changes before running CI checks.
  echo.
)

rem Run formatting checks
echo Checking code formatting...
cargo fmt --all -- --check
if errorlevel 1 (
  set /a FAILURES+=1
  set FAILURE_MSGS=%FAILURE_MSGS%- Code formatting check failed.
)

rem Run clippy
echo.
echo Running clippy...
cargo clippy --all-targets --all-features -- -D warnings
if errorlevel 1 (
  set /a FAILURES+=1
  set FAILURE_MSGS=%FAILURE_MSGS%- Clippy checks failed.
)

rem Build the project
echo.
echo Building project...
cargo build %RELEASE_MODE%
if errorlevel 1 (
  set /a FAILURES+=1
  set FAILURE_MSGS=%FAILURE_MSGS%- Build failed.
)

rem Skip remaining checks if quick mode is enabled
if %QUICK_MODE%==1 (
  echo.
  echo Skipping remaining checks in quick mode.
  if %FAILURES% gtr 0 (
    echo.
    echo Failed checks:
    echo %FAILURE_MSGS%
    echo CI checks failed with %FAILURES% error(s).
    exit /b 1
  ) else (
    echo All quick CI checks passed!
    exit /b 0
  )
)

rem Run tests if not skipped
if %SKIP_TESTS%==0 (
  echo.
  echo Running tests...
  cargo test
  if errorlevel 1 (
    set /a FAILURES+=1
    set FAILURE_MSGS=%FAILURE_MSGS%- Tests failed.
  )
) else (
  echo.
  echo Tests skipped.
)

rem Run security audit
echo.
echo Running security audit...
cargo audit --version >nul 2>&1
if errorlevel 1 (
  echo cargo-audit not found. Installing...
  cargo install cargo-audit
)
cargo audit
if errorlevel 1 (
  set /a FAILURES+=1
  set FAILURE_MSGS=%FAILURE_MSGS%- Security audit failed.
)

rem Check documentation
echo.
echo Checking documentation...
cargo doc --no-deps --all-features
if errorlevel 1 (
  set /a FAILURES+=1
  set FAILURE_MSGS=%FAILURE_MSGS%- Documentation build failed.
)

rem Run coverage check if tarpaulin is available
cargo tarpaulin --version >nul 2>&1
if errorlevel 1 (
  echo.
  echo Skipping coverage check (cargo-tarpaulin not installed).
  echo To install: cargo install cargo-tarpaulin
) else (
  echo.
  echo Running coverage check...
  cargo tarpaulin --out Xml --all-features
  if errorlevel 1 (
    set /a FAILURES+=1
    set FAILURE_MSGS=%FAILURE_MSGS%- Coverage check failed.
  )
)

rem Check for outdated dependencies
echo.
echo Checking for outdated dependencies...
cargo outdated --exit-code 1
if errorlevel 1 (
  set /a FAILURES+=1
  set FAILURE_MSGS=%FAILURE_MSGS%- Outdated dependencies found.
)

rem Set up pre-commit hook if it doesn't exist
if not exist ".git\hooks\pre-commit" (
  echo.
  echo Setting up Git pre-commit hook...
  
  if not exist ".git\hooks" mkdir ".git\hooks"
  
  echo #!/bin/sh > .git\hooks\pre-commit
  echo # Run formatting and clippy checks before commit >> .git\hooks\pre-commit
  echo echo "Running pre-commit checks..." >> .git\hooks\pre-commit
  echo. >> .git\hooks\pre-commit
  echo # Stash any changes not in the index >> .git\hooks\pre-commit
  echo git stash -q --keep-index >> .git\hooks\pre-commit
  echo. >> .git\hooks\pre-commit
  echo # Run checks >> .git\hooks\pre-commit
  echo FAILED=0 >> .git\hooks\pre-commit
  echo echo "Checking formatting..." >> .git\hooks\pre-commit
  echo cargo fmt --all -- --check ^|^| FAILED=1 >> .git\hooks\pre-commit
  echo echo "Running clippy..." >> .git\hooks\pre-commit
  echo cargo clippy --all-targets --all-features -- -D warnings ^|^| FAILED=1 >> .git\hooks\pre-commit
  echo. >> .git\hooks\pre-commit
  echo # Restore stashed changes >> .git\hooks\pre-commit
  echo git stash pop -q >> .git\hooks\pre-commit
  echo. >> .git\hooks\pre-commit
  echo if [ $FAILED -ne 0 ]; then >> .git\hooks\pre-commit
  echo   echo "Pre-commit checks failed. Please fix errors before committing." >> .git\hooks\pre-commit
  echo   exit 1 >> .git\hooks\pre-commit
  echo fi >> .git\hooks\pre-commit
  echo. >> .git\hooks\pre-commit
  echo echo "Pre-commit checks passed!" >> .git\hooks\pre-commit
  echo exit 0 >> .git\hooks\pre-commit
  
  echo Pre-commit hook installed.
)

rem Report results
if %FAILURES% gtr 0 (
  echo.
  echo Failed checks:
  echo %FAILURE_MSGS%
  echo CI checks failed with %FAILURES% error(s).
  exit /b 1
) else (
  echo.
  echo All CI checks passed!
  exit /b 0
) 