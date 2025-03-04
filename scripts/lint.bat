@echo off
rem ====================================================================
rem Obscura Linting Script (Windows)
rem ====================================================================
rem This script runs comprehensive static analysis on the codebase using
rem clippy with strict settings.
rem
rem Requirements:
rem - Rust toolchain with clippy installed
rem
rem Usage:
rem   scripts\lint.bat [fix]
rem     - Add "fix" parameter to automatically fix issues when possible
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

echo Running clippy for static code analysis...

rem Check if we should attempt to fix issues
SET FIX_OPTION=
if "%1"=="fix" (
  echo Auto-fix mode enabled.
  SET FIX_OPTION=--fix
)

rem Run clippy with strict settings
cargo clippy --all-targets --all-features -- -D warnings %FIX_OPTION%

rem Check exit code
if %ERRORLEVEL% EQU 0 (
  echo Linting passed successfully!
) else (
  echo Linting found issues that need to be fixed.
  exit /b 1
)

rem Additional lints
echo Checking for unused dependencies...
cargo udeps --all-targets

echo Checking for module structure issues...
cargo modules check 