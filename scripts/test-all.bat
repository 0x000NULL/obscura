@echo off
rem ====================================================================
rem Obscura Comprehensive Test Runner (Windows)
rem ====================================================================
rem This script runs all test suites including unit tests, integration
rem tests, doc tests, and property-based tests.
rem
rem Requirements:
rem - Rust toolchain
rem
rem Usage:
rem   scripts\test-all.bat [options]
rem     Options:
rem       --nocapture       Show test output
rem       --filter PATTERN  Only run tests containing PATTERN
rem       --ignored         Run ignored tests
rem       --release         Run tests in release mode
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Process arguments
SET OPTIONS=
SET DOCTEST_OPTIONS=
SET FILTER=

:process_args
if "%1"=="" goto after_args
if "%1"=="--nocapture" (
  SET OPTIONS=%OPTIONS% --nocapture
  SET DOCTEST_OPTIONS=%DOCTEST_OPTIONS% --nocapture
  shift
  goto process_args
)
if "%1"=="--ignored" (
  SET OPTIONS=%OPTIONS% --ignored
  SET DOCTEST_OPTIONS=%DOCTEST_OPTIONS% --ignored
  shift
  goto process_args
)
if "%1"=="--release" (
  SET OPTIONS=%OPTIONS% --release
  SET DOCTEST_OPTIONS=%DOCTEST_OPTIONS% --release
  shift
  goto process_args
)
if "%1:~0,9%"=="--filter=" (
  SET FILTER=%1:~9%
  SET OPTIONS=%OPTIONS% --test %FILTER%
  shift
  goto process_args
)
shift
goto process_args

:after_args

echo =====================================================================
echo                  Running Obscura Test Suite                          
echo =====================================================================

rem Run unit tests
echo Running unit tests...
SET RUST_BACKTRACE=1
cargo test %OPTIONS%

rem Run doc tests
echo.
echo Running documentation tests...
cargo test --doc %DOCTEST_OPTIONS%

rem Run property-based tests
echo.
echo Running property-based tests...
cargo test --test proptest %OPTIONS%

rem Run integration tests
echo.
echo Running integration tests...
cargo test --test *_integration %OPTIONS%

echo.
echo All test suites completed! 