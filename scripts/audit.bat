@echo off
rem ====================================================================
rem Obscura Dependency Audit Script (Windows)
rem ====================================================================
rem This script checks dependencies for security vulnerabilities, outdated
rem packages, and generates dependency reports.
rem
rem Requirements:
rem - Rust toolchain
rem - cargo-audit (cargo install cargo-audit)
rem - cargo-outdated (cargo install cargo-outdated)
rem - cargo-lichking (cargo install cargo-lichking) (optional)
rem
rem Usage:
rem   scripts\audit.bat [options]
rem     Options:
rem       --fix        Apply automatic fixes when possible
rem       --report     Generate detailed HTML report
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Process arguments
SET FIX_MODE=0
SET REPORT_MODE=0

:process_args
if "%1"=="" goto after_args
if "%1"=="--fix" (
  SET FIX_MODE=1
  shift
  goto process_args
)
if "%1"=="--report" (
  SET REPORT_MODE=1
  shift
  goto process_args
)
shift
goto process_args

:after_args

echo =====================================================================
echo                 Obscura Dependency Audit                             
echo =====================================================================

rem Check for required tools
cargo audit --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo cargo-audit not found. Installing...
  cargo install cargo-audit
)

cargo outdated --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo cargo-outdated not found. Installing...
  cargo install cargo-outdated
)

rem Create reports directory
if %REPORT_MODE%==1 (
  if not exist "reports" mkdir reports
)

rem Check for security vulnerabilities
echo Checking for security vulnerabilities...
if %FIX_MODE%==1 (
  SET AUDIT_COMMAND=cargo audit fix
) else (
  SET AUDIT_COMMAND=cargo audit
)

if %REPORT_MODE%==1 (
  %AUDIT_COMMAND% --format json > reports\security_audit.json
  echo Security audit report saved to reports\security_audit.json
) else (
  %AUDIT_COMMAND%
)

rem Check for outdated dependencies
echo.
echo Checking for outdated dependencies...
SET OUTDATED_COMMAND=cargo outdated

if %REPORT_MODE%==1 (
  %OUTDATED_COMMAND% --format json > reports\outdated_dependencies.json
  echo Outdated dependencies report saved to reports\outdated_dependencies.json
) else (
  %OUTDATED_COMMAND%
)

rem Check dependency licenses
echo.
echo Checking dependency licenses...
cargo lichking --version >nul 2>&1
if %ERRORLEVEL%==0 (
  if %REPORT_MODE%==1 (
    cargo lichking > reports\license_check.txt
    echo License check report saved to reports\license_check.txt
  ) else (
    cargo lichking
  )
) else (
  echo cargo-lichking not installed. Skipping license check.
  echo To enable license checking, run: cargo install cargo-lichking
)

rem Generate dependency tree
echo.
echo Generating dependency tree...
if %REPORT_MODE%==1 (
  cargo tree --all > reports\dependency_tree.txt
  echo Dependency tree saved to reports\dependency_tree.txt
) else (
  cargo tree
)

rem Generate HTML report if requested
if %REPORT_MODE%==1 (
  echo.
  echo Generating HTML report...
  
  rem Create simple HTML report
  echo ^<!DOCTYPE html^> > reports\dependencies_report.html
  echo ^<html^> >> reports\dependencies_report.html
  echo ^<head^> >> reports\dependencies_report.html
  echo     ^<title^>Obscura Dependency Audit Report^</title^> >> reports\dependencies_report.html
  echo     ^<style^> >> reports\dependencies_report.html
  echo         body { font-family: Arial, sans-serif; margin: 20px; } >> reports\dependencies_report.html
  echo         h1 { color: #333366; } >> reports\dependencies_report.html
  echo         h2 { color: #336699; margin-top: 20px; } >> reports\dependencies_report.html
  echo         pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; } >> reports\dependencies_report.html
  echo         .vulnerability { color: #cc0000; } >> reports\dependencies_report.html
  echo         .outdated { color: #ff6600; } >> reports\dependencies_report.html
  echo         .ok { color: #008800; } >> reports\dependencies_report.html
  echo     ^</style^> >> reports\dependencies_report.html
  echo ^</head^> >> reports\dependencies_report.html
  echo ^<body^> >> reports\dependencies_report.html
  echo     ^<h1^>Obscura Dependency Audit Report^</h1^> >> reports\dependencies_report.html
  echo     ^<p^>Generated on %DATE% %TIME%^</p^> >> reports\dependencies_report.html
  
  echo     ^<h2^>Security Vulnerabilities^</h2^> >> reports\dependencies_report.html
  echo     ^<pre^> >> reports\dependencies_report.html
  type reports\security_audit.json >> reports\dependencies_report.html
  echo     ^</pre^> >> reports\dependencies_report.html
  
  echo     ^<h2^>Outdated Dependencies^</h2^> >> reports\dependencies_report.html
  echo     ^<pre^> >> reports\dependencies_report.html
  type reports\outdated_dependencies.json >> reports\dependencies_report.html
  echo     ^</pre^> >> reports\dependencies_report.html
  
  echo     ^<h2^>License Check^</h2^> >> reports\dependencies_report.html
  echo     ^<pre^> >> reports\dependencies_report.html
  if exist reports\license_check.txt (
    type reports\license_check.txt >> reports\dependencies_report.html
  ) else (
    echo License check not available >> reports\dependencies_report.html
  )
  echo     ^</pre^> >> reports\dependencies_report.html
  
  echo     ^<h2^>Dependency Tree^</h2^> >> reports\dependencies_report.html
  echo     ^<pre^> >> reports\dependencies_report.html
  type reports\dependency_tree.txt >> reports\dependencies_report.html
  echo     ^</pre^> >> reports\dependencies_report.html
  
  echo ^</body^> >> reports\dependencies_report.html
  echo ^</html^> >> reports\dependencies_report.html

  echo HTML report generated at reports\dependencies_report.html
)

echo.
echo Dependency audit complete! 