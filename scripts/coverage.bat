@echo off
rem ====================================================================
rem Obscura Code Coverage Script (Windows)
rem ====================================================================
rem This script generates code coverage reports using cargo-tarpaulin
rem with the LLVM engine.
rem
rem Requirements:
rem - cargo-tarpaulin must be installed:
rem   cargo install cargo-tarpaulin
rem
rem Outputs:
rem - tarpaulin-report.html: HTML code coverage report
rem - tarpaulin-report.json: JSON code coverage data
rem
rem Usage:
rem   scripts\coverage.bat
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

echo Running tarpaulin coverage analysis with LLVM engine...

rem Clean and build
cargo clean
cargo build

rem Run tarpaulin with LLVM engine
rem Generate both HTML and JSON reports
cargo tarpaulin --engine llvm ^
    --out Html --out Json ^
    --output-dir . ^
    --workspace ^
    --exclude-files "tests/*" ^
    --exclude-files "benches/*" ^
    --exclude-files "RandomX/*" ^
    --exclude-files "lib/*" ^
    --fail-under 70

echo Coverage reports generated:
echo - tarpaulin-report.html (HTML report)
echo - tarpaulin-report.json (JSON report) 