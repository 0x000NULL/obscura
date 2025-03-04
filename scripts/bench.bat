@echo off
rem ====================================================================
rem Obscura Benchmarking Script (Windows)
rem ====================================================================
rem This script runs performance benchmarks and generates reports.
rem
rem Requirements:
rem - Rust toolchain
rem - Criterion (dependency in Cargo.toml)
rem - gnuplot (for graphical output)
rem
rem Usage:
rem   scripts\bench.bat [options]
rem     Options:
rem       --filter=PATTERN   Only run benchmarks matching PATTERN
rem       --compare=BASELINE Compare against BASELINE results
rem       --save=NAME        Save results as named baseline
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Process arguments
SET FILTER=
SET COMPARE=
SET SAVE=

:process_args
if "%1"=="" goto after_args
set ARG=%1
if "%ARG:~0,9%"=="--filter=" (
  set FILTER=%ARG:~9%
  shift
  goto process_args
)
if "%ARG:~0,10%"=="--compare=" (
  set COMPARE=%ARG:~10%
  shift
  goto process_args
)
if "%ARG:~0,7%"=="--save=" (
  set SAVE=%ARG:~7%
  shift
  goto process_args
)
shift
goto process_args

:after_args

echo =====================================================================
echo                Running Obscura Benchmarks                            
echo =====================================================================

rem Create benchmarks directory if it doesn't exist
if not exist "target\criterion" mkdir target\criterion

rem Run benchmarks
if not "%FILTER%"=="" (
  echo Running benchmarks matching: %FILTER%
  SET BENCHMARK_CMD=cargo bench --bench %FILTER%
) else (
  echo Running all benchmarks...
  SET BENCHMARK_CMD=cargo bench
)

rem Run the benchmarks
%BENCHMARK_CMD%

rem Compare against baseline if specified
if not "%COMPARE%"=="" (
  if exist "target\criterion\%COMPARE%" (
    echo Comparing against baseline: %COMPARE%
    rem Use Criterion's comparison feature or a custom comparison tool
    cargo install critcmp
    critcmp target\criterion\%COMPARE% target\criterion\baseline
  ) else (
    echo Error: Baseline '%COMPARE%' not found.
    exit /b 1
  )
)

rem Save as baseline if requested
if not "%SAVE%"=="" (
  echo Saving benchmark results as baseline: %SAVE%
  if not exist "target\criterion\baselines" mkdir target\criterion\baselines
  xcopy /E /I /Y target\criterion\latest target\criterion\baselines\%SAVE%
  echo Baseline saved successfully.
)

echo Benchmarking complete. Results available in target\criterion\ 