@echo off
rem ====================================================================
rem Obscura Release Management Script (Windows)
rem ====================================================================
rem This script automates the release process including version bumping,
rem changelog updates, tagging, and artifact creation.
rem
rem Requirements:
rem - Rust toolchain
rem - Git
rem - cargo-release (cargo install cargo-release)
rem - GitHub CLI (gh) (optional, for GitHub releases)
rem
rem Usage:
rem   scripts\release.bat <version>
rem     Options:
rem       --dry-run    Don't make any changes, just simulate
rem       --no-publish Don't publish to crates.io
rem       --github     Create GitHub release
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Check arguments
if "%1"=="" (
  echo Usage: %0 ^<version^> [options]
  echo   version format: major, minor, patch, or specific version (e.g., 1.2.3)
  echo   options:
  echo     --dry-run    Don't make any changes, just simulate
  echo     --no-publish Don't publish to crates.io
  echo     --github     Create GitHub release
  exit /b 1
)

set VERSION=%1
shift

rem Process options
set DRY_RUN=0
set NO_PUBLISH=0
set GITHUB_RELEASE=0

:process_args
if "%1"=="" goto after_args
if "%1"=="--dry-run" (
  set DRY_RUN=1
  shift
  goto process_args
)
if "%1"=="--no-publish" (
  set NO_PUBLISH=1
  shift
  goto process_args
)
if "%1"=="--github" (
  set GITHUB_RELEASE=1
  shift
  goto process_args
)
shift
goto process_args

:after_args

echo =====================================================================
echo             Obscura Release Management: %VERSION%                    
echo =====================================================================

rem Install cargo-release if not available
cargo release --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
  echo cargo-release not found. Installing...
  cargo install cargo-release
)

rem Check if working directory is clean
git diff --quiet --exit-code
if %ERRORLEVEL% NEQ 0 (
  echo Error: Working directory not clean. Please commit or stash changes.
  exit /b 1
)

rem Update changelog
echo Updating CHANGELOG.md...
set CURRENT_DATE=%DATE:~10,4%-%DATE:~4,2%-%DATE:~7,2%
set RELEASE_HEADING=## [%VERSION%] - %CURRENT_DATE%

if exist CHANGELOG.md (
  rem Check if version already exists in changelog
  findstr /C:"## [%VERSION%]" CHANGELOG.md >nul
  if %ERRORLEVEL% EQU 0 (
    echo Warning: Version %VERSION% already exists in CHANGELOG.md
    echo Continuing without modifying it.
  ) else (
    rem Insert new version after the Unreleased section
    if %DRY_RUN%==0 (
      rem Create a temporary file
      type CHANGELOG.md > changelog.tmp
      set FOUND=0
      set TEMPFILE=changelog_new.tmp
      if exist %TEMPFILE% del %TEMPFILE%
      
      for /f "delims=" %%a in (changelog.tmp) do (
        echo %%a >> %TEMPFILE%
        if "%%a"=="## [Unreleased]" (
          echo. >> %TEMPFILE%
          echo %RELEASE_HEADING% >> %TEMPFILE%
          set FOUND=1
        )
      )
      
      if %FOUND%==1 (
        del CHANGELOG.md
        rename %TEMPFILE% CHANGELOG.md
        echo CHANGELOG.md updated.
      ) else (
        echo Warning: Could not find Unreleased section in CHANGELOG.md
        del %TEMPFILE%
      )
      
      if exist changelog.tmp del changelog.tmp
    ) else (
      echo (DRY RUN) Would update CHANGELOG.md with: %RELEASE_HEADING%
    )
  )
) else (
  echo Warning: CHANGELOG.md not found. Skipping changelog update.
)

rem Run tests
echo Running tests...
cargo test --all-features

rem Handle the release with cargo-release
echo Preparing release...
set RELEASE_CMD=cargo release

rem Add options based on arguments
if "%VERSION%"=="major" (
  set RELEASE_CMD=%RELEASE_CMD% major
) else if "%VERSION%"=="minor" (
  set RELEASE_CMD=%RELEASE_CMD% minor
) else if "%VERSION%"=="patch" (
  set RELEASE_CMD=%RELEASE_CMD% patch
) else (
  set RELEASE_CMD=%RELEASE_CMD% --exact-version %VERSION%
)

if %DRY_RUN%==1 (
  set RELEASE_CMD=%RELEASE_CMD% --dry-run
)

if %NO_PUBLISH%==1 (
  set RELEASE_CMD=%RELEASE_CMD% --no-publish
)

rem Execute the release command
echo Executing: %RELEASE_CMD%
%RELEASE_CMD%

rem Create GitHub release if requested
if %GITHUB_RELEASE%==1 if %DRY_RUN%==0 (
  echo Creating GitHub release...
  gh --version >nul 2>&1
  if %ERRORLEVEL% EQU 0 (
    rem Create simple GitHub release
    gh release create "v%VERSION%" --title "Obscura v%VERSION%" --notes "Release version %VERSION%"
    echo GitHub release created.
  ) else (
    echo GitHub CLI (gh) not installed. Skipping GitHub release.
    echo To create a GitHub release, install GitHub CLI: https://cli.github.com/
  )
)

echo Release process completed! 