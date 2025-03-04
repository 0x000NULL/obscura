@echo off
rem ====================================================================
rem Obscura Blockchain Utilities (Windows)
rem ====================================================================
rem This script provides various blockchain-specific utilities for
rem development and testing.
rem
rem Requirements:
rem - Rust toolchain
rem - Obscura node binaries (built from the project)
rem
rem Usage:
rem   scripts\chain-utils.bat <command>
rem
rem Commands:
rem   init       Initialize a new test network
rem   reset      Reset blockchain data (delete data directory)
rem   generate   Generate new development keys
rem   node       Start a node with development settings
rem   mine       Start mining on a running node
rem   faucet     Request tokens from the development faucet
rem   status     Check status of nodes and network
rem ====================================================================

rem Navigate to the project root
cd "%~dp0\.."

rem Define constants
set DATA_DIR=%USERPROFILE%\.obscura
set DEV_DATA_DIR=%DATA_DIR%\devnet
set KEYS_DIR=%DEV_DATA_DIR%\keys
set BINARY_PATH=.\target\release\obscura.exe
set DEV_BINARY_PATH=.\target\debug\obscura.exe

rem Process commands
if "%1"=="" (
  echo Usage: %0 ^<command^>
  echo.
  echo Commands:
  echo   init       - Initialize a new test network
  echo   reset      - Reset blockchain data (delete data directory)
  echo   generate   - Generate new development keys
  echo   node       - Start a node with development settings
  echo   mine       - Start mining on a running node
  echo   faucet     - Request tokens from the development faucet
  echo   status     - Check status of nodes and network
  exit /b 1
)

set COMMAND=%1
shift

rem Check if node binary exists and build if necessary
:check_node_binary
if not exist "%BINARY_PATH%" (
  if not exist "%DEV_BINARY_PATH%" (
    echo Node binary not found. Building...
    cargo build
    if not exist "%DEV_BINARY_PATH%" (
      echo Failed to build node binary.
      exit /b 1
    )
  )
)

rem Use debug binary for development
if exist "%DEV_BINARY_PATH%" (
  set NODE_BINARY=%DEV_BINARY_PATH%
) else (
  set NODE_BINARY=%BINARY_PATH%
)

goto cmd_%COMMAND%

rem Initialize a new test network
:cmd_init
echo Initializing new test network...
call :check_node_binary

rem Create directories
if not exist "%DEV_DATA_DIR%" mkdir "%DEV_DATA_DIR%"
if not exist "%KEYS_DIR%" mkdir "%KEYS_DIR%"

rem Generate genesis block
%NODE_BINARY% init-devnet --data-dir "%DEV_DATA_DIR%" %*

echo Test network initialized at %DEV_DATA_DIR%
echo Use '%0 node' to start the node
exit /b 0

rem Reset blockchain data
:cmd_reset
echo Resetting blockchain data...

set /p CONFIRM=This will delete all blockchain data in %DEV_DATA_DIR%. Continue? (y/N) 
if /i "%CONFIRM%"=="y" (
  if exist "%DEV_DATA_DIR%" rmdir /s /q "%DEV_DATA_DIR%"
  mkdir "%DEV_DATA_DIR%"
  mkdir "%KEYS_DIR%"
  echo Blockchain data reset.
) else (
  echo Operation cancelled.
)
exit /b 0

rem Generate new development keys
:cmd_generate
echo Generating new development keys...
call :check_node_binary

if not exist "%KEYS_DIR%" mkdir "%KEYS_DIR%"
%NODE_BINARY% generate-keys --output-dir "%KEYS_DIR%" %*

echo Keys generated at %KEYS_DIR%
exit /b 0

rem Start a node with development settings
:cmd_node
echo Starting node with development settings...
call :check_node_binary

rem Start the node
%NODE_BINARY% run --data-dir "%DEV_DATA_DIR%" --dev-mode %*
exit /b 0

rem Start mining on a running node
:cmd_mine
echo Starting mining on the node...
call :check_node_binary

%NODE_BINARY% mine --data-dir "%DEV_DATA_DIR%" %*
exit /b 0

rem Request tokens from the development faucet
:cmd_faucet
if "%1"=="" (
  echo Usage: %0 faucet ^<address^>
  exit /b 1
)

set ADDRESS=%1
shift

echo Requesting tokens from faucet for address %ADDRESS%...
call :check_node_binary

%NODE_BINARY% faucet --data-dir "%DEV_DATA_DIR%" --address "%ADDRESS%" %*
exit /b 0

rem Check status of nodes and network
:cmd_status
echo Checking node and network status...
call :check_node_binary

%NODE_BINARY% status --data-dir "%DEV_DATA_DIR%" %*
exit /b 0

rem Unknown command
:cmd_
echo Unknown command: %COMMAND%
echo Run '%0' without arguments to see available commands.
exit /b 1 