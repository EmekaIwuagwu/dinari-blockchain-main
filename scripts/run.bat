@echo off
REM DinariBlockchain Node Runner Script for Windows

echo Starting DinariBlockchain Node...

REM Default values
set DATA_DIR=.\data
set RPC_ADDR=localhost:8545
set P2P_ADDR=/ip4/0.0.0.0/tcp/9000
set MINER_ADDR=
set AUTO_MINE=
set LOG_LEVEL=info

REM Parse arguments
:parse_args
if "%1"=="" goto run_node
if "%1"=="--datadir" (
    set DATA_DIR=%2
    shift
    shift
    goto parse_args
)
if "%1"=="--rpc" (
    set RPC_ADDR=%2
    shift
    shift
    goto parse_args
)
if "%1"=="--p2p" (
    set P2P_ADDR=%2
    shift
    shift
    goto parse_args
)
if "%1"=="--miner" (
    set MINER_ADDR=%2
    shift
    shift
    goto parse_args
)
if "%1"=="--mine" (
    set AUTO_MINE=--mine
    shift
    goto parse_args
)
if "%1"=="--loglevel" (
    set LOG_LEVEL=%2
    shift
    shift
    goto parse_args
)
if "%1"=="--create-wallet" (
    .\bin\dinari-node.exe --create-wallet
    exit /b 0
)
shift
goto parse_args

:run_node

REM Build if binary doesn't exist
if not exist ".\bin\dinari-node.exe" (
    echo Building dinari-node...
    make build
)

REM Create data directory
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

REM Build command
set CMD=.\bin\dinari-node.exe --datadir=%DATA_DIR% --rpc=%RPC_ADDR% --p2p=%P2P_ADDR% --loglevel=%LOG_LEVEL%

if not "%MINER_ADDR%"=="" (
    set CMD=%CMD% --miner=%MINER_ADDR%
)

if not "%AUTO_MINE%"=="" (
    set CMD=%CMD% %AUTO_MINE%
)

echo Command: %CMD%
echo.

%CMD%