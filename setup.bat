@echo off
setlocal

:: Define variables
set "GOPATH=%USERPROFILE%\go"
set "REPO_URL=https://github.com/runZeroInc/sshamble.git"
set "REPO_DIR=%GOPATH%\src\github.com\runZeroInc\sshamble"
set "BIN_DIR=%GOPATH%\bin"

:: Create GOPATH directories if they don't exist
if not exist "%GOPATH%" mkdir "%GOPATH%"
if not exist "%GOPATH%\src" mkdir "%GOPATH%\src"
if not exist "%GOPATH%\bin" mkdir "%GOPATH%\bin"

:: Clone the repository if it doesn't exist
if not exist "%REPO_DIR%" (
    echo Cloning repository...
    git clone "%REPO_URL%" "%REPO_DIR%"
) else (
    echo Repository already exists. Pulling latest changes...
    pushd "%REPO_DIR%"
    git pull
    popd
)

:: Navigate to the repository directory
cd /d "%REPO_DIR%"

:: Install Go modules
echo Installing Go modules...
go mod tidy

:: Build the Go project
echo Building the project...
go build -o "%BIN_DIR%\sshamble"

:: Check if the build was successful
if exist "%BIN_DIR%\sshamble" (
    echo Build successful. Binary installed at %BIN_DIR%\sshamble
) else (
    echo Build failed. Please check the Go build logs for errors.
    exit /b 1
)

:: Display success message
echo Setup complete. You can now use the 'sshamble' command.

:: End script
endlocal
pause
