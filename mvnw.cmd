@REM ----------------------------------------------------------------------------
@REM Maven Wrapper for CookieTrace
@REM ----------------------------------------------------------------------------
@echo off
setlocal

set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

@REM Detect portable JDK if JAVA_HOME is not set or not valid
if not exist "%JAVA_HOME%\bin\java.exe" (
    if exist "%PROJECT_DIR%\tools\jdk-17\bin\java.exe" (
        set "JAVA_HOME=%PROJECT_DIR%\tools\jdk-17"
        set "PATH=%PROJECT_DIR%\tools\jdk-17\bin;%PATH%"
    )
)

if not exist "%JAVA_HOME%\bin\java.exe" (
    echo Error: JAVA_HOME is not set and portable JDK was not found in %PROJECT_DIR%\tools\jdk-17.
    exit /b 1
)

@REM If bundled Maven exists in tools/maven, run it directly
if exist "%PROJECT_DIR%\tools\maven\bin\mvn.cmd" (
    call "%PROJECT_DIR%\tools\maven\bin\mvn.cmd" %*
    exit /b %ERRORLEVEL%
)

@REM Fallback to maven-wrapper.jar
if exist "%PROJECT_DIR%\.mvn\wrapper\maven-wrapper.jar" (
    "%JAVA_HOME%\bin\java.exe" -jar "%PROJECT_DIR%\.mvn\wrapper\maven-wrapper.jar" %*
    exit /b %ERRORLEVEL%
)

echo Error: Neither tools\maven nor .mvn\wrapper\maven-wrapper.jar was found.
exit /b 1
