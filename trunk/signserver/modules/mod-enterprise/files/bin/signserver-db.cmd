@echo off

rem Developers: Note: This file is located in modules/mod-enterprise/files/bin/.
rem Changes directly under bin will not be version controlled.

rem Library classpath
if "%SIGNSERVER_HOME%" == "" (
    set SIGNSRV_HOME=..
    rem It must work to call both as bin\signserver-db.cmd or from within bin
    if not exist signserver-db.cmd set SIGNSRV_HOME=.
) else (
    set SIGNSRV_HOME=%SIGNSERVER_HOME%
)

rem Find the JAR
for /f "tokens=*" %%a in ('dir /b /s %SIGNSRV_HOME%\lib\SignServer-DatabaseCLI*.jar') do set JAR=%%a

rem Check that we have built the classes
if not exist %JAR% (
    echo You must build SignServer before using the CLI, use 'ant'.
    goto end
)

set CLASSPATH=%SIGNSRV_HOME%\conf;%JAR%;%SIGNSRV_HOME%\res\deploytools\cesecore;%SIGNSRV_HOME%\lib\ext\jdbc\jdbc.jar;%OPTIONAL_CLASSPATH%

rem create tempdir and copy databaseprotections.properties if it exists
if exist %SIGNSRV_HOME%\conf\databaseprotection.properties (
	mkdir %SIGNSRV_HOME%\conf\conf
	copy %SIGNSRV_HOME%\conf\databaseprotection.properties %SIGNSRV_HOME%\conf\conf >NUL
)

rem echo %CLASSPATH%

rem Enable Java network debug logs
rem set JAVA_OPTS=%JAVA_OPTS% -Djavax.net.debug=all
rem set JAVA_OPTS=%JAVA_OPTS% -Djavax.net.debug=ssl

rem Enable Java PKCS#11 debug logs
rem set JAVA_OPTS=%JAVA_OPTS% -Djava.security.debug=sunpkcs11

rem Enable Java debugging
rem set JAVA_OPTS=%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=n
rem set JAVA_OPTS=%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=y

set CLASS_NAME=org.signserver.db.cli.Main

if "%JAVA_HOME%" == "" (
  java %JAVA_OPTS% -cp %CLASSPATH% %CLASS_NAME% %*
) else (
  "%JAVA_HOME%\bin\java" %JAVA_OPTS% -cp %CLASSPATH% %CLASS_NAME% %*
)

rem remove directory where databaseprotection.properties was copied
rem if it exists
if exist %SIGNSRV_HOME%\conf\conf (
	rmdir /S /Q %SIGNSRV_HOME%\conf\conf
)
:end
