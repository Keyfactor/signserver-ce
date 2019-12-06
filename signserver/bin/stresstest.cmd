@echo off

rem Library classpath
if "%SIGNSERVER_HOME%" == "" (
    set SIGNSRV_HOME=..
    rem It must work to call both as bin\stresstest.cmd or from within bin
    if not exist stresstest.cmd set SIGNSRV_HOME=.
) else (
    set SIGNSRV_HOME=%SIGNSERVER_HOME%
)

rem Find the JAR
for /f "tokens=*" %%a in ('dir /b /s %SIGNSRV_HOME%\lib\SignServer-Test-Performance*.jar') do set JAR=%%a

rem Check that we have built the classes
if not exist %JAR% (
    echo You must build SignServer Performance Test CLI first.
    goto end
)

rem Construct the classpath
set MAIN_CLASSPATH=%SIGNSRV_HOME%\conf;%JAR%

rem Application server dependencies
if exist %APPSRV_HOME%\lib\appserv-rt.jar (
    set JEE_CLASSPATH=%SIGNSRV_HOME%\conf\glassfish;%APPSRV_HOME%\lib\appserv-rt.jar
)
if exist %APPSRV_HOME%\client\jbossall-client.jar  (
    set JEE_CLASSPATH=%SIGNSRV_HOME%\conf\jboss;%APPSRV_HOME%\client\jbossall-client.jar
)
if exist %APPSRV_HOME%\bin\standalone.bat  (
    set JEE_CLASSPATH=%SIGNSRV_HOME%\conf\jboss7;%APPSRV_HOME%\bin\client\jboss-client.jar
)

set CLASSPATH=%MAIN_CLASSPATH%;%JEE_CLASSPATH%;%OPTIONAL_CLASSPATH%
rem echo %CLASSPATH%

rem Enable Java network debug logs
rem set JAVA_OPTS="%JAVA_OPTS% -Djavax.net.debug=all"
rem set JAVA_OPTS="%JAVA_OPTS% -Djavax.net.debug=ssl"

rem Enable Java PKCS#11 debug logs
rem set JAVA_OPTS="%JAVA_OPTS% -Djava.security.debug=sunpkcs11"

rem Enable Java debugging
rem set JAVA_OPTS="%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=n"
rem set JAVA_OPTS="%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=y"

set CLASS_NAME=org.signserver.test.performance.cli.Main

if "%JAVA_HOME%" == "" (
  java %JAVA_OPTS% -cp %CLASSPATH% %CLASS_NAME% %*
) else (
  "%JAVA_HOME%\bin\java" %JAVA_OPTS% -cp %CLASSPATH% %CLASS_NAME% %*
)
:end
