@echo off

rem library classpath
if "%SIGNSERVER_HOME%" == "" (
  set SIGNSRV_HOME=..
  rem It must work to call both as bin\signserver.cmd or from within bin
  if not exist signserver.cmd set SIGNSRV_HOME=.
 ) else (
    set SIGNSRV_HOME=%SIGNSERVER_HOME%
) 
  
if "%APPSRV_HOME%" == "" (
    echo You must set APPSRV_HOME before running the SignServer cli.
    goto end
)

rem check that we have built the classes
if not exist %SIGNSRV_HOME%\lib\SignServer-AdminCLI.jar  (
    echo You must build SignServer before using the cli, use 'ant'.
    goto end
)

rem Optional JARs
set OPTIONAL_CLASSPATH=

rem Construct the classpath
set MAIN_CLASSPATH=%SIGNSRV_HOME%\conf;%SIGNSRV_HOME%\lib\SignServer-AdminCLI.jar;%OPTIONAL_CLASSPATH%

rem Application server dependencies
if exist %APPSRV_HOME%\lib\appserv-rt.jar (
    set JEE_CLASSPATH=%CLASSPATH%;%SIGNSRV_HOME%\conf\glassfish;%APPSRV_HOME%\lib\appserv-rt.jar
)
if exist %APPSRV_HOME%\client\jbossall-client.jar  (
    set JEE_CLASSPATH=%CLASSPATH%;%SIGNSRV_HOME%\conf\jboss;%APPSRV_HOME%\client\jbossall-client.jar
)

if exist %APPSRV_HOME%\bin\standalone.bat  (
    set JEE_CLASSPATH=%CLASSPATH%;%SIGNSRV_HOME%\conf\jboss7;%APPSRV_HOME%\bin\client\jboss-client.jar
)

set CLASSPATH=%MAIN_CLASSPATH%;%JEE_CLASSPATH%
rem echo %CLASSPATH%

rem Enable Java network debug logs
rem set JAVA_OPTS="%JAVA_OPTS% -Djavax.net.debug=all"
rem set JAVA_OPTS="%JAVA_OPTS% -Djavax.net.debug=ssl"

rem Enable Java PKCS#11 debug logs
rem set JAVA_OPTS="%JAVA_OPTS% -Djava.security.debug=sunpkcs11"

rem Enable Java debugging
rem set JAVA_OPTS="%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=n"
rem set JAVA_OPTS="%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=y"

if "%JAVA_HOME%" == "" (
  java %JAVA_OPTS% -cp %CLASSPATH%  org.signserver.admin.cli.AdminCLI %*
) else (
  "%JAVA_HOME%\bin\java" %JAVA_OPTS% -cp %CLASSPATH% org.signserver.admin.cli.AdminCLI %*
)
:end
