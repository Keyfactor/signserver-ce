@echo off

rem library classpath
if "%SIGNSERVER_HOME%" == "" (
  set SIGNSRV_HOME=..
  rem It must work to call both as bin\signserver.cmd or from within bin
  if not exist signclient.cmd set SIGNSRV_HOME=.
 ) else (
    set SIGNSRV_HOME=%SIGNSERVER_HOME%
) 

rem Application server jars
if not "%APPSRV_HOME%" == "" (
	set J2EE_CP=%APPSRV_HOME%\lib\jbossall-client.jar;%APPSRV_HOME%\lib\appserv-rt.jar
)

rem check that we have built the classes
if not exist %SIGNSRV_HOME%\lib\SignServer-Client-CLI.jar  (
    echo You must build SignServer Client CLI first.
    goto end
)

rem Optional JARs
set OPTIONAL_CLASSPATH=%SIGNSRV_HOME%\lib\SignServer-Client-ValidationCLI.jar;%EXTRA_CLASSPATH%

set CLASSPATH=%SIGNSRV_HOME%\conf;%SIGNSRV_HOME%\bin;%SIGNSRV_HOME%\lib\SignServer-Client-CLI.jar;%J2EE_CP%;%OPTIONAL_CLASSPATH%
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
  java %JAVA_OPTS% -cp %CLASSPATH%  org.signserver.client.cli.ClientCLI %*
) else (
  "%JAVA_HOME%\bin\java" %JAVA_OPTS% -cp %CLASSPATH% org.signserver.client.cli.ClientCLI %*
)
:end
