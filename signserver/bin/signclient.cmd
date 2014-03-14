@echo off

rem library classpath
if "%SIGNSERVER_HOME%" == "" (
  set SIGNSRV_HOME=..
  rem It must work to call both as bin\signserver.cmd or from within bin
  if not exist signserver.cmd set SIGNSRV_HOME=.
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

set CLASSPATH=%SIGNSRV_HOME%\bin;%SIGNSRV_HOME%\lib\SignServer-Client-CLI.jar;%J2EE_CP%;%OPTIONAL_CLASSPATH%
rem echo %CLASSPATH%

if "%JAVA_HOME%" == "" (
  java -cp %CLASSPATH%  org.signserver.client.cli.ClientCLI %*
) else (
  "%JAVA_HOME%\bin\java" -cp %CLASSPATH% org.signserver.client.cli.ClientCLI %*
)
:end
