@echo off

rem library classpath
if "%SIGNSERVER_HOME%" == "" (
  set SIGNSRV_HOME=..
  rem It must work to call both as bin\signserver.cmd or from within bin
  if not exist signserver.cmd set SIGNSRV_HOME=.
 ) else (
    set SIGNSRV_HOME=%SIGNSERVER_HOME%
) 
  
if "%APPSRV_HOME%" == " (
    echo You must set APPSRV_HOME before running the SignServer cli.
    goto end
)

rem Application server jars
set J2EE_CP=%APPSRV_HOME%\lib\jbossall-client.jar;%APPSRV_HOME%\lib\appserv-rt.jar

rem check that we have built the classes
if not exist %SIGNSRV_HOME%\dist-client\SignServer-AdminCLI.jar  (
    echo You must build SignServer before using the cli, use 'ant'.
    goto end
)

set CLASSPATH=%SIGNSRV_HOME%\bin;%SIGNSRV_HOME%\lib\SignServer-AdminCLI.jar;%J2EE_CP%
rem echo %CLASSPATH%

rem Fixup arguments, we have to do this since windows normally only 
rem supports %1-%9 as command line arguments
shift
set a=%0
set b=%1
set c=%2
set d=%3
set e=%4
set f=%5
set g=%6
set h=%7
set i=%8
set j=%9
rem echo %a% %b% %c% %d% %e% %f% %g% %h% %i% %j%
if "%JAVA_HOME%" == "" (
  java -cp %CLASSPATH%  org.signserver.cli.signserver %a% %b% %c% %d% %e% %f% %g% %h% %i% %j%
) else (
  "%JAVA_HOME%\bin\java" -cp %CLASSPATH% org.signserver.cli.signserver %a% %b% %c% %d% %e% %f% %g% %h% %i% %j% 
)
:end
