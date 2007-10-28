@echo off

rem Check that JAVA_HOME is set
if "%JAVA_HOME%" == "" (
    echo You must set JAVA_HOME before running the SIGNSERVER cli.
    goto end
)
    
rem Which command are we running?
set class_name=""

set class_name=org.signserver.cli.signserver

if %class_name% == "" (
    echo "Usage: %0 options"
	echo For options information, specify a command directive
    goto end
)
rem echo Class name to run is %class_name%

rem J2EE server classpath
set J2EE_DIR=""
set J2EE_CP=""
if not "%JBOSS_HOME%" == ""  ( 
    echo Using JBoss JNDI provider...
    set J2EE_DIR=%JBOSS_HOME%\client
    set J2EE_CP=%JBOSS_HOME%\client\jnp-client.jar;%JBOSS_HOME%\client\jboss-j2ee.jar;%JBOSS_HOME%\client\jbossall-client.jar;%JBOSS_HOME%\client\jboss-client.jar;%JBOSS_HOME%\client\jbosssx-client.jar;%JBOSS_HOME%\client\jboss-common-client.jar;%JBOSS_HOME%\client\ejb3-persistence.jar
) else if not "%WEBLOGIC_HOME%" == ""  ( 
    echo Using Weblogic JNDI provider...
    set J2EE_DIR=%WEBLOGIC_HOME%\server
    set J2EE_CP=%WEBLOGIC_HOME%\server\lib\weblogic.jar
) else (
    echo Could not find a valid J2EE server for JNDI provider.
    echo Specify a JBOSS_HOME or WEBLOGIC_HOME environment variable
    goto end
)
rem echo J2EE directory is %J2EE_DIR%

rem library classpath
if "%SIGNSERVER_HOME%" == "" (
  set SIGNSRV_HOME=..
  rem It must work to call both as bin\signserver.cmd or from within bin
  if not exist signserver.cmd set SIGNSRV_HOME=.
 ) else (
    set SIGNSRV_HOME="%SIGNSERVER_HOME%"
) 
  
set SIGNSERVER_CP=%SIGNSRV_HOME%\lib\log4j.jar;%SIGNSRV_HOME%\lib\1.5\bcprov-jdk.jar;%SIGNSRV_HOME%\lib\1.5\bcmail-jdk.jar;%SIGNSRV_HOME%\lib\ejbca-util.jar;%SIGNSRV_HOME%\lib\commons-lang-2.0.jar;%SIGNSRV_HOME%\tmp\lib\base-core.jar;%SIGNSRV_HOME%\tmp\lib\base-opt.jar;%SIGNSRV_HOME%\tmp\lib\caTokenCard.jar;%SIGNSRV_HOME%\tmp\lib\pcscOCFTerminal.jar;%SIGNSRV_HOME%\tmp\lib\pkcs15.jar.jar;%SIGNSRV_HOME%\tmp\lib\securityProvider.jar;%SIGNSRV_HOME%\tmp\lib\smartCard.jar;%SIGNSRV_HOME%\lib\ext\ejb\jboss-ejb3x.jar
set CP=%SIGNSRV_HOME%\tmp\bin\classes

rem check that we have built the classes
if not exist %CP% (
    echo You must build SIGNSERVER before using the cli, use 'ant'.
    goto end
)

rem Due to short limit of windows command line, we can not use the below to
rem automgically construct the classpath, as we can du with unices.
rem 
rem SETLOCAL ENABLEDELAYEDEXPANSION
rem IF ERRORLEVEL 1 echo Unable to enable extensions
rem for %%i in (%J2EE_DIR%\*.jar) do set J2EE_CP=%%i;!J2EE_CP!
rem for %%i in (%SIGNSRV_HOME%\lib\*.jar) do set CP=%%i;!CP!
rem for %%i in (%SIGNSRV_HOME%\dist\*.jar) do set CP=%%i;!CP!

set CLASSPATH=%J2EE_CP%;%SIGNSERVER_CP%;%CP%;%SIGNSRV_HOME%\bin
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
"%JAVA_HOME%\bin\java" -cp %CLASSPATH% %class_name% %a% %b% %c% %d% %e% %f% %g% %h% %i% %j% 

:end
