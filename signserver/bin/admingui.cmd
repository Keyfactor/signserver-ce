@echo off

rem library classpath
if "%SIGNSERVER_HOME%" == "" (
  set SIGNSRV_HOME=..
  rem It must work to call both as bin\signserver.cmd or from within bin
  if not exist signserver.cmd set SIGNSRV_HOME=.
 ) else (
    set SIGNSRV_HOME=%SIGNSERVER_HOME%
) 
  
set SIGNSERVER_CP=%SIGNSRV_HOME%\lib\log4j.jar;%SIGNSRV_HOME%\lib\1.6\bcprov-jdk.jar;%SIGNSRV_HOME%\lib\1.6\bcmail-jdk.jar;%SIGNSRV_HOME%\lib\ejbca-util.jar;%SIGNSRV_HOME%\lib\cert-cvc.jar;%SIGNSRV_HOME%\lib\commons-lang-2.0.jar;%SIGNSRV_HOME%\lib\ext\ejb\jboss-ejb3x.jar;%SIGNSRV_HOME%\lib\asm\asm-3.1.jar;%SIGNSRV_HOME%\lib\asm\asm-commons-3.1.jar;%SIGNSRV_HOME%\lib\commons-lang-2.4.jar;%SIGNSRV_HOME%\lib\ext\commons-cli-1.0.jar;%SIGNSRV_HOME%\dist-client\lib\SignServer-Common.jar;%SIGNSRV_HOME%\dist-client\lib\SignServer-ejb.jar;%SIGNSRV_HOME%\dist-client\SignServer-AdminGUI.jar
set J2EE_CP=%SIGNSRV_HOME%\dist-client\lib\jbossall-client.jar

set SIGNSERVER_PKG_CP=%SIGNSRV_HOME%\lib\asm-3.1.jar;%SIGNSRV_HOME%\lib\asm-commons-3.1.jar;%SIGNSRV_HOME%\lib\bcmail-jdk.jar;%SIGNSRV_HOME%\lib\bcprov-jdk.jar;%SIGNSRV_HOME%\lib\commons-lang-2.0.jar;%SIGNSRV_HOME%\lib\ejbca-util.jar;%SIGNSRV_HOME%\lib\cert-cvc.jar;%SIGNSRV_HOME%\lib\jbossall-client.jar;%SIGNSRV_HOME%\lib\jboss-ejb3x.jar;%SIGNSRV_HOME%\lib\log4j.jar;%SIGNSRV_HOME%\lib\signserver-cli.jar

set class_name=org.signserver.admin.gui.SignServerAdminGUIApplication

rem check that we have built the classes

if not exist %SIGNSRV_HOME%\dist-client\SignServer-AdminCLI.jar  (
    echo SignServer AdminGUI not available. Build it by running 'ant admingui'.
    goto end
)


set CLASSPATH=%J2EE_CP%;%SIGNSERVER_CP%;%SIGNSRV_HOME%\bin;%SIGNSRV_HOME%\dist-client\SignServer-AdminCLI.jar;%SIGNSERVER_PKG_CP%
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
  java -cp %CLASSPATH% -splash:%SIGNSRV_HOME%/modules/SignServer-AdminGUI/src/splash.png %class_name% %a% %b% %c% %d% %e% %f% %g% %h% %i% %j% -connectfile %SIGNSRV_HOME%/modules/SignServer-AdminGUI/connect.properties -defaultconnectfile %SIGNSRV_HOME%/modules/SignServer-AdminGUI/default_connect.properties
) else (
  "%JAVA_HOME%\bin\java" -cp %CLASSPATH% -splash:%SIGNSRV_HOME%/modules/SignServer-AdminGUI/src/splash.png %class_name% %a% %b% %c% %d% %e% %f% %g% %h% %i% %j% -connectfile %SIGNSRV_HOME%/modules/SignServer-AdminGUI/connect.properties -defaultconnectfile %SIGNSRV_HOME%/modules/SignServer-AdminGUI/default_connect.properties

)
:end
