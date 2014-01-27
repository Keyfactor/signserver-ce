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
    echo You must set APPSRV_HOME before running the SignServer AdminGUI.
    goto end
)

rem check that we have built the classes
if not exist %SIGNSRV_HOME%\lib\SignServer-AdminGUI.jar  (
    echo You must build SignServer before using the cli, use 'ant'.
    goto end
)

set class_name=org.signserver.admin.gui.SignServerAdminGUIApplication

rem check that we have built the classes
if not exist %SIGNSRV_HOME%\lib\SignServer-AdminGUI.jar  (
    echo SignServer AdminGUI not available. Build it by running 'ant'.
    goto end
)

rem Construct the classpath
set MAIN_CLASSPATH=%SIGNSRV_HOME%\conf;%SIGNSRV_HOME%\lib\SignServer-AdminGUI.jar

rem Application server dependencies
if exist %APPSRV_HOME%\lib\appserv-rt.jar (
    set JEE_CLASSPATH=%CLASSPATH%;%SIGNSRV_HOME%\conf\glassfish;%APPSRV_HOME%\lib\appserv-rt.jar
)
if exist %APPSRV_HOME%\client\jbossall-client.jar  (
    set JEE_CLASSPATH=%CLASSPATH%;%SIGNSRV_HOME%\conf\jboss;%APPSRV_HOME%\client\jbossall-client.jar
)

set CLASSPATH=%MAIN_CLASSPATH%;%JEE_CLASSPATH%
rem echo %CLASSPATH%


if "%JAVA_HOME%" == "" (
  java -cp %CLASSPATH% -splash:%SIGNSRV_HOME%\res\admingui-splash.png %class_name% %* -connectfile %SIGNSRV_HOME%/conf/admingui.properties -defaultconnectfile %SIGNSRV_HOME%/conf/admingui_default.properties -basedir %SIGNSRV_HOME%
) else (
  "%JAVA_HOME%\bin\java" -cp %CLASSPATH% -splash:%SIGNSRV_HOME%\res\admingui-splash.png %class_name% %* -connectfile %SIGNSRV_HOME%/conf/admingui.properties -defaultconnectfile %SIGNSRV_HOME%/conf/admingui_default.properties -basedir %SIGNSRV_HOME%

)
:end
