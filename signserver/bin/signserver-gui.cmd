@echo off

rem library classpath
if "%SIGNSERVER_HOME%" == "" (
  set SIGNSRV_HOME=..
  rem It must work to call both as bin\signserver.cmd or from within bin
  if not exist signserver-gui.cmd set SIGNSRV_HOME=.
 ) else (
    set SIGNSRV_HOME=%SIGNSERVER_HOME%
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

if exist %APPSRV_HOME%\bin\standalone.bat  (
    set JEE_CLASSPATH=%CLASSPATH%;%SIGNSRV_HOME%\conf\jboss7;%APPSRV_HOME%\bin\client\jboss-client.jar
)

set CLASSPATH=%MAIN_CLASSPATH%;%JEE_CLASSPATH%;%EXTRA_CLASSPATH%
rem echo %CLASSPATH%

rem Enable Java network debug logs
rem set JAVA_OPTS="%JAVA_OPTS% -Djavax.net.debug=all"
rem set JAVA_OPTS="%JAVA_OPTS% -Djavax.net.debug=ssl"

rem Enable Java PKCS#11 debug logs
rem set JAVA_OPTS="%JAVA_OPTS% -Djava.security.debug=sunpkcs11"

rem Enable Java debugging
rem set JAVA_OPTS="%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=n"
rem set JAVA_OPTS="%JAVA_OPTS% -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=y"

rem Disable TLS Server Name Indication (SNI)
rem set JAVA_OPTS="%JAVA_OPTS% -Djsse.enableSNIExtension=false"

if "%JAVA_HOME%" == "" (
  java %JAVA_OPTS% -cp %CLASSPATH% -splash:%SIGNSRV_HOME%\res\admingui-splash.png %class_name% %* -connectfile %SIGNSRV_HOME%/conf/admingui.properties -defaultconnectfile %SIGNSRV_HOME%/conf/admingui_default.properties -basedir %SIGNSRV_HOME%
) else (
  "%JAVA_HOME%\bin\java" %JAVA_OPTS% -cp %CLASSPATH% -splash:%SIGNSRV_HOME%\res\admingui-splash.png %class_name% %* -connectfile %SIGNSRV_HOME%/conf/admingui.properties -defaultconnectfile %SIGNSRV_HOME%/conf/admingui_default.properties -basedir %SIGNSRV_HOME%
)
:end
