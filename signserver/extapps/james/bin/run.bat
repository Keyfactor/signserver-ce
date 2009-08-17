@echo off
rem
rem Phoenix start script.
rem
rem Author: Peter Donald [donaldp@apache.org]
rem
rem Environment Variable Prequisites
rem
rem   PHOENIX_OPTS       (Optional) Java runtime options used when the command is
rem                      executed.
rem
rem   PHOENIX_TMPDIR     (Optional) Directory path location of temporary directory
rem                      the JVM should use (java.io.tmpdir).  Defaults to
rem                      $PHOENIX_BASE/temp.
rem
rem   JAVA_HOME          Must point at your Java Development Kit installation.
rem
rem   PHOENIX_JVM_OPTS   (Optional) Java runtime options used when the command is
rem                       executed.
rem
rem -----------------------------------------------------------------------------

rem
rem Determine if JAVA_HOME is set and if so then use it
rem
if not "%JAVA_HOME%"=="" goto found_java

set PHOENIX_JAVACMD=java
goto file_locate

:found_java
set PHOENIX_JAVACMD=%JAVA_HOME%\bin\java

:file_locate

rem
rem Locate where phoenix is in filesystem
rem
if not "%OS%"=="Windows_NT" goto start

rem %~dp0 is name of current script under NT
set PHOENIX_HOME=%~dp0*

rem : operator works similar to make : operator
set PHOENIX_HOME=%PHOENIX_HOME:\bin\*=%

:start

if not "%PHOENIX_HOME%" == "" goto phoenix_home

echo.
echo Error: PHOENIX_HOME environment variable is not set.
echo   This needs to be set manually for Win9x as its command
echo   prompt scripting does not allow it to be set automatically.
echo.
goto end

:phoenix_home

if not "%PHOENIX_TMPDIR%"=="" goto afterTmpDir
set PHOENIX_TMPDIR=%PHOENIX_HOME%\temp
if not exist "%PHOENIX_TMPDIR%" mkdir "%PHOENIX_TMPDIR%"

:afterTmpDir

echo Using PHOENIX_HOME:   %PHOENIX_HOME%
echo Using PHOENIX_TMPDIR: %PHOENIX_TMPDIR%
echo Using JAVA_HOME:      %JAVA_HOME%

set PHOENIX_SM=

if "%PHOENIX_SECURE%" == "false" goto postSecure

rem Make Phoenix run with security Manager enabled
set PHOENIX_SM="-Djava.security.manager"

:postSecure

rem Make sure we don't run with a never expiring cache for InetAddress
rem In Phoenix Main this is read and applied as Security.setProperty
set PHOENIX_JVM_OPTS=%PHOENIX_JVM_OPTS% -Dnetworkaddress.cache.ttl=300

rem
rem -Djava.ext.dirs= is needed as some JVM vendors do foolish things
rem like placing jaxp/jaas/xml-parser jars in ext dir
rem thus breaking Phoenix
rem

rem uncomment to get enable remote debugging
rem set DEBUG=-Xdebug -Xrunjdwp:transport=dt_socket,address=8000,server=y,suspend=y

rem change to the bin directory
cd %PHOENIX_HOME%\bin

rem Kicking the tires and lighting the fires!!!
"%PHOENIX_JAVACMD%" %DEBUG% "-Djava.ext.dirs=%PHOENIX_HOME%\lib;%PHOENIX_HOME%\tools\lib" "-Dphoenix.home=%PHOENIX_HOME%" "-Djava.security.policy=jar:file:%PHOENIX_HOME%/bin/phoenix-loader.jar!/META-INF/java.policy" %PHOENIX_JVM_OPTS% %PHOENIX_SM% -jar "%PHOENIX_HOME%\bin\phoenix-loader.jar" %1 %2 %3 %4 %5 %6 %7 %8 %9

:end

