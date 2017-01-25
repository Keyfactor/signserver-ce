@echo off
if "%ANT_HOME%" == "" (
  ant -f build.xml -q %* | FindStr /v "Trying to override old definition of task http://www.netbeans.org/"
) else (
  %ANT_HOME%\bin\ant -f build.xml -q %* | FindStr /v "Trying to override old definition of task http://www.netbeans.org/"
)
