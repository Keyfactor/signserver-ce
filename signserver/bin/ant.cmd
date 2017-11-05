@echo off
if "%ANT_HOME%" == "" (
  ant -f build.xml -q %*
) else (
  %ANT_HOME%\bin\ant -f build.xml -q %*
)
