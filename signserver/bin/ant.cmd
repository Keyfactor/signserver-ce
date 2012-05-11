@echo off
ant -f build.xml -q %* | FindStr /v "Trying to override old definition of task http://www.netbeans.org/"
