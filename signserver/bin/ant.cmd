@echo off
ant -f build.xml -q %1 %2 %3 %4 %5 %6 %7 %8 %9 | FindStr /v "Trying to override old definition of task http://www.netbeans.org/"
