#!/bin/bash
# Updates jars-list.txt with each jar file, its hash (external jars only),
# and which project it comes from (filled in manually).

# External dependencies
EXT=`find ./ext -name "*.jar" -o -name "*.bin" | LC_ALL=C sort`

# Things we build our self
INT=`find . -name "*-Lib-*.jar" | LC_ALL=C sort`
VERSION=`grep "app.version.number=" ../res/deploytools/app.properties | sed "s/app.version.number=//"`

# Previous list of dependencies
PREVFILE="../tmp/jars-list.txt"
mkdir -p ../tmp/
cp jars-list.txt ../tmp/
echo -n "" > jars-list.txt

for f in $EXT
do
    # Checksum (and file name)
    SUM=`sha256sum $f`

    # Fill in project name from previous file
    PROJECT=`grep $f ${PREVFILE} | awk -F\; '{ print $2 }' | sed -e 's/^[ \t]*//'`

    printf "%-120s  %s\n" "${SUM};" "${PROJECT}" >> jars-list.txt
done

for f1 in $INT
do
    # Remove our version number as it makes the build process tricky
    f=`echo $f1 | sed "s/-${VERSION}//"`

    # Only file name for JARs we build
    SUM=`printf "%64s  %s" " " "$f"`

    # Fill in project name from previous file
    PROJECT=`grep $f ${PREVFILE} | awk -F\; '{ print $2 }' | sed -e 's/^[ \t]*//'`

    printf "%-120s  %s\n" "${SUM};" "${PROJECT}" >> jars-list.txt
done
