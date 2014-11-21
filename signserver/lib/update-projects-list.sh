#!/bin/bash
# Updates projects-list.txt with each project used based on the projects
# referenced in jars-list.txt. Information about license etc are filled in
# manually.

# Each project name
PROJECTS=`cat jars-list.txt | awk -F\; '{ print $2}' | sed -e 's/^[ \t]*//'| sort | uniq`

# Previous list of dependencies
PREVFILE="../tmp/projects-list.txt"
mkdir -p ../tmp/
cp projects-list.txt ../tmp/
echo "" > projects-list.txt

OURIFS=$(echo -en "\n\b")
OLDIFS=$IFS
IFS=$OURIFS
for p in ${PROJECTS}
do
    IFS=$OLDIFS
    INFO=`grep "$p" ${PREVFILE}`
    LICENSE=`echo ${INFO} | awk -F\; '{ print $2 }'`
    OTHER1=`echo ${INFO} | awk -F\; '{ print $3 }'`
    OTHER2=`echo ${INFO} | awk -F\; '{ print $4 }'`

    printf "%-28s %-48s %s %s\n" "$p;" "${LICENSE};" "${OTHER1};" "${OTHER2};" >> projects-list.txt
    IFS=$OURIFS
done
IFS=$OLDIFS
