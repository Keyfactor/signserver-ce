#!/bin/bash

# Find directory for this script
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink -f "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

APPJARS=`find "${DIR}/../lib" -name "SignServer-TimeMonitor-*.jar"`

# Construct class path
CP=$DIR/../conf/
for jar in ${APPJARS}; do
    CP=${CP}:${jar}
done

# Enable Java network debug logs
#JAVA_OPTS="$JAVA_OPTS -Djavax.net.debug=all"
#JAVA_OPTS="$JAVA_OPTS -Djavax.net.debug=ssl"

# Enable Java PKCS#11 debug logs
#JAVA_OPTS="$JAVA_OPTS -Djava.security.debug=sunpkcs11"

# Enable Java debugging
#JAVA_OPTS="$JAVA_OPTS -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=n"
#JAVA_OPTS="$JAVA_OPTS -Xrunjdwp:transport=dt_socket,address=8788,server=y,suspend=y"

echo "Directing output to ${DIR}/../timemonitor.out"
JAVA_OPTS="$JAVA_OPTS -Dtimemonitor.home=$DIR/.."
java $JAVA_OPTS -cp ${CP} org.signserver.timemonitor.cli.Main >> ${DIR}/../timemonitor.out 2>&1 &
PID=$!

if [ ! -z "$TIMEMONITOR_PIDFILE" ]; then
        echo $PID > $TIMEMONITOR_PIDFILE
else
        echo "PID: $PID"
fi
