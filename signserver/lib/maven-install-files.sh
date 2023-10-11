#!/usr/bin/env bash

# Find directory for this script
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink -f "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"


# Below add commands for manually installing dependencies to Maven (for CE see separate file for EE).
# Note that this is intended as a temporarily solution until artifacts are in the repo.

echo "Will call mvn install:install-file with certain dependencies from ${DIR}/ext/."

# Install KFC dependencies not yet in Central
XCU_VERSION=0.7.4
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/x509-common-util-${XCU_VERSION}.jar" -DgroupId=com.keyfactor -DartifactId=x509-common-util -Dversion=${XCU_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/x509-common-util-${XCU_VERSION}-sources.jar" -DgroupId=com.keyfactor -DartifactId=x509-common-util -Dversion=${XCU_VERSION} -Dpackaging=jar -Dclassifier=sources

# Add next group of dependencies here


# Install EE dependencies as well if available
if [ -f "${DIR}/maven-install-files-ee.sh" ]; then
    source "${DIR}/maven-install-files-ee.sh"
fi
