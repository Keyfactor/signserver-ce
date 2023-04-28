#!/usr/bin/env bash

# Find directory for this script
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink -f "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"


# Below add commands for manually installing dependencies to Maven (for CE see separate file for EE).
# Note that this is intended as a temporarily solution until artifacts are in the repo.

echo "Will call mvn install:install-file with certain dependencies from ${DIR}/ext/."

# Install KFC dependencies not yet in Central
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/x509-common-util-0.3.jar" -DgroupId=org.ejbca.cesecore -DartifactId=x509-common-util -Dversion=0.3 -Dpackaging=jar

# Add next group of dependencies here


# Install EE dependencies as well if available
if [ -f "${DIR}/maven-install-files-ee.sh" ]; then
    source "${DIR}/maven-install-files-ee.sh"
fi
