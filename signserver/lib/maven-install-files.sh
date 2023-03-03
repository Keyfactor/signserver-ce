#!/usr/bin/env bash

# Find directory for this script
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink -f "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"


# Below add commands for manually installing dependencies to Maven.
# Note that this is intended as a temporarily solution until artifacts are in the repo.

echo "Will call mvn install:install-file with certain dependencies from ${DIR}/lib/ext/."

# Install BC: As we currently use a beta version. This should be removed after upgrading to official release.
mvn install:install-file -Dfile=${DIR}/ext/bcutil-jdk18on-1.73b.12.jar -DgroupId=org.bouncycastle -DartifactId=bcutil-jdk18on -Dversion=1.73b.12 -Dpackaging=jar
mvn install:install-file -Dfile=${DIR}/ext/bcprov-jdk18on-1.73b.12.jar -DgroupId=org.bouncycastle -DartifactId=bcprov-jdk18on -Dversion=1.73b.12 -Dpackaging=jar
mvn install:install-file -Dfile=${DIR}/ext/bcpkix-jdk18on-1.73b.12.jar -DgroupId=org.bouncycastle -DartifactId=bcpkix-jdk18on -Dversion=1.73b.12 -Dpackaging=jar
mvn install:install-file -Dfile=${DIR}/ext/bcpg-jdk18on-1.73b.12.jar -DgroupId=org.bouncycastle -DartifactId=bcpg-jdk18on -Dversion=1.73b.12 -Dpackaging=jar

# Add next group of dependencies here
