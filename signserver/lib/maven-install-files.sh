#!/usr/bin/env bash

# Find directory for this script
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink -f "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

# Below add commands for manually installing dependencies to Maven (for CE see separate file for EE).
# Note that this is intended as a temporarily solution until artifacts are in the repo.

echo "Will call mvn install:install-file with certain dependencies from ${DIR}/ext/."

# Install KFC dependencies not yet in Central
XCU_VERSION=4.1.4
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/x509-common-util-${XCU_VERSION}.jar" -DgroupId=com.keyfactor -DartifactId=x509-common-util -Dversion=${XCU_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/x509-common-util-${XCU_VERSION}-sources.jar" -DgroupId=com.keyfactor -DartifactId=x509-common-util -Dversion=${XCU_VERSION} -Dpackaging=jar -Dclassifier=sources

CRYPTOTOKENS_VERSION=2.3.0
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cryptotokens-api-${CRYPTOTOKENS_VERSION}.jar" -DgroupId=com.keyfactor -DartifactId=cryptotokens-api -Dversion=${CRYPTOTOKENS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/cryptotokens-api-${CRYPTOTOKENS_VERSION}-sources.jar" -DgroupId=com.keyfactor -DartifactId=cryptotokens-api -Dversion=${CRYPTOTOKENS_VERSION} -Dpackaging=jar -Dclassifier=sources

# Install DeployTools dependencies
DEPLOYTOOLS_VERSION=2.3

mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-${DEPLOYTOOLS_VERSION}.pom" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=pom

mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Maven-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Maven -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-Maven-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Maven -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Maven-${DEPLOYTOOLS_VERSION}.pom" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Maven -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=pom


mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-CLI-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-CLI -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-CLI-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-CLI -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-CLI-${DEPLOYTOOLS_VERSION}.pom" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-CLI -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=pom

mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Ant-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Ant -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-Ant-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Ant -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Ant-${DEPLOYTOOLS_VERSION}.pom" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Ant -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=pom

mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Common-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Common -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-Common-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Common -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Common-${DEPLOYTOOLS_VERSION}.pom" -DgroupId=org.signserver.deploytools -DartifactId=DeployTools-Common -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=pom

# BC 1.79 Beta
BC_VERSION=1.79-SNAPSHOT

# BCPG
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/bcpg-jdk18on-${BC_VERSION}.jar" -DgroupId=org.bouncycastle -DartifactId=bcpg-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/bcpg-jdk18on-${BC_VERSION}-sources.jar" -DgroupId=org.bouncycastle -DartifactId=bcpg-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar -Dclassifier=sources

# BCPKIX
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/bcpkix-jdk18on-${BC_VERSION}.jar" -DgroupId=org.bouncycastle -DartifactId=bcpkix-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/bcpkix-jdk18on-${BC_VERSION}-sources.jar" -DgroupId=org.bouncycastle -DartifactId=bcpkix-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar -Dclassifier=sources

# BCPROV
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/bcprov-jdk18on-${BC_VERSION}.jar" -DgroupId=org.bouncycastle -DartifactId=bcprov-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/bcprov-jdk18on-${BC_VERSION}-sources.jar" -DgroupId=org.bouncycastle -DartifactId=bcprov-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar -Dclassifier=sources

# BCUTIL
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/bcutil-jdk18on-${BC_VERSION}.jar" -DgroupId=org.bouncycastle -DartifactId=bcutil-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/bcutil-jdk18on-${BC_VERSION}-sources.jar" -DgroupId=org.bouncycastle -DartifactId=bcutil-jdk18on -Dversion=${BC_VERSION} -Dpackaging=jar -Dclassifier=sources

# Add next group of dependencies here
XADES4J_VERSION=2.2.1-signserver7.0.0
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/xades4j-${XADES4J_VERSION}.jar" -DgroupId=org.signserver.xades4j -DartifactId=xades4j -Dversion=${XADES4J_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/xades4j-${XADES4J_VERSION}-sources.jar" -DgroupId=org.signserver.xades4j -DartifactId=xades4j -Dversion=${XADES4J_VERSION} -Dpackaging=jar -Dclassifier=sources

CESECORE_VERSION=7.0.0.1signserver7.0.0
# cesecore-common jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-common-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-common -Dversion=${CESECORE_VERSION} -Dpackaging=jar

# cesecore-ejb-interfaces jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-interfaces-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-interfaces -Dversion=${CESECORE_VERSION} -Dpackaging=jar

# cesecore-ebj jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-ejb-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-ejb -Dversion=${CESECORE_VERSION} -Dpackaging=jar

# cesecore-entity jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-entity-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-entity -Dversion=${CESECORE_VERSION} -Dpackaging=jar

JACKNJI11_VERSION=1.3.0
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/jacknji11-${JACKNJI11_VERSION}.jar" -DgroupId=com.keyfactor -DartifactId=jacknji11 -Dversion=${JACKNJI11_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/jacknji11-${JACKNJI11_VERSION}-sources.jar" -DgroupId=com.keyfactor -DartifactId=jacknji11 -Dversion=${JACKNJI11_VERSION} -Dpackaging=jar -Dclassifier=sources


FILEUPLOAD_VERSION=1.5-signserver7.0.0
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/commons-fileupload-${FILEUPLOAD_VERSION}.jar" -DgroupId=org.signserver.commons-fileupload -DartifactId=commons-fileupload -Dversion=${FILEUPLOAD_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/commons-fileupload-${FILEUPLOAD_VERSION}-sources.jar" -DgroupId=org.signserver.commons-fileupload -DartifactId=commons-fileupload -Dversion=${FILEUPLOAD_VERSION} -Dpackaging=jar -Dclassifier=sources

# Install EE dependencies as well if available
if [ -f "${DIR}/maven-install-files-ee.sh" ]; then
    source "${DIR}/maven-install-files-ee.sh"
else
    # Install CE version of cesecore source jars
    # cesecore-common source-jar
    mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/cesecore-common-${CESECORE_VERSION}-sources.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-common -Dversion=${CESECORE_VERSION} -Dpackaging=jar -Dclassifier=sources

    # cesecore-ejb-interfaces source-jar
    mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/cesecore-interfaces-${CESECORE_VERSION}-sources.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-interfaces -Dversion=${CESECORE_VERSION} -Dpackaging=jar -Dclassifier=sources

    # cesecore-ejb source-jar
    mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/cesecore-ejb-${CESECORE_VERSION}-sources.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-ejb -Dversion=${CESECORE_VERSION} -Dpackaging=jar -Dclassifier=sources

    # cesecore-entity source-jar
    mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/cesecore-entity-${CESECORE_VERSION}-sources.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-entity -Dversion=${CESECORE_VERSION} -Dpackaging=jar -Dclassifier=sources
fi