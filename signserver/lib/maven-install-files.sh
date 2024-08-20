#!/usr/bin/env bash

# Find directory for this script
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink -f "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

# Below add commands for manually installing dependencies to Maven (for CE see separate file for EE).
# Note that this is intended as a temporarily solution until artifacts are in the repo.

echo "Will call mvn install:install-file with certain dependencies from ${DIR}/ext/."

# Install KFC dependencies not yet in Central
XCU_VERSION=0.10.5
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/x509-common-util-${XCU_VERSION}.jar" -DgroupId=com.keyfactor -DartifactId=x509-common-util -Dversion=${XCU_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/x509-common-util-${XCU_VERSION}-sources.jar" -DgroupId=com.keyfactor -DartifactId=x509-common-util -Dversion=${XCU_VERSION} -Dpackaging=jar -Dclassifier=sources

# Install DeployTools dependencies
DEPLOYTOOLS_VERSION=2.3
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Maven-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools.maven -DartifactId=DeployTools-Maven -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-Maven-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools.maven -DartifactId=DeployTools-Maven -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources

mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-CLI-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools.cli -DartifactId=DeployTools-CLI -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-CLI-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools.cli -DartifactId=DeployTools-CLI -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources

mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Ant-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools.ant -DartifactId=DeployTools-Ant -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-Ant-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools.ant -DartifactId=DeployTools-Ant -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources

mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/DeployTools-Common-${DEPLOYTOOLS_VERSION}.jar" -DgroupId=org.signserver.deploytools.common -DartifactId=DeployTools-Common -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/DeployTools-Common-${DEPLOYTOOLS_VERSION}-sources.jar" -DgroupId=org.signserver.deploytools.common -DartifactId=DeployTools-Common -Dversion=${DEPLOYTOOLS_VERSION} -Dpackaging=jar -Dclassifier=sources


# Add next group of dependencies here
OPENPDF_VERSION=1.3.30signserver6.2.0
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/openpdf-${OPENPDF_VERSION}.jar" -DgroupId=org.signserver.librepdf -DartifactId=openpdf -Dversion=${OPENPDF_VERSION} -Dpackaging=jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/../modules/source-jars/openpdf-${OPENPDF_VERSION}-sources.jar" -DgroupId=org.signserver.librepdf -DartifactId=openpdf -Dversion=${OPENPDF_VERSION} -Dpackaging=jar -Dclassifier=sources

CESECORE_VERSION=7.0.0.1signserver7.0.0
# cesecore-common jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-common-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-common -Dversion=${CESECORE_VERSION} -Dpackaging=jar

# cesecore-ejb-interfaces jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-interfaces-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-interfaces -Dversion=${CESECORE_VERSION} -Dpackaging=jar

# cesecore-ebj jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-ejb-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-ejb -Dversion=${CESECORE_VERSION} -Dpackaging=jar

# cesecore-entity jar
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/cesecore-entity-${CESECORE_VERSION}.jar" -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-entity -Dversion=${CESECORE_VERSION} -Dpackaging=jar

JACKNJI11_VERSION=1.2.7
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/jacknji11-${JACKNJI11_VERSION}.jar" -DgroupId=com.keyfactor -DartifactId=jacknji11 -Dversion=${JACKNJI11_VERSION} -Dpackaging=jar

FILEUPLOAD_VERSION=1.5signserver7.0.0
mvn ${MVN_OPTS} install:install-file -Dfile="${DIR}/ext/commons-fileupload-${FILEUPLOAD_VERSION}.jar" -DgroupId=commons-fileupload -DartifactId=commons-fileupload -Dversion=${FILEUPLOAD_VERSION} -Dpackaging=jar

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