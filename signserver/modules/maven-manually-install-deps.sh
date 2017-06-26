#!/bin/bash
### Install CESeCore jars etc not in an repository and without POM

mvn install:install-file -Dfile=lib/ext/cesecore-common-6.4.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-common -Dversion=6.4.1 -Dpackaging=jar $@
mvn install:install-file -Dfile=lib/ext/cesecore-entity-6.4.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-entity -Dversion=6.4.1 -Dpackaging=jar $@
mvn install:install-file -Dfile=lib/ext/cesecore-interfaces-6.4.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-interfaces -Dversion=6.4.1 -Dpackaging=jar $@
mvn install:install-file -Dfile=lib/ext/cesecore-ejb-6.4.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-ejb -Dversion=6.4.1 -Dpackaging=ejb $@
mvn install:install-file -Dfile=lib/ext/cert-cvc-1.4.3.jar -DgroupId=org.ejbca.cvc -DartifactId=cert-cvc -Dversion=1.4.3 -Dpackaging=jar $@
mvn install:install-file -Dfile=lib/ext/xades4j-1.3.2-signserver4.jar -DgroupId=org.signserver.xades4j -DartifactId=xades4j -Dversion=1.3.2-signserver4 -Dpackaging=jar $@

# Install DeployTools parent POM
DPL_VERSION=2.0
mvn install:install-file -DgroupId=org.signserver.deploytools -DartifactId=DeployTools -Dversion=${DPL_VERSION} -Dpackaging=pom -Dfile=lib/ext/DeployTools-${DPL_VERSION}-pom.xml $@

# Install the DeployTools artifacts from JARS
# Based on post by David Blevins: https://www.mail-archive.com/users@maven.apache.org/msg91297.html
for jar in lib/ext/DeployTools-Common-${DPL_VERSION}.jar lib/ext/DeployTools-Maven-${DPL_VERSION}.jar; do
    pom=$(jar tvf $jar | grep pom.xml | perl -pe 's,.* ,,')
    props=$(jar tvf $jar | grep pom.properties | perl -pe 's,.* ,,')

    if [ -n "$pom" ]; then
        jar xvf $jar $pom $props
        source $props

        mvn install:install-file -DgroupId=$groupId -DartifactId=$artifactId -Dversion=$version -Dpackaging=jar -Dfile=$jar $@
        mvn install:install-file -DgroupId=$groupId -DartifactId=$artifactId -Dversion=$version -Dpackaging=pom -Dfile=$pom $@

    else
        echo "missing POM.xml in $jar"
    fi
done
rm META-INF -r
