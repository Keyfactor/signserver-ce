#!/bin/bash
# Disables NetBeans IDE projects to the pom.xml (Maven) files will be used instead.

FILES=*
for f in $FILES
do
	echo "Processing $f"
	rm $f/nbproject.disabled -rf
	mv $f/nbproject $f/nbproject.disabled
done

### Install CESeCore jars not in an repository and without POM
#mvn install:install-file -Dfile=lib/ext/cesecore-common-6.1.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-common -Dversion=6.1.1 -Dpackaging=jar
#mvn install:install-file -Dfile=lib/ext/cesecore-entity-6.1.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-entity -Dversion=6.1.1 -Dpackaging=jar
#mvn install:install-file -Dfile=lib/ext/cesecore-interfaces-6.1.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-interfaces -Dversion=6.1.1 -Dpackaging=jar
#mvn install:install-file -Dfile=lib/ext/cesecore-ejb-6.1.1.jar -DgroupId=org.cesecore -DartifactId=cesecore-ejb -Dversion=6.1.1 -Dpackaging=ejb
#mvn install:install-file -Dfile=lib/ext/cert-cvc-1.2.11.jar -DgroupId=org.ejbca.cvc -DartifactId=cert-cvc -Dversion=1.2.11 -Dpackaging=jar
#mvn install:install-file -Dfile=lib/ext/xades4j/xades4j-1.3.0-signserver.jar -DgroupId=org.signserver.xades4j -DartifactId=xades4j -Dversion=1.3.0-signserver -Dpackaging=jar
