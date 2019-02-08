#!/bin/bash
### Install CESeCore jars etc not in an repository and without POM

MAVEN_REPO_DIR=${MAVEN_REPO_DIR:-"${HOME}/.m2/repository"}

mvn -Dmaven.repo.local=${MAVEN_REPO_DIR} install:install-file -Dfile=lib/ext/cesecore-common-7.0.0.1.jar -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-common -Dversion=7.0.0.1 -Dpackaging=jar &&
mvn -Dmaven.repo.local=${MAVEN_REPO_DIR} install:install-file -Dfile=lib/ext/cesecore-entity-7.0.0.1.jar -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-entity -Dversion=7.0.0.1 -Dpackaging=jar &&
mvn -Dmaven.repo.local=${MAVEN_REPO_DIR} install:install-file -Dfile=lib/ext/cesecore-interfaces-7.0.0.1.jar -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-interfaces -Dversion=7.0.0.1 -Dpackaging=jar &&
mvn -Dmaven.repo.local=${MAVEN_REPO_DIR} install:install-file -Dfile=lib/ext/cesecore-ejb-7.0.0.1.jar -DgroupId=org.ejbca.cesecore -DartifactId=cesecore-ejb -Dversion=7.0.0.1 -Dpackaging=ejb
