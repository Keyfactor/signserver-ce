#!/bin/bash -x
echo "Building OpenJDK patch..."

startDir="$(pwd)"

jdkDir=$(readlink -m $(dirname $(readlink -f $(which java)))/../..)
echo "JDK directory: ${jdkDir}"

unzip -qd src/ ${jdkDir}/src.zip

patchJar() {
    jarFile="$1"
    patchFile="$2"
    echo "Attempting to patch ${jarFile} using ${patchFile}..."
    # Patch the JDK source files
    patch -d src/ -p1 < ${patchFile}
    mkdir out-${jarFile//.jar/}/
    # Re-compile any file affected by the patch
    cd src/
    javac -d ../out-${jarFile//.jar/}/ -XDignore.symbol.file $(grep "diff " ../${patchFile} | awk '{print $4}' | sed 's/^b\///' | tr '\r\n' ' ') || exit 1
    cd ..
    # Make a local copy of the JAR from the JDK
    cp "${jdkDir}/jre/lib/ext/${jarFile}" ${jarFile}
    # Update local copy of the JAR with the patched and compiled files
    jar uvf ${jarFile} -C out-${jarFile//.jar/}/ . || exit 1
}

patchJar sunec.jar     jenkins-files/containers/$CONTAINER/binaries/openJDK8-sunec.patch
patchJar sunpkcs11.jar jenkins-files/containers/$CONTAINER/binaries/openJDK8u232-sunpkcs11-v3.patch

mkdir artifacts/

artifactBaseName=$(basename $jdkDir)

cp sunec.jar artifacts/sunec-${artifactBaseName}.jar
cp sunpkcs11.jar artifacts/sunpkcs11-${artifactBaseName}.jar

ls -l artifacts/*

zip -r artifacts-$artifactBaseName.zip artifacts/

