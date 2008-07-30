#!/bin/sh


genCertHelp() {

    echo "$0 <IssuerDN> <SubjectDN> <Output Path> <tomcat.jks passwd> <truststore.jks passwd> <testclient.jks passwd>"
    echo "to make new signserver certificates use something like this"
    echo "$0 'CN=Signserver test CA,O=Acme,C=SE' 'CN=signserver.acme.local,O=Acme,C=SE' /etc/signserver/'
}

if [ "x$1" == "x--help" -o "x$1" == "x-h" ] ; then
    genCertHelp
    exit
fi


if [ "x$1" == "x" ] ; then
    genCertHelp
    exit
else
    issuerDN=$1
fi

if [ "x$2" == "x" ] ; then
    genCertHelp
    exit
else
    subjectDN=$2
fi

if [ "x$3" == "x" ] ; then
    genCertHelp
    exit
else
    outputPath=$3
fi


if [ "x$4" == "x" ] ; then
    genCertHelp
    exit
else
    tomcatJksPassword=$4
fi

if [ "x$5" == "x" ] ; then
    genCertHelp
    exit
else
    trustJksPassword=$5
fi

if [ "x$6" == "x" ] ; then
    genCertHelp
    exit
else
    testClientJksPassword=$6
fi

if [ -r /etc/signserver/signservermgmt.env ] ; then
    . /etc/signserver/signservermgmt.env
else
    echo "signserver environment not setup properly"
    echo "file: /etc/signserver/signservermgmt.env is missing"
    exit
fi

java -jar ${SIGNSERVER_HOME}/lib/genservercert.jar ${issuerDN} ${subjectDN} ${outputPath} ${tomcatJksPassword} ${trustJksPassword} ${testclientJksPassword}

