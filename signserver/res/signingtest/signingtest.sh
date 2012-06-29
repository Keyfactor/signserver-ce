#!/bin/bash

# Test script running different signer on sample documents
# assumes signers have been setup using the provided properties file
#
# $Id$

# test that SIGNSERVER_HOME is set
if [ ! -n "${SIGNSERVER_HOME}" ]; then
  SIGNSERVER_HOME=../..
fi

SIGNCLIENT=$SIGNSERVER_HOME/bin/signclient
SCRIPTDIR=$SIGNSERVER_HOME/res/signingtest

# test PDF signer
echo "Testing PDF signer..."
$SIGNCLIENT signdocument -workername TestPDFSigner -infile $SCRIPTDIR/input/test.pdf -outfile $SCRIPTDIR/output/test-out.pdf 
echo "Testing PDF signer done"

# test XML signer
echo "Testing XML signer..."
$SIGNCLIENT signdocument -workername TestXMLSigner -infile $SCRIPTDIR/input/test.xml -outfile $SCRIPTDIR/output/test-out.xml
echo "Testing XML signer done"

# test ODF signer
echo "Testing ODF signer..."
$SIGNCLIENT signdocument -workername TestODFSigner -infile $SCRIPTDIR/input/test.odf -outfile $SCRIPTDIR/output/test-out.odf
echo "Testing ODF signer done"

# test OOXML signer
echo "Testing OOXML signer..."
$SIGNCLIENT signdocument -workername TestOOXMLSigner -infile $SCRIPTDIR/input/test.docx -outfile $SCRIPTDIR/output/test-out.docx  
echo "Testing OOXML signer done"

# test MRTDSODSigner
echo "Testing MRTDSODSigner..."
$SIGNCLIENT signdatagroups -workername TestMRTDSODSigner -data "1=value1\&2=value2\&3=value3" > $SCRIPTDIR/output/test-out.sod
echo "Testing MRTDSODSigner done"

# test CMSSigner
echo "Testing CMS Signer..."
$SIGNCLIENT signdocument -workername TestCMSSigner -infile $SCRIPTDIR/input/test.xml -outfile $SCRIPTDIR/output/test-signed.p7s 
echo "Testing CMS Signer done"

# test TSA
echo "Testing TSA..."
$SIGNCLIENT timestamp -instr "Foobar" -outrep $SCRIPTDIR/output/test-tsa.resp -url http://localhost:8080/signserver/tsa\?workerName=TestTimeStampSigner
echo "Testing TSA done"
