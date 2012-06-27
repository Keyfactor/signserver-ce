#!/bin/bash

# Test script running different signer on sample documents
# assumes signers have been setup using the provided properties file
#
# $Id$

# test that SIGNSERVER_HOME is set
if [ ! -n "${SIGNSERVER_HOME}" ]; then
  SIGNSERVER_HOME=..
fi

SIGNCLIENT=$SIGNSERVER_HOME/bin/signclient

# test PDF signer
$SIGNCLIENT signdocument -workername TestPDFSigner -infile test.pdf -outfile test-out.pdf 

# test XML signer
$SIGNCLIENT signdocument -workername TestXMLSigner -infile test.xml -outfile test-out.xml

# test ODF signer
$SIGNCLIENT signdocument -workername TestODFSigner -infile test.odf -outfile test-out.odf

# test OOXML signer
$SIGNCLIENT signdocument -workername TestOOXMLSigner -infile test.docx -outfile test-out.docx  

# test MRTDSODSigner
$SIGNCLIENT signdatagroups -workername TestMRTDSODSigner -data "1=value1\&2=value2\&3=value3" > test-out.sod

# test CMSSigner
$SIGNCLIENT signdocument -workername TestCMSSigner -infile test.xml -outfile test-signed.p7s 

# test TSA
$SIGNCLIENT timestamp -instr "Foobar" -outrep test-tsa.resp -url http://localhost:8080/signserver/tsa\?workerName=TestTimeStampSigner
