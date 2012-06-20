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
  

