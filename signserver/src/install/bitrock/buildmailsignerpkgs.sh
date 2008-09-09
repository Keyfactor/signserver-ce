#!/bin/bash
# This script requires that ant and builder is in the path
# The jboss prepared dist should be in JBOSS-DIST and 
# signserver_build.properties should be preconfigured.

cd ../../..
ant clean 
ant
ant pkgdist

cd src/install/bitrock
builder build mailsignernode-unix.xml linux
builder build mailsignermgmt-unix.xml linux
builder build mailsignernode-windows.xml windows
builder build mailsignermgmt-windows.xml windows
