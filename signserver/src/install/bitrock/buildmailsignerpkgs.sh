#!/bin/bash
# This script requires that ant and builder is in the path
# and signserver_build.properties should be preconfigured.

if [ ! -n "$1" ]; then
  echo "Usage : ./buildmailsignerpkgs.sh <version>"
  exit
fi

echo "Generating MailSigner Installation Packages for version $1"

cd ../../..
ant clean 
ant
ant pkgdist

cd src/install/bitrock

builder build mailsignernode-unix.xml linux --setvars project.version="$1"
builder build mailsignermgmt-unix.xml linux --setvars project.version="$1"
builder build mailsignernode-windows.xml windows --setvars project.version="$1"
builder build mailsignermgmt-windows.xml windows --setvars project.version="$1"
