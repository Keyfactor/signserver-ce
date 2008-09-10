#!/bin/bash
# This script requires that ant and builder is in the path
# The jboss prepared dist should be in JBOSS-DIST and 
# signserver_build.properties should be preconfigured.

if [ ! -n "$1" ]; then
  echo "Usage : ./buildsignserverpkgs.sh <version>"
  exit
fi

echo "Generating SignServer Installation Packages for version $1"

cd ../../..
ant clean 
ant
ant pkgdist

cd src/install/bitrock
builder build signservernode-unix.xml linux --setvars project.version="$1"
builder build signservermgmt-unix.xml linux  --setvars project.version="$1"
builder build signservernode-windows.xml windows  --setvars project.version="$1"
builder build signservermgmt-windows.xml windows  --setvars project.version="$1"
