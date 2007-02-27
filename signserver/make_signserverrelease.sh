#!/bin/sh


if [$1 == ""]
then
 echo "The package name must be given to create the release.";
else

 #Remove the old workspace
 rm -rf signserver

 #Checkout
 export CVSROOT=/var/lib/cvs
 cvs co signserver > /dev/null

 #Remove all CVS referenses
 rm -rf signserver/CVS
 rm -rf signserver/*/CVS
 rm -rf signserver/*/*/CVS
 rm -rf signserver/*/*/*/CVS
 rm -rf signserver/*/*/*/*/CVS
 rm -rf signserver/*/*/*/*/*/CVS
 rm -rf signserver/*/*/*/*/*/*/CVS
 rm -rf signserver/*/*/*/*/*/*/*/CVS

 #Set binaries to executable
 chmod +x signserver/bin/signserver.sh

 #Pack the archive
 mv signserver $1
 zip -r $1.zip $1
 
fi





