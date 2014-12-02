#!/bin/bash
# Disables NetBeans IDE projects to the pom.xml (Maven) files will be used instead.

FILES=*
EEFILES=mod-enterprise/*
for f in $FILES $EEFILES
do
	echo "Processing $f"
	if [[ $f != *SignServer-Project* ]]
	then
		rm $f/nbproject.disabled -rf
		mv $f/nbproject $f/nbproject.disabled
	fi
done

echo "If NetBeans IDE was running with any of the SignServer projects open it needs to be restarted now to start use the POM.xml:s."
