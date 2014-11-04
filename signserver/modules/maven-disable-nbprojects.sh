#!/bin/bash
# Disables NetBeans IDE projects to the pom.xml (Maven) files will be used instead.

FILES=*
for f in $FILES
do
	echo "Processing $f"
	rm $f/nbproject.disabled -rf
	mv $f/nbproject $f/nbproject.disabled
done

echo "If NetBeans IDE was running with any of the SignServer projects open it needs to be restarted now to start use the POM.xml:s."
