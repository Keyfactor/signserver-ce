#!/usr/bin/env bash

# Sample script for updating the status property TIMESOURCE0_INSYNC and letting 
# it expire in 5 seconds.
# This script must be run from the SIGNSERVER_HOME folder.
#
# An alternative to using the Admin CLI for setting the property is to instead 
# configure a StatusPropertiesWorker and use the Client CLI, HTTP or even the 
# web services interface to update the property. That might be faster and also 
# gives the ability to update the property remotely.

# Get current timestamp
STAMP=`date +%s`
echo "Current time: ${STAMP}000"

# Convert from seconds to milliseconds and add 5 seconds
EXPIRE=$((1000*STAMP+5000))
echo "Will expire:  $EXPIRE"

# Set the property
./bin/signserver setstatusproperty TIMESOURCE0_INSYNC true $EXPIRE
