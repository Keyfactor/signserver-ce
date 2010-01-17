#!/bin/bash


STAMP=`date +%s`
EXPIRE=$((1000*STAMP+3000))

echo "Expire: $EXPIRE"

./signserver.sh setstatusproperty INSYNC true $EXPIRE
