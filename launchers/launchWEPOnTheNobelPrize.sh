#!/bin/sh

python3 ../wep/WEP.py \
    ../workflows/xml/The\ Nobel\ Prize.bpmn \
    ../workflows/operations/ \
    --logLevel=INFO \
    --logFile=theNoblePrize.log \
    --allExecutions
    
