#!/bin/sh

python3 ../wep/WEP.py \
    ../workflows/xml/The\ Pizza\ Collaboration.bpmn \
    ../workflows/operations/ \
    --logLevel=INFO \
    --logFile=thePizzaCollaboration.log \
    --allExecutions
