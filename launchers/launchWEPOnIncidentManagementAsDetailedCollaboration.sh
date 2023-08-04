#!/bin/sh

python3 ../wep/WEP.py \
    ../workflows/xml/Incident\ Management\ as\ Detailed\ Collaboration.bpmn \
    ../workflows/operations/ \
    --logLevel=DEBUG \
    --logFile=theIncedentManagementAsCollaboration.log \
    --allExecutions
    

