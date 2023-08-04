#!/bin/sh

python3 ../wep/WEP.py \
    ../workflows/xml/Patient\ Treatment\ -\ Collaboration.bpmn \
    ../workflows/operations/ \
    --logLevel=DEBUG \
    --logFile=thePatientTreatmentCollaboration.log \
    --allExecutions
    

