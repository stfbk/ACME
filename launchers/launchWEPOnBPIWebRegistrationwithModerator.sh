#!/bin/sh

python3 ../wep/WEP.py \
    ../workflows/xml/BPI\ Web\ Registration\ with\ Moderator.bpmn \
    ../workflows/operations/ \
    --logLevel=DEBUG \
    --logFile=theBPIWebRegistrationWithModerator.log \
    --allExecutions
    

