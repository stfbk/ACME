#!/bin/sh

python3 simulator/Initializer.py \
    simulator/states/healthcare.json \
    CryptoAC \
    https://127.0.0.1:8443 \
    --logLevel=INFO \
    --seed=1 \
    --doInitialize \
    --flexibleACState \
    --operations="workflows/operations/The_Pizza_Collaboration_WEP.json;workflows/operations/The_Nobel_Prize_WEP.json;workflows/operations/Incident_Management_as_Detailed_Collaboration_WEP.json;workflows/operations/Patient_Treatment_-_Collaboration_WEP.json;workflows/operations/BPI_Web_Registration_with_Moderator_WEP.json"