#!/bin/sh

locust -f simulator/Engine.py \
    "workflows/operations/The_Pizza_Collaboration_WEP.json;workflows/operations/The_Nobel_Prize_WEP.json;workflows/operations/Incident_Management_as_Detailed_Collaboration_WEP.json;workflows/operations/Patient_Treatment_-_Collaboration_WEP.json;workflows/operations/BPI_Web_Registration_with_Moderator_WEP.json" \
    CryptoAC \
    --loglevel=INFO \
    --ignorePersistentAssignRevokePermission --ignoreAddUser --ignoreAddRole --ignoreDeleteUser --ignoreDeleteRole \
    --uniqueTransientResourceNames \
    --reservePolicy \
    --reserveUsers \
    --syncPolicyAcrossWorkers \
    --host=https://127.0.0.1:8443 \
    --csv=results/CryptoAC_AllWorkflows \
    --master \
    --autostart \
    --expect-workers=1 \
    --numberOfWorkers=1 \
    --master-bind-port=5557 \
    -t 20m \
    -u 1 \
    -r 0.2
