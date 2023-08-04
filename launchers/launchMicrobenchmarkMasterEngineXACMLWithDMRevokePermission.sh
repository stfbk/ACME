#!/bin/sh

locust -f simulator/Engine.py \
    "microbenchmark/revoke_permission_from_role.json" \
    XACMLWithDM \
    --loglevel=INFO \
    --uniqueTransientResourceNames --uniqueRoleNames \
    --host=https://127.0.0.1:8446 \
    --csv=results/XACMLWithDM_AllWorkflows \
    --master \
    --autostart \
    --expect-workers=10 \
    --numberOfWorkers=10 \
    --master-bind-port=5557 \
    -t 20m \
    -u 10 \
    -r 0.2
