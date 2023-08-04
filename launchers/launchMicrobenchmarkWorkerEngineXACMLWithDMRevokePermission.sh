#!/bin/sh

locust -f simulator/Engine.py \
    "microbenchmark/revoke_permission_from_role.json" \
    XACMLWithDM \
    --loglevel=INFO \
    --uniqueTransientResourceNames --uniqueRoleNames \
    --host=https://127.0.0.1:8446 \
    --csv=results/XACMLWithDM_AllWorkflows \
    --headless \
    --worker \
    --master-host=127.0.0.1 \
    --master-port=5557
