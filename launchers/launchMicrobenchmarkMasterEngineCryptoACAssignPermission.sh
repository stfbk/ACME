#!/bin/sh

locust -f simulator/Engine.py \
    "microbenchmark/assign_permission_to_role.json" \
    CryptoAC \
    --loglevel=INFO \
    --uniqueTransientResourceNames --uniqueRoleNames \
    --host=https://127.0.0.1:8443 \
    --csv=results/CryptoAC_AllWorkflows \
    --master \
    --autostart \
    --expect-workers=10 \
    --numberOfWorkers=10 \
    --master-bind-port=5557 \
    -t 20m \
    -u 10 \
    -r 0.2
