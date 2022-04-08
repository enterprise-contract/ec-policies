#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

FORMAT=${1:-pretty}
DATA_DIR=$(dirname $0)/data
POLICY_DIR=$(dirname $0)/../policies

# We currently don't fail the pipeline if the check fails
# We can add the --fail or --fail-defined flags later, if we want to
opa eval \
  --data $DATA_DIR \
  --data $POLICY_DIR \
  --format $FORMAT \
  data.hacbs.contract.main.deny
