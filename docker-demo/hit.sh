#!/usr/bin/env bash
# Send a test request to the demo container and pretty-print the audit event
# from its stdout.
#
# Usage:
#   ./hit.sh [port]
#
# The script generates a fresh project_id and user_id UUID each run.

PORT=${1:-8080}
PROJECT_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
USER_ID=$(python3 -c "import uuid; print(uuid.uuid4())")

echo ">>> Hitting http://localhost:${PORT}/v2/${PROJECT_ID}/servers"
echo "    project_id : $PROJECT_ID"
echo "    user_id    : $USER_ID"
echo ""

curl -s -w "\nHTTP %{http_code}\n" \
  -H "X-Identity-Status: Confirmed" \
  -H "X-User-Id: ${USER_ID}" \
  -H "X-User-Name: admin" \
  -H "X-Project-Id: ${PROJECT_ID}" \
  -H "X-Project-Name: demo" \
  "http://localhost:${PORT}/v2/${PROJECT_ID}/servers"

echo ""
echo ">>> Check the docker container logs for the CADF event:"
echo "    docker logs <container-id> 2>&1 | grep -A 100 'audit.cadf'"
