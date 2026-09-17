# Testing the audit middleware demo

Two modes: **local** (log driver, plain JSON to stdout) and **Docker Compose** (raw_amqp driver,
plain JSON published to RabbitMQ).

---

## Prerequisites

```bash
cd ~/go/src/github.com/sapcc/openstack-audit-middleware
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]" kombu pytz
```

---

## Local mode (log driver)

Events are written as plain JSON lines to stdout — no RabbitMQ needed.

```bash
.venv/bin/python docker-demo/run_local.py 8282
```

In a second terminal:

```bash
PROJECT_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
curl -s \
  -H "X-Identity-Status: Confirmed" \
  -H "X-User-Id: $(python3 -c 'import uuid; print(uuid.uuid4())')" \
  -H "X-User-Name: admin" \
  -H "X-Project-Id: $PROJECT_ID" \
  -H "X-Project-Name: demo" \
  "http://localhost:8282/v2/$PROJECT_ID/servers" | python3 -m json.tool
```

**Expected output in the server terminal** — a plain JSON CADF event with no oslo envelope:

```json
{
  "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
  "eventType": "activity",
  "id": "...",
  "eventTime": "2026-09-17T14:35:49.437779+00:00",
  "action": "read/list",
  "outcome": "success",
  "observer": {"typeURI": "service/compute", ...},
  "initiator": {"project_id": "...", ...},
  "target": {"typeURI": "compute/...", ...},
  "tenant_ids": ["<project-id>"]
}
```

What to check:
- `eventTime` ends with `+00:00` (colon present — RFC 3339 compliant)
- No `oslo.message`, `oslo.version`, or `event_type` keys at the top level
- `tenant_ids` is a non-empty list

---

## Docker Compose mode (raw_amqp driver)

Events are published as plain JSON to RabbitMQ. Requires Docker.

```bash
cd docker-demo
docker compose up --build
```

To force a full rebuild after source changes:

```bash
docker compose build --no-cache audit-demo
docker compose up
```

Send a request using the helper script (generates fresh UUIDs each run):

```bash
bash docker-demo/hit.sh 8083
```

Or manually:

```bash
PROJECT_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
curl -s \
  -H "X-Identity-Status: Confirmed" \
  -H "X-User-Id: $(python3 -c 'import uuid; print(uuid.uuid4())')" \
  -H "X-User-Name: admin" \
  -H "X-Project-Id: $PROJECT_ID" \
  -H "X-Project-Name: demo" \
  "http://localhost:8083/v2/$PROJECT_ID/servers"
```

### Verify the message landed in RabbitMQ

Open the management UI at http://localhost:15673 (guest / guest), navigate to
**Queues**, and check `notifications.info` (or create a temporary binding if the queue does
not yet exist — see below).

Or use the HTTP API to peek at the message without consuming it:

```bash
curl -s -u guest:guest \
  -X POST http://localhost:15673/api/queues/%2F/notifications.info/get \
  -H "Content-Type: application/json" \
  -d '{"count":1,"ackmode":"ack_requeue_true","encoding":"auto"}' \
  | python3 -c "
import sys, json, base64
msgs = json.load(sys.stdin)
if not msgs:
    print('No messages — make sure a queue is bound to notifications exchange')
    sys.exit(1)
body = msgs[0]['payload']
event = json.loads(body)
print(json.dumps(event, indent=2))
"
```

**Create a temporary queue binding** (if the queue doesn't exist yet):

```bash
# Declare the queue
curl -s -u guest:guest -X PUT http://localhost:15673/api/queues/%2F/notifications.info \
  -H "Content-Type: application/json" \
  -d '{"durable":false}'

# Bind it to the notifications exchange with routing key notifications.info
curl -s -u guest:guest \
  -X POST http://localhost:15673/api/bindings/%2F/e/notifications/q/notifications.info \
  -H "Content-Type: application/json" \
  -d '{"routing_key":"notifications.info"}'
```

Then re-send the request and peek again.

**What to check in the message:**
- `content_type` is `application/json`
- Body is a plain JSON CADF event (no `oslo.message` wrapper)
- `eventTime` ends with `+00:00`
- `tenant_ids` is a non-empty list containing the project UUID

---

## Unit tests

```bash
cd ~/go/src/github.com/sapcc/openstack-audit-middleware
.venv/bin/python -m pytest auditmiddleware/tests/unit/ -v
```

Key test files:
- `tests/unit/test_logging_notifier.py` — verifies `_LogNotifier` emits plain JSON (no oslo wrapper)
- `tests/unit/test_audit_oslo_messaging.py` — `RawAmqpNotifierTest` verifies `_RawAmqpNotifier`
  publishes plain JSON with `content_type: application/json`
