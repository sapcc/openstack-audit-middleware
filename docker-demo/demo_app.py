"""Minimal WSGI app wrapped with AuditMiddleware.

By default events are written to stdout via the 'log' oslo.messaging driver.
Set AUDIT_DRIVER=raw_amqp and AUDIT_TRANSPORT_URL=rabbit://... to publish
plain JSON events directly to RabbitMQ without an oslo envelope.

Run locally (log driver):

    cd ~/go/src/github.com/sapcc/openstack-audit-middleware
    .venv/bin/python docker-demo/run_local.py 8282

Run with Docker Compose (raw_amqp driver + RabbitMQ):

    cd docker-demo && docker compose up --build

Then hit it:

    curl -s -H "X-Identity-Status: Confirmed" \\
         -H "X-User-Id: $(python3 -c 'import uuid; print(uuid.uuid4())')" \\
         -H "X-User-Name: admin" \\
         -H "X-Project-Id: $(python3 -c 'import uuid; print(uuid.uuid4())')" \\
         -H "X-Project-Name: demo" \\
         http://localhost:8080/v2/REPLACE_WITH_PROJECT_ID/servers
"""
import json
import os

from oslo_config import cfg
from oslo_log import log as logging
import webob
import webob.dec

import auditmiddleware


# --------------------------------------------------------------------------- #
# oslo.config / oslo.log bootstrap (no config file needed)
# --------------------------------------------------------------------------- #
logging.register_options(cfg.CONF)
cfg.CONF(['--config-file', '/dev/null'] if os.path.exists('/dev/null') else [],
         project='audit-demo')
logging.setup(cfg.CONF, 'audit-demo')

driver = os.environ.get('AUDIT_DRIVER', 'log')
transport_url = os.environ.get('AUDIT_TRANSPORT_URL', '')

cfg.CONF.set_override('driver', driver, group='audit_middleware_notifications')
if transport_url:
    cfg.CONF.set_override('transport_url', transport_url,
                          group='audit_middleware_notifications')
if driver in ('raw_amqp', 'log', '', None):
    # raw_amqp and log both bypass oslo_messaging; use _LogNotifier / _RawAmqpNotifier
    cfg.CONF.set_override('use_oslo_messaging', False,
                          group='audit_middleware_notifications')
else:
    # named oslo driver (messaging, messagingv2, routing, etc.)
    cfg.CONF.set_override('use_oslo_messaging', True,
                          group='audit_middleware_notifications')

# --------------------------------------------------------------------------- #
# The "backend" service — just echoes the request path
# --------------------------------------------------------------------------- #
@webob.dec.wsgify
def _backend(req):
    body = json.dumps({'path': req.path, 'method': req.method})
    return webob.Response(
        body=body.encode('utf-8'),
        content_type='application/json',
        charset='utf-8',
        status=200,
    )


# --------------------------------------------------------------------------- #
# Wrap it with AuditMiddleware using the Nova audit map
# --------------------------------------------------------------------------- #
_audit_map = os.environ.get(
    'AUDIT_MAP',
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'etc', 'nova_audit_map.yaml',
    )
)

app = auditmiddleware.AuditMiddleware(
    _backend,
    audit_map_file=_audit_map,
    service_name='nova',
)
