#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Build open standard audit information based on incoming requests.

AuditMiddleware filter should be placed after
keystonemiddleware.auth_token in the pipeline so that it can utilise the
information the Identity server provides.
"""

from auditmiddleware import _api
from auditmiddleware import _notifier
import copy
import datetime
import functools
from oslo_config import cfg
from oslo_context import context as oslo_context
from oslo_log import log as logging
import pycadf
import pytz
import webob.dec

_LOG = None
AUDIT_MIDDLEWARE_GROUP = 'audit_middleware_notifications'

_AUDIT_OPTS = [
    cfg.StrOpt('driver',
               help='The Driver to handle sending notifications. Possible '
                    'values are messaging, messagingv2, routing, log, test, '
                    'noop. If not specified, then value from '
                    'oslo_messaging_notifications conf section is used.'),
    cfg.ListOpt('topics',
                help='List of AMQP topics used for OpenStack notifications. If'
                     ' not specified, then value from '
                     ' oslo_messaging_notifications conf section is used.'),
    cfg.StrOpt('transport_url',
               secret=True,
               help='A URL representing messaging driver to use for '
                    'notification. If not specified, we fall back to the same '
                    'configuration used for RPC.'),
    cfg.IntOpt('mem_queue_size',
               help='Size of the in-memory queue that is used to buffer '
                    'messages that have not yet been accepted by the '
                    'transport'),
]
CONF = cfg.CONF
CONF.register_opts(_AUDIT_OPTS, group=AUDIT_MIDDLEWARE_GROUP)


# see https://bugs.launchpad.net/pycadf/+bug/1738737
def patched_get_utc_now(timezone=None):
    """Return the current UTC time.

    :param timezone: an optional timezone param to offset time to.
    """
    utc_datetime = pytz.utc.localize(datetime.datetime.utcnow())
    if timezone is not None:
        try:
            utc_datetime = utc_datetime.astimezone(pytz.timezone(timezone))
        except Exception as e:
            _LOG.exception('Error translating timezones: %s ', e)

    return utc_datetime.isoformat()


# monkey patch pycadfs flawed timestamp formatter
pycadf.timestamp.get_utc_now = patched_get_utc_now


def _log_and_ignore_error(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception:
            _LOG.exception('An exception occurred processing '
                           'the API call with args: {0}{1}'
                           .format(args, kwargs))

    return wrapper


class ConfigError(BaseException):
    """Exception for configuration errors."""

    pass


class AuditMiddleware(object):
    """Create an audit event based on request/response.

    The audit middleware takes in various configuration options such as the
    ability to skip audit of certain requests. The full list of options can
    be discovered here:
    https://github.com/sapcc/openstack-audit-middleware/blob/master/README.md
    """

    def __init__(self, app, **conf):
        """Initialize the middleware based on the application config.

        Parameters:
            app: the web application exteneded by this middleware
            conf: the application specific configuration parameters as dict
        """
        self._application = app
        self._conf = CONF

        global _LOG
        _LOG = logging.getLogger(conf.get('log_name', __name__))
        self._ignore_req_list = [x.upper().strip() for x in
                                 conf.get('ignore_req_list', '').split(',')]
        self._cadf_audit = _api.OpenStackAuditMiddleware(
            conf.get('audit_map_file'),
            conf.get('record_payloads', False),
            conf.get('metrics_enabled', False),
            _LOG)

        self._notifier = _notifier.create_notifier(self._conf, _LOG,
                                                   conf.get('metrics_enabled',
                                                            False))
        _LOG.debug("audit middleware config: %s", conf)

    @_log_and_ignore_error
    def _process_request(self, request, response=None):
        """Create & push events for request/response pair."""
        events = self._cadf_audit.create_events(request, response)

        if events:
            # currently there is nothing useful in the context
            request.environ['audit.context'] = {}
            for e in events:
                ctx = request.environ['audit.context']
                self._notifier.notify(ctx, e.as_dict())

    @webob.dec.wsgify
    def __call__(self, req):
        """Here is the actual application call that we are "decorating"."""
        if req.method in self._ignore_req_list:
            return req.get_response(self._application)

        # Cannot use a RequestClass on wsgify above because the `req` object is
        # a `WebOb.Request` when this method is called so the RequestClass is
        # ignored by the wsgify wrapper.
        ctx = oslo_context.get_admin_context().to_dict()
        req.environ['audit.context'] = ctx

        try:
            response = req.get_response(self._application)
        except Exception:
            self._process_request(req)
            raise
        else:
            self._process_request(req, response)
        return response


def _list_opts():
    """Return a list of oslo_config options available in audit middleware.

    The returned list includes all oslo_config options which may be registered
    at runtime by the project.

    Each element of the list is a tuple. The first element is the name of the
    group under which the list of elements in the second element will be
    registered. A group name of None corresponds to the [DEFAULT] group in
    config files.

    :returns: a list of (group_name, opts) tuples
    """
    return [(AUDIT_MIDDLEWARE_GROUP, copy.deepcopy(_AUDIT_OPTS))]


def filter_factory(global_conf, **local_conf):
    """Return a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def audit_filter(app):
        return AuditMiddleware(app, **conf)

    return audit_filter
