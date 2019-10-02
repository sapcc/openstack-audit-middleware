# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Base functionality for all tests."""

import auditmiddleware
from auditmiddleware._api import _make_tags
from auditmiddleware.tests.unit import utils
from mock import mock
from oslo_config import fixture as cfg_fixture
from oslo_messaging import conffixture as msg_fixture
from oslotest import createfile
from testtools.matchers import MatchesRegex
import uuid
import webob
import webob.dec


iso8601 = r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}[+-]\d\d:\d\d$'

JSON = 'application/json'

audit_map_content_nova = """
service_type: 'compute'
service_name: 'nova'
prefix: '/v2/[0-9a-z-]*'

resources:
    servers:
        custom_actions:
            createBackup: backup
            confirmResize: update/resize-confirm
            detail: read/list/details
            suppressed: null
            "POST:*": null
            "GET:*": "read/*"
        custom_attributes:
            custom_attr: "xs:string"
            custom_attr2: "/data/compute/server/custom"
        payloads:
            # hide this attribute from payload attachments
            exclude:
              - hidden_attr
        children:
            interfaces:
                api_name: os-interface
                custom_id: port_id
            metadata:
                singleton: true
                type_name: meta
            volume-attachments:
                api_name: os-volume_attachments
                payloads:
                  enabled: false
            tags:
    # pseudo resource representing a namespace
    mynamespace:
      singleton: true
      children:
        someresources:
          type_uri: compute/someresources
"""

user_counter = 0


class BaseAuditMiddlewareTest(utils.MiddlewareTestCase):
    """Base class of all auditmiddleware tests.

    Takes care of middleware configuration, scoping and common
    functionality to build fixtures and validate test outcomes.
    """

    def setUp(self):
        """Set up common parts of all test-cases here."""
        super(BaseAuditMiddlewareTest, self).setUp()

        global user_counter

        self.audit_map_file_fixture = self.useFixture(
            createfile.CreateFileWithContent('audit', audit_map_content_nova,
                                             ext=".yaml"))

        self.cfg = self.useFixture(cfg_fixture.Config())
        self.msg = self.useFixture(msg_fixture.ConfFixture(self.cfg.conf))

        self.cfg.conf([])

        # service_name needs to be redefined by subclass
        self.service_name = None
        self.service_type = None
        self.project_id = str(uuid.uuid4().hex)
        self.user_id = str(uuid.uuid4().hex)
        self.username = "test user " + str(user_counter)
        user_counter += 1

        patcher = mock.patch('datadog.dogstatsd.DogStatsd._report')
        self.statsd_report_mock = patcher.start()
        self.addCleanup(patcher.stop)

    def assert_statsd_counter(self, metric, value, tags=None):
        """Assert that a statsd counter metric has a certain value.

        Parameters:
            metric: name of the metric
            value: expected value of said metric
            tags: tags associated with the metric (dimensions)
        """
        self.statsd_report_mock.assert_any_call(metric, 'c', value, tags, 1)

    def assert_statsd_gauge(self, metric, value, tags=None):
        """Assert that a statsd gauge metric has a certain value.

        Parameters:
            metric: name of the metric
            value: expected value of said metric
            tags: tags associated with the metric (dimensions)
        """
        self.statsd_report_mock.assert_any_call(metric, 'g', value, tags, 1)

    def create_middleware(self, cb, **kwargs):
        """Implement abstract method from base class."""
        @webob.dec.wsgify
        def _do_cb(req):
            return cb(req)

        kwargs.setdefault('audit_map_file', self.audit_map)

        return auditmiddleware.AuditMiddleware(_do_cb, **kwargs)

    @property
    def audit_map(self):
        """Path to the audit mapping file used for this test-case."""
        return self.audit_map_file_fixture.path

    def get_environ_header(self, req_type=None):
        """Provide the headers usually the keystonemiddleware would provide."""
        env_headers = {'HTTP_X_USER_ID': self.user_id,
                       'HTTP_X_USER_NAME': self.username,
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': self.project_id,
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed'}
        if req_type:
            env_headers['REQUEST_METHOD'] = req_type
        return env_headers

    def build_event(self, req, resp=None, middleware_cfg=None,
                    record_payloads=False, metrics_enabled=True):
        """Trigger the creation of a single event from a request/response.

        Parameters:
            req: webob request
            resp: webeb response (unless we have a negative test)
            middleware_cfg (optional): override standard path to the mapping
                file
            record_payloads: option to add request payloads to the CADF event
            metrics_enabled: enable/disable creation of metrics
        """
        event_list = self.build_event_list(req, resp, middleware_cfg,
                                           record_payloads, metrics_enabled)
        if event_list:
            ev = event_list[0]
            if record_payloads:
                self.assertIn('attachments', ev,
                              "attachments missing (and thus no payload att.)")
                payload_attachment = [x['name'] for x in ev['attachments']]
                self.assertIn('payload', payload_attachment,
                              'payload attachment missing')
                self.assertEqual(1, payload_attachment.count('payload'),
                                 "too many payload attachments")
            else:
                self.assertNotIn('payload',
                                 [x['name'] for x in ev.get('attachments',
                                                            [])])

            return ev

        return None

    def build_event_list(self, req, resp=None, middleware_cfg=None,
                         record_payloads=False, metrics_enabled=True):
        """Trigger the actual creation of events from a request/response.

        Parameters:
            req: webob request
            resp: webeb response (unless we have a negative
                test)
            middleware_cfg (optional): override standard path to the mapping
                file
            record_payloads: option to add request payloads to the CADF event
            metrics_enabled: enable/disable creation of metrics
        """
        cfg = middleware_cfg or self.audit_map
        middleware = auditmiddleware._api.OpenStackAuditMiddleware(
            cfg, record_payloads, metrics_enabled=metrics_enabled)
        events = middleware.create_events(req, resp) or []
        if metrics_enabled:
            for e in events:
                self.assert_statsd_counter('events', 1,
                                           tags=_make_tags(e))
            # will not check for operational metrics
        else:
            self.statsd_report_mock.assert_not_called()

        return [e.as_dict() for e in events]

    def build_api_call(self, method, url, req_json=None,
                       resp_json=None, resp_code=0,
                       environ=None):
        """Build a request/response pair for testing.

        This method assumes JSON contents in both.

        Parameters:
            method: HTTP method
            url: URL
            req_json: request payload as dict
            resp_json: response payload as dict
            environ: HTTP headers if default ones do not fit
        """
        environ = environ or self.get_environ_header()
        req = webob.Request.blank(url,
                                  body=None,
                                  method=method,
                                  content_type=JSON,
                                  environ=environ,
                                  remote_addr='192.168.0.1')
        if req_json:
            req.json = req_json
        elif method[0] == 'P' and not url.endswith('action'):
            # POST, PUT, PATCH resource
            req.json = {'name': 'utest'}

        resp = webob.Response(content_type=JSON)
        if resp_json:
            resp.json = resp_json
        elif method == "GET":
            resp.json = {}

        if resp_code == 0:
            resp.status_code = \
                {'GET': 200, 'HEAD': 200, 'PATCH': 200, 'POST': 201, 'PUT':
                    200,
                 'DELETE': 204}[method]
            if method == 'POST' and not resp_json:
                resp.status_code = 204
        else:
            resp.status_code = resp_code

        return req, resp

    def check_event(self, request, response, event, action,
                    target_type_uri,
                    target_id=None,
                    target_name=None,
                    outcome="success"):
        """Check the service-independent parts of an event."""
        self.assertIsNotNone(event, "missing event")
        self.assertEqual(event['action'], action)
        self.assertEqual(event['typeURI'],
                         'http://schemas.dmtf.org/cloud/audit/1.0/event')
        self.assertEqual(event['outcome'], outcome)
        self.assertEqual(event['eventType'], 'activity')
        self.assertThat(event['eventTime'], MatchesRegex(iso8601))
        self.assertEqual(event['target'].get('name'), target_name)
        if target_id:  # only check what is known
            self.assertEqual(event['target'].get('id'), target_id)
        self.assertEqual(event['target']['typeURI'], target_type_uri)
        self.assertEqual(event['observer']['typeURI'],
                         'service/' + self.service_type)
        self.assertIsNotNone(event['observer']['id'])
        self.assertEqual(event['observer'].get('name'), self.service_name)

        self.assertEqual(event['initiator']['id'], self.user_id)
        self.assertEqual(event['initiator'].get('name'), self.username)
        self.assertEqual(event['initiator']['project_id'], self.project_id)
        self.assertEqual(event['initiator']['host']['address'],
                         '192.168.0.1')
        self.assertEqual(event['initiator']['typeURI'],
                         'service/security/account/user')
        # these fields are only available for finished requests
        if outcome == 'pending':
            self.assertNotIn('reason', event)
            self.assertNotIn('reporterchain', event)
        else:
            self.assertEqual(event['reason']['reasonType'], 'HTTP')
            self.assertEqual(event['reason']['reasonCode'],
                             str(response.status_code))

        self.assertEqual(event['requestPath'], request.path)

    def build_url(self, res, host_url=None, prefix='', suffix=None,
                  res_id=None,
                  child_res=None, child_res_id=None):
        """Build a REST URL.

        Parameters:
            res: name of the target resource type
            host_url: URL without path
            prefix: prefix of the URL path (e.g. v2/<tenant>)
            res_id: object ID of the resource
            child_res: target child resource (if target is nested)
            child_res_id: object ID of child resource
        """
        url = host_url if host_url else 'http://admin_host:8774' + prefix
        url += '/' + res
        url += '/' + res_id if res_id else ''
        url += '/' + child_res if child_res else ''
        url += '/' + child_res_id if child_res_id else ''
        url += '/' + suffix if suffix else ''

        return url
