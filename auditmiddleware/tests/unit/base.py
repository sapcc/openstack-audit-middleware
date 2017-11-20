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
import uuid

import webob
import webob.dec
from oslo_config import fixture as cfg_fixture
from oslo_messaging import conffixture as msg_fixture
from oslotest import createfile

import auditmiddleware
from auditmiddleware.tests.unit import utils

JSON = 'application/json'

audit_map_content_nova = """
service_type: 'compute'
service_name: 'nova'
prefix: '/v2/{project_id}'

resources:
    servers:
        custom_actions:
            createBackup: backup
            confirmResize: update/resize-confirm
            detail: read/list/details
        children:
            interfaces:
                api_name: os-interface
                custom_id: port_id
            metadata:
                singleton: true
                custom_actions:
                  'GET:*': 'read/metadata/*'
                  'PUT:*': 'update/metadata/*'
                  'DELETE:*': 'delete/metadata/*'
            volume-attachments:
                api_name: os-volume_attachments
            tags:
    os-services:
        # all default
"""

user_counter = 0


class BaseAuditMiddlewareTest(utils.MiddlewareTestCase):
    PROJECT_NAME = 'auditmiddleware'

    def setUp(self):
        super(BaseAuditMiddlewareTest, self).setUp()

        global user_counter

        self.audit_map_file_fixture = self.useFixture(
            createfile.CreateFileWithContent('audit', audit_map_content_nova,
                                             ext=".yaml"))

        self.cfg = self.useFixture(cfg_fixture.Config())
        self.msg = self.useFixture(msg_fixture.ConfFixture(self.cfg.conf))

        self.cfg.conf([], project=self.PROJECT_NAME)

        # service_name needs to be redefined by subclass
        self.service_name = None
        self.project_id = str(uuid.uuid4().hex)
        self.user_id = str(uuid.uuid4().hex)
        self.username = "test user " + str(user_counter)
        user_counter += 1

    def create_middleware(self, cb, **kwargs):
        @webob.dec.wsgify
        def _do_cb(req):
            return cb(req)

        kwargs.setdefault('audit_map_file', self.audit_map)
        kwargs.setdefault('service_name', 'nova')

        return auditmiddleware.AuditMiddleware(_do_cb, **kwargs)

    @property
    def audit_map(self):
        return self.audit_map_file_fixture.path

    def get_environ_header(self, req_type=None):
        env_headers = {'HTTP_X_USER_ID': self.user_id,
                       'HTTP_X_USER_NAME': self.username,
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': self.project_id,
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'HTTP_X_SERVICE_CATALOG':
                           '''[{"endpoints_links": [],
                                "endpoints": [{"adminURL":
                                               "http://admin_host:8774",
                                               "region": "RegionOne",
                                               "publicURL":
                                               "http://public_host:8774",
                                               "internalURL":
                                               "http://internal_host:8774"}],
                                "type": "compute",
                                "name": "nova"}]''',
                       }
        if req_type:
            env_headers['REQUEST_METHOD'] = req_type
        return env_headers

    def build_event(self, req, resp=None, middleware_cfg=None):
        cfg = middleware_cfg or self.audit_map
        middleware = auditmiddleware._api.OpenStackAuditMiddleware(cfg)
        event = middleware.create_event(req, resp)
        return event.as_dict() if event else None

    def build_api_call(self, method, url, req_json=None,
                       resp_json=None, resp_code=0,
                       environ=None):
        environ = environ or self.get_environ_header()
        req = webob.Request.blank(url,
                                  body=None,
                                  method=method,
                                  content_type=JSON,
                                  environ=environ,
                                  remote_addr='192.168.0.1')
        if req_json:
            req.json = req_json

        resp = webob.Response(content_type=JSON)
        if resp_json:
            resp.json = resp_json

        if resp_code == 0:
            resp.status_code = \
                {'GET': 200, 'HEAD': 200, 'POST': 201, 'PUT': 200,
                 'DELETE': 204}[
                    method]
            if method == 'POST' and not resp_json:
                resp.status_code = 204
        else:
            resp.status_code = resp_code

        return req, resp

    def get_payload(self, method, url,
                    audit_map=None, body=None, environ=None):
        req, _ = self.build_api_call(method, url, body, environ)

        return self.build_event(req, audit_map)

    def check_event(self, request, response, event, action,
                    target_type_uri,
                    target_id=None,
                    target_name=None,
                    outcome="success"):
        self.assertEqual(event['action'], action)
        self.assertEqual(event['typeURI'],
                         'http://schemas.dmtf.org/cloud/audit/1.0/event')
        self.assertEqual(event['outcome'], outcome)
        self.assertEqual(event['eventType'], 'activity')
        self.assertEqual(event['target'].get('name'), target_name)
        if target_id:  # only check what is known
            self.assertEqual(event['target'].get('id'), target_id)
        self.assertEqual(event['target']['typeURI'], target_type_uri)
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

        # TODO check observer
        self.assertEqual(event['requestPath'], request.path)

    def build_url(self, res, host_url=None, prefix='', action=None,
                  res_id=None,
                  child_res=None, child_res_id=None):
        url = host_url if host_url else 'http://admin_host:8774' + prefix
        url += '/' + res
        url += '/' + res_id if res_id else ''
        url += '/' + child_res if child_res else ''
        url += '/' + child_res_id if child_res_id else ''
        url += '/' + action if action else ''

        return url
