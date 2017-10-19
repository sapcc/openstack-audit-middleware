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
from pycadf import cadftaxonomy as taxonomy

import auditmiddleware
from auditmiddleware.tests.unit import base


class AuditApiLogicTest(base.BaseAuditMiddlewareTest):
    def get_payload(self, method, url,
                    audit_map=None, body=None, environ=None):
        req, _ = self.build_api_call(method, url, body, environ)

        return self.build_event(req, audit_map)

    def build_event(self, req, resp=None, middleware_cfg=None):
        cfg = middleware_cfg or self.audit_map
        middleware = auditmiddleware._api.OpenStackAuditMiddleware(cfg)
        return middleware.create_event(req, resp).as_dict()

    def build_api_call(self, method, url, req_body=None,
                       resp_json=None, resp_code=0,
                       environ=None):
        environ = environ or self.get_environ_header()
        req = webob.Request.blank(url,
                                  body=req_body,
                                  method=method,
                                  environ=environ,
                                  remote_addr='192.168.0.1')
        resp = webob.Response()
        if resp_json:
            resp.json = resp_json

        if resp_code == 0:
            resp.status_code = \
            {'GET': 200, 'HEAD': 200, 'POST': 201, 'PUT': 200, 'DELETE': 204}[
                method]
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
        self.assertEqual(event['action'], action)
        self.assertEqual(event['typeURI'],
                         'http://schemas.dmtf.org/cloud/audit/1.0/event')
        self.assertEqual(event['outcome'], outcome)
        self.assertEqual(event['eventType'], 'activity')
        self.assertEqual(event['target'].get('name'), target_name)
        self.assertEqual(event['target'].get('id'), target_id or self.project_id)
        self.assertEqual(event['target']['typeURI'], target_type_uri)
        self.assertEqual(event['initiator']['id'], self.user_id)
        self.assertEqual(event['initiator'].get('name'), self.username)
        self.assertEqual(event['initiator']['project_id'], self.project_id)
        self.assertEqual(event['initiator']['host']['address'],
                         '192.168.0.1')
        self.assertEqual(event['initiator']['typeURI'],
                         'service/security/account/user')
        # TODO: review current behaviour (why have an obfuscated token
        # instead of a prefix)
        self.assertNotEqual(event['initiator']['credential']['token'], 'token')
        self.assertEqual(event['initiator']['credential']['identity_status'],
                         'Confirmed')
        # these fields are only available for finished requests
        if outcome == 'pending':
            self.assertNotIn('reason', event)
            self.assertNotIn('reporterchain', event)
        else:
            self.assertEqual(event['reason']['reasonType'], 'HTTP')
            self.assertEqual(event['reason']['reasonCode'], str(response.status_code))

        # TODO check observer
        self.assertEqual(event['requestPath'], request.path)

    def build_url(self, res, host_url=None, prefix='', action=None, res_id=None, child_res=None, child_res_id=None):
        url = host_url if host_url else 'http://admin_host:8774' + prefix
        url += '/' + res
        url += '/' + res_id if res_id else ''
        url += '/' + child_res if child_res else ''
        url += '/' + child_res_id if child_res_id else ''
        url += '/' + action if action else ''

        return url

    def test_get_list(self):
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST, "compute/servers")

    def test_get_read(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id, res_id=rid)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_READ, "compute/servers/server", rid)

    def test_get_unknown_endpoint(self):
        url = 'http://unknown:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('GET', url)

        self.assertEqual(payload['action'], 'read/list')
        self.assertEqual(payload['outcome'], 'pending')
        self.assertEqual(payload['target']['name'], 'unknown')
        self.assertEqual(payload['target']['id'], 'unknown')
        self.assertEqual(payload['target']['typeURI'], 'unknown')

    def test_get_unknown_endpoint_default_set(self):
        with open(self.audit_map, "w") as f:
            f.write("[DEFAULT]\n")
            f.write("target_endpoint_type = compute\n")
            f.write("[path_keywords]\n")
            f.write("servers = server\n\n")
            f.write("[service_endpoints]\n")
            f.write("compute = service/compute")

        url = 'http://unknown:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('GET', url)

        self.assertEqual(payload['action'], 'read/list')
        self.assertEqual(payload['outcome'], 'pending')
        self.assertEqual(payload['target']['name'], 'nova')
        self.assertEqual(payload['target']['id'], 'resource_id')
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')

    def test_put(self):
        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('PUT', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'update')
        self.assertEqual(payload['outcome'], 'pending')

    def test_delete(self):
        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('DELETE', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'delete')
        self.assertEqual(payload['outcome'], 'pending')

    def test_head(self):
        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('HEAD', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'read')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_update(self):
        url = 'http://admin_host:8774/v2/%s/servers/%s' % (self.project_id,
                                                           uuid.uuid4().hex)
        payload = self.get_payload('POST', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers/server')
        self.assertEqual(payload['action'], 'update')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_create(self):
        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('POST', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers')
        self.assertEqual(payload['action'], 'create')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_action(self):
        url = 'http://admin_host:8774/v2/%s/servers/action' % self.project_id
        body = b'{"createImage" : {"name" : "new-image","metadata": ' \
               b'{"ImageType": "Gold","ImageVersion": "2.0"}}}'
        payload = self.get_payload('POST', url, body=body)
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers/action')
        self.assertEqual(payload['action'], 'update/createImage')
        self.assertEqual(payload['outcome'], 'pending')

    def test_post_empty_body_action(self):
        url = 'http://admin_host:8774/v2/%s/servers/action' % self.project_id
        payload = self.get_payload('POST', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/servers/action')
        self.assertEqual(payload['action'], 'create')
        self.assertEqual(payload['outcome'], 'pending')

    def test_custom_action(self):
        host_id = uuid.uuid4().hex
        url = 'http://admin_host:8774/v2/%s/os-hosts/%s/reboot' % (
            self.project_id, host_id)
        payload = self.get_payload('GET', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/os-host')
        self.assertEqual(payload['target']['id'], host_id)
        self.assertEqual(payload['action'], 'start/reboot')
        self.assertEqual(payload['outcome'], 'unknown')

    def test_custom_action_complex(self):
        url = 'http://admin_host:8774/v2/%s/os-migrations' % self.project_id
        payload = self.get_payload('GET', url)

        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/os-migrations')
        self.assertEqual(payload['action'], 'read')
        payload = self.get_payload('POST', url)
        self.assertEqual(payload['target']['typeURI'],
                         'service/compute/os-migrations')
        self.assertEqual(payload['action'], 'create')

    def test_response_mod_msg(self):
        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        req = webob.Request.blank(url,
                                  environ=self.get_environ_header('GET'),
                                  remote_addr='192.168.0.1')
        req.context = {}
        middleware = self.create_simple_middleware()
        middleware._process_request(req, webob.Response())
        payload = req.environ['cadf_event'].as_dict()
        self.assertEqual(payload['outcome'], 'success')
        self.assertEqual(payload['reason']['reasonType'], 'HTTP')
        self.assertEqual(payload['reason']['reasonCode'], '200')
        self.assertEqual(len(payload['reporterchain']), 1)
        self.assertEqual(payload['reporterchain'][0]['role'], 'modifier')
        self.assertEqual(payload['reporterchain'][0]['reporter']['id'],
                         'target')

    def test_missing_catalog_endpoint_id(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
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
                       'HTTP_X_USER_ID': self.user_id,
                       'HTTP_X_USER_NAME': self.username,
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': self.project_id,
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}

        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('GET', url, environ=env_headers)
        self.assertEqual(payload['target']['id'], 'nova')

    def test_endpoint_missing_internal_url(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                           '''[{"endpoints_links": [],
                                "endpoints": [{"adminURL":
                                               "http://admin_host:8774",
                                               "region": "RegionOne",
                                               "publicURL":
                                               "http://public_host:8774"}],
                                 "type": "compute",
                                 "name": "nova"}]''',
                       'HTTP_X_USER_ID': self.user_id,
                       'HTTP_X_USER_NAME': self.username,
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': self.project_id,
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}

        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('GET', url, environ=env_headers)
        self.assertEqual((payload['target']['addresses'][1]['url']), "unknown")

    def test_endpoint_missing_public_url(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                           '''[{"endpoints_links": [],
                                "endpoints": [{"adminURL":
                                               "http://admin_host:8774",
                                               "region": "RegionOne",
                                               "internalURL":
                                               "http://internal_host:8774"}],
                                 "type": "compute",
                                 "name": "nova"}]''',
                       'HTTP_X_USER_ID': self.user_id,
                       'HTTP_X_USER_NAME': self.username,
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': self.project_id,
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}

        url = 'http://admin_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('GET', url, environ=env_headers)
        self.assertEqual((payload['target']['addresses'][2]['url']), "unknown")

    def test_endpoint_missing_admin_url(self):
        env_headers = {'HTTP_X_SERVICE_CATALOG':
                           '''[{"endpoints_links": [],
                                "endpoints": [{"region": "RegionOne",
                                               "publicURL":
                                               "http://public_host:8774",
                                               "internalURL":
                                               "http://internal_host:8774"}],
                                 "type": "compute",
                                 "name": "nova"}]''',
                       'HTTP_X_USER_ID': self.user_id,
                       'HTTP_X_USER_NAME': self.username,
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': self.project_id,
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed',
                       'REQUEST_METHOD': 'GET'}

        url = 'http://public_host:8774/v2/' + self.project_id + '/servers'
        payload = self.get_payload('GET', url, environ=env_headers)
        self.assertEqual((payload['target']['addresses'][0]['url']), "unknown")

    def test_no_auth_token(self):
        # Test cases where API requests such as Swift list public containers
        # which does not require an auth token. In these cases, CADF event
        # should have the defaults (i.e taxonomy.UNKNOWN) instead of raising
        # an exception.
        env_headers = {'HTTP_X_IDENTITY_STATUS': 'Invalid',
                       'REQUEST_METHOD': 'GET'}

        path = '/v1/' + str(uuid.uuid4())
        url = 'https://23.253.72.207' + path
        payload = self.get_payload('GET', url, environ=env_headers)

        self.assertEqual(payload['action'], 'read')
        self.assertEqual(payload['typeURI'],
                         'http://schemas.dmtf.org/cloud/audit/1.0/event')
        self.assertEqual(payload['outcome'], 'pending')
        self.assertEqual(payload['eventType'], 'activity')
        self.assertEqual(payload['target']['name'], taxonomy.UNKNOWN)
        self.assertEqual(payload['target']['id'], taxonomy.UNKNOWN)
        self.assertEqual(payload['target']['typeURI'], taxonomy.UNKNOWN)
        self.assertNotIn('addresses', payload['target'])
        self.assertEqual(payload['initiator']['id'], taxonomy.UNKNOWN)
        self.assertEqual(payload['initiator']['name'], taxonomy.UNKNOWN)
        self.assertEqual(payload['initiator']['project_id'],
                         taxonomy.UNKNOWN)
        self.assertEqual(payload['initiator']['host']['address'],
                         '192.168.0.1')
        self.assertEqual(payload['initiator']['typeURI'],
                         'service/security/account/user')
        self.assertNotEqual(payload['initiator']['credential']['token'],
                            None)
        self.assertEqual(payload['initiator']['credential']['identity_status'],
                         'Invalid')
        self.assertNotIn('reason', payload)
        self.assertNotIn('reporterchain', payload)
        self.assertEqual(payload['observer']['id'], 'target')
        self.assertEqual(path, payload['requestPath'])
