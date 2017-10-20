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

JSON = 'application/json'


class AuditApiLogicTest(base.BaseAuditMiddlewareTest):
    def get_payload(self, method, url,
                    audit_map=None, body=None, environ=None):
        req, _ = self.build_api_call(method, url, body, environ)

        return self.build_event(req, audit_map)

    def build_event(self, req, resp=None, middleware_cfg=None):
        cfg = middleware_cfg or self.audit_map
        middleware = auditmiddleware._api.OpenStackAuditMiddleware(cfg)
        return middleware.create_event(req, resp).as_dict()

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
        self.assertEqual(event['target'].get('id'), target_id or 'nova')
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

    def test_get_list(self):
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "service/compute/servers")

    def test_get_read(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_READ,
                         "compute/server", rid)

    def test_put(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('PUT', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server", rid)

    def test_delete(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('DELETE', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_DELETE,
                         "compute/server", rid)

    # TODO: uncomment for swift (which requires a new API pattern)
    # def test_head(self):
    #     rid = str(uuid.uuid4().hex)
    #     url = self.build_url('images', prefix='/v1/' + self.project_id,
    #                          res_id=rid)
    #     request, response = self.build_api_call('HEAD', url)
    #     event = self.build_event(request, response)
    #
    #     self.check_event(request, response, event, taxonomy.ACTION_READ,
    #                      "compute/server", rid)
    #

    def test_post_update(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('POST', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server", rid)

    def test_put_update(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata")
        request, response = self.build_api_call('PUT', url)
        event = self.build_event(request, response)
        print event

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server/metadata", rid)

    def test_put_singleton_child_update_action(self):
        rid = str(uuid.uuid4().hex)
        key = "server_meta_key"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata",
                             action="server_meta_key")
        request, response = self.build_api_call('PUT', url)
        event = self.build_event(request, response)
        print event

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE +
                         "/metadata/" + key,
                         "compute/server/metadata", rid)

    def test_put_singleton_child_delete_action(self):
        rid = str(uuid.uuid4().hex)
        key = "server_meta_key"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata",
                             action="server_meta_key")
        request, response = self.build_api_call('DELETE', url)
        event = self.build_event(request, response)
        print event

        self.check_event(request, response, event, taxonomy.ACTION_DELETE +
                         "/metadata/" + key,
                         "compute/server/metadata", rid)

    def test_get_singleton_child_read_action(self):
        rid = str(uuid.uuid4().hex)
        # this property is modelled as custom action
        key = "server_meta_key"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata",
                             action="server_meta_key")
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)
        print event

        self.check_event(request, response, event, taxonomy.ACTION_READ +
                         "/metadata/" + key,
                         "compute/server/metadata", rid)

    def test_post_create(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('POST', url, resp_json={
            'id': rid})
        event = self.build_event(request, response)
        print event

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid)

    def test_post_create_child(self):
        rid = str(uuid.uuid4().hex)
        child_rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="os-interface")
        request, response = self.build_api_call('POST', url, resp_json={
            'port_id': child_rid})
        event = self.build_event(request, response)
        print event

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server/os-interface", target_id=child_rid)

    def test_post_action(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             action="action", res_id=rid)
        request, response = self.build_api_call('POST', url, req_json={
            "createBackup": {
                "name": "Backup 1",
                "backup_type": "daily",
                "rotation": 1
            }
        })
        event = self.build_event(request, response)

        self.check_event(request, response, event, "backup",
                         "compute/server", rid)

    def test_post_action_no_response(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             action="action", res_id=rid)
        request, response = self.build_api_call('POST', url, req_json={
            "confirmResize": None})
        event = self.build_event(request, response)

        self.check_event(request, response, event, "update/resize-confirm",
                         "compute/server", rid)

    def test_get_service_action(self):
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             action="detail")
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)
        print event

        self.check_event(request, response, event, "read/list/details",
                         "service/compute/servers")

    # TODO: fix and enable for Swift
    # def test_no_auth_token(self):
    #     # Test cases where API requests such as Swift list public containers
    #     # which does not require an auth token. In these cases, CADF event
    #     # should have the defaults (i.e taxonomy.UNKNOWN) instead of raising
    #     # an exception.
    #     env_headers = {'HTTP_X_IDENTITY_STATUS': 'Invalid',
    #                    'REQUEST_METHOD': 'GET'}
    #
    #     path = '/v2/' + self.project_id
    #     url = 'https://23.253.72.207' + path
    #     payload = self.get_payload('GET', url, environ=env_headers)
    #
    #     self.assertEqual(payload['action'], 'read')
    #     self.assertEqual(payload['typeURI'],
    #                      'http://schemas.dmtf.org/cloud/audit/1.0/event')
    #     self.assertEqual(payload['outcome'], 'pending')
    #     self.assertEqual(payload['eventType'], 'activity')
    #     self.assertEqual(payload['target']['name'], taxonomy.UNKNOWN)
    #     self.assertEqual(payload['target']['id'], taxonomy.UNKNOWN)
    #     self.assertEqual(payload['target']['typeURI'], taxonomy.UNKNOWN)
    #     self.assertNotIn('addresses', payload['target'])
    #     self.assertEqual(payload['initiator']['id'], taxonomy.UNKNOWN)
    #     self.assertEqual(payload['initiator']['name'], taxonomy.UNKNOWN)
    #     self.assertEqual(payload['initiator']['project_id'],
    #                      taxonomy.UNKNOWN)
    #     self.assertEqual(payload['initiator']['host']['address'],
    #                      '192.168.0.1')
    #     self.assertEqual(payload['initiator']['typeURI'],
    #                      'service/security/account/user')
    #     self.assertNotEqual(payload['initiator']['credential']['token'],
    #                         None)
    #     self.assertEqual(payload['initiator']['credential']['identity_status'],
    #                      'Invalid')
    #     self.assertNotIn('reason', payload)
    #     self.assertNotIn('reporterchain', payload)
    #     self.assertEqual(payload['observer']['id'], 'target')
    #     self.assertEqual(path, payload['requestPath'])
