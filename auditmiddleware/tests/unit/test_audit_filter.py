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

from pycadf import cadftaxonomy as taxonomy

from auditmiddleware.tests.unit import base


class AuditApiLogicTest(base.BaseAuditMiddlewareTest):
    def setUp(self):
        super(AuditApiLogicTest, self).setUp()
        self.service_name = 'nova'
        self.service_type = 'compute'

    def test_get_list(self):
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "compute/servers", None,
                         self.service_name)

    def test_get_list_child(self):
        rid = str(uuid.uuid4().hex)
        # this property is modelled as custom action
        key = "os-volume_attachments"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res=key)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "compute/server/volume-attachments", rid)

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

    #  /v2/a759dcc2a2384a76b0386bb985952373/servers/805780cd-9934-42bd-a0b3
    # -6db177a656b5/os-volume_attachments/e733127c-4bae-429c-bd01-a89ff0b109a2
    def test_delete_child(self):
        """ verify fix for
        https://github.com/sapcc/openstack-audit-middleware/issues/8
        """
        rid = str(uuid.uuid4().hex)
        rid2 = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid,
                             child_res='os-volume_attachments',
                             child_res_id=rid2)
        request, response = self.build_api_call('DELETE', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_DELETE,
                         "compute/server/volume-attachment", rid2)

    def test_delete_all(self):
        """ delete all child-resources at once, i.e. delete w/o child ID
        :return:
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res='tags')
        request, response = self.build_api_call('DELETE', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_DELETE,
                         "compute/server/tags", rid)

    def test_delete_fail(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('DELETE', url, resp_code=404)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_DELETE,
                         "compute/server", rid, outcome="failure")

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

    def test_put_update_child(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata")
        request, response = self.build_api_call('PUT', url)
        event = self.build_event(request, response)

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

        self.check_event(request, response, event, taxonomy.ACTION_READ +
                         "/metadata/" + key,
                         "compute/server/metadata", rid)

    def test_post_create(self):
        rid = str(uuid.uuid4().hex)
        rname = 'server1'
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('POST', url, resp_json={
            'id': rid, 'displayName': rname})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid, rname)

    def test_post_create_neutron_style(self):
        rid = str(uuid.uuid4().hex)
        rname = 'server1'
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('POST', url, resp_json={
            'server': {'id': rid, 'name': rname}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid, rname)

    def test_post_create_multiple(self):
        items = [{'id': str(uuid.uuid4().hex), 'name': 'name-' + str(i)} for
                 i in range(3)]

        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        # Note: this batch create call is made up. it does not exist in nova
        request, response = self.build_api_call('POST', url, resp_json={
            "servers": items})

        events = self.build_event_list(request, response)

        for idx, event in enumerate(events):
            self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                             "compute/server",
                             items[idx]['id'], items[idx]['name'])

    def test_post_create_child(self):
        rid = str(uuid.uuid4().hex)
        child_rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="os-interface")
        request, response = self.build_api_call('POST', url, resp_json={
            'port_id': child_rid})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server/interface", target_id=child_rid)

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

    def test_post_action_default_mapping(self):
        url = self.build_url('os-services', prefix='/v2/' + self.project_id,
                             action="disable")
        request, response = self.build_api_call('PUT', url, req_json={
            "host": "ignored anyway",
            "binary": "ignored too"
        })
        event = self.build_event(request, response)

        self.check_event(request, response, event, "update/disable",
                         "compute/os-services", None,
                         self.service_name)

    def test_post_action_missing_payload(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             action="action", res_id=rid)
        request, response = self.build_api_call('POST', url)
        event = self.build_event(request, response)

        self.assertIsNone(event, "malformed ./action with no payload should "
                                 "be ignored")

    def test_post_action_filtered(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             action="unknown_action", res_id=rid)
        request, response = self.build_api_call('POST', url, req_json={})
        event = self.build_event(request, response)

        self.assertIsNone(event, "unknown actions should be ignored if a "
                                 "mapping was declared")

    def test_post_resource_filtered(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             action="unknown_action", res_id=rid,
                             child_res_id="unknown")
        request, response = self.build_api_call('POST', url, req_json={})
        event = self.build_event(request, response)

        self.assertIsNone(event, "unknown child resources should be ignored")

    def test_put_resource_filtered(self):
        url = self.build_url('unknown', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('PUT', url, req_json={})
        event = self.build_event(request, response)

        self.assertIsNone(event, "unknown resources should be ignored")

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

        self.check_event(request, response, event, "read/list/details",
                         "compute/servers", None,
                         self.service_name)

        # TODO: fix and enable for Swift
        # def test_no_auth_token(self):
        #     # Test cases where API requests such as Swift list public
        # containers
        #     # which does not require an auth token. In these cases,
        # CADF event
        #     # should have the defaults (i.e taxonomy.UNKNOWN) instead of
        # raising
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
        #     self.assertEqual(payload['initiator']['credential'][
        # 'identity_status'],
        #                      'Invalid')
        #     self.assertNotIn('reason', payload)
        #     self.assertNotIn('reporterchain', payload)
        #     self.assertEqual(payload['observer']['id'], 'target')
        #     self.assertEqual(path, payload['requestPath'])
