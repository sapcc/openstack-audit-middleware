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
import json
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
        # this property is modelled as singleton
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

    def test_head_read(self):
        rid = str(uuid.uuid4().hex)
        # such API does not exist in Nova
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('HEAD', url)
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

    def test_patch(self):
        rid = str(uuid.uuid4().hex)
        # such API does not exist in Nova
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('PATCH', url, req_json="{}")
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server", rid)

    def test_patch_custom_attr(self):
        rid = str(uuid.uuid4().hex)
        custom_value = {'child1': 'test', 'child2': 'test-two'}
        # such API does not exist in Nova
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call(
            'PATCH', url,
            req_json={'custom_attr2': custom_value},
            resp_json={'custom_attr2': custom_value})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server", rid)

        # check custom attribute
        custom_attachment = {'name': 'custom_attr2',
                             'typeURI': '/data/compute/server/custom',
                             'content': json.dumps(custom_value,
                                                   separators=(',', ':'))}
        self.assertIn(custom_attachment, event['attachments'],
                      "attachment should contain custom_attr value")

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

    def test_put_singleton_key(self):
        rid = str(uuid.uuid4().hex)
        key = "server_meta_key"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata",
                             suffix=key)
        request, response = self.build_api_call('PUT', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event,
                         taxonomy.ACTION_UPDATE + "/set",
                         "compute/server/metadata", rid)
        key_attachment = {'name': 'key',
                          'typeURI': 'xs:string',
                          'content': key}
        self.assertIn(key_attachment, event['target']['attachments'],
                      "attachment should contain key " + key)

    def test_delete_singleton_key(self):
        rid = str(uuid.uuid4().hex)
        key = "server_meta_key"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata",
                             suffix="server_meta_key")
        request, response = self.build_api_call('DELETE', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event,
                         taxonomy.ACTION_DELETE + "/unset",
                         "compute/server/metadata", rid)
        key_attachment = {'name': 'key',
                          'typeURI': 'xs:string',
                          'content': key}
        self.assertIn(key_attachment, event['target']['attachments'],
                      "attachment should contain key " + key)

    def test_get_singleton_child_read_key(self):
        rid = str(uuid.uuid4().hex)
        # this property is modelled as custom action
        key = "server_meta_key"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata",
                             suffix=key)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event,
                         taxonomy.ACTION_READ + "/get",
                         "compute/server/metadata", rid)
        key_attachment = {'name': 'key',
                          'typeURI': 'xs:string',
                          'content': key}
        self.assertIn(key_attachment, event['target']['attachments'],
                      "attachment should contain key " + key)

    def test_post_create(self):
        rid = str(uuid.uuid4().hex)
        rname = 'server1'
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call(
            'POST', url,
            resp_json={'server': {'id': rid, 'name': rname}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid, rname)

    def test_post_create_rec_payload(self):
        rid = str(uuid.uuid4().hex)
        rname = 'server1'
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        payload_content = {'name': rname}
        request, response = self.build_api_call(
            'POST', url,
            req_json=payload_content,
            resp_json={'id': rid, 'name': rname})
        event = self.build_event(request, response, record_payloads=True,
                                 metrics_enabled=False)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid, rname)
        payload_attachment = {'name': 'payload',
                              'content': json.dumps(payload_content,
                                                    separators=(',', ':')),
                              'typeURI': 'mime:application/json'}
        self.assertIn(payload_attachment, event['attachments'],
                      "event attachments should contain payload")

    def test_post_create_neutron_style(self):
        rid = str(uuid.uuid4().hex)
        rname = 'server1'
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('POST', url, resp_json={
            'server': {'id': rid, 'name': rname}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid, rname)

    def test_post_create_cross_project_wrapped(self):
        rid = str(uuid.uuid4().hex)
        pid = str(uuid.uuid4().hex)
        rname = 'server1'
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('POST', url, resp_json={
            'server': {'id': rid, 'name': rname, 'project_id': pid}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid, rname)

        self.assertEqual(pid, event['target']['project_id'],
                         "target attachment should contain target "
                         "project_id for cross-project create actions")

    def test_post_create_multiple_wrapped(self):
        items = [{'id': str(uuid.uuid4().hex), 'name': 'name-' + str(i),
                  'custom_attr': 'custom-' + str(i),
                  'hidden_attr': 'hidden-' + str(i)} for i in range(3)]
        req_json = {"servers": [{
            'name': x['name'],
            'custom_attr': x['custom_attr'],
            'hidden_attr': x['hidden_attr']}
            for x in items]}
        resp_json = {"servers": items}
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        # Note: this batch create call is made up. it does not exist in nova
        request, response = self.build_api_call('POST', url,
                                                req_json=req_json,
                                                resp_json=resp_json)

        events = self.build_event_list(request, response, record_payloads=True)

        for idx, event in enumerate(events):
            self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                             "compute/server",
                             items[idx]['id'], items[idx]['name'])
            # check logged payload
            payload_content = req_json['servers'][idx]
            # make sure the excluded attribute is hidden
            del payload_content['hidden_attr']
            payload_attachment = {'name': 'payload',
                                  'content': json.dumps(payload_content,
                                                        separators=(',', ':')),
                                  'typeURI': 'mime:application/json'}
            self.assertIn(payload_attachment, event['attachments'],
                          "event attachment should contain filtered payload "
                          "copy")
            # check custom attribute
            custom_attachment = {'name': 'custom_attr',
                                 'typeURI': 'xs:string',
                                 'content': payload_content['custom_attr']}
            self.assertIn(custom_attachment, event['attachments'],
                          "attachment should contain custom_attr value")

    def test_post_create_multiple_cross_project_wrapped(self):
        """ test cross-project batch creation.
        """
        items = [{'id': str(uuid.uuid4().hex), 'name': 'name-' + str(i),
                  'project_id': str(uuid.uuid4().hex)} for
                 i in range(3)]

        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        # Note: this batch create call is made up. it does not exist in nova
        req_json = {"servers": [{
            'name': x['name'],
            'project_id': x['project_id']}
            for x in items]}
        resp_json = {"servers": items}
        request, response = self.build_api_call('POST', url,
                                                req_json=req_json,
                                                resp_json=resp_json)

        events = self.build_event_list(request, response, record_payloads=True)

        for idx, event in enumerate(events):
            self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                             "compute/server",
                             items[idx]['id'], items[idx]['name'])
            self.assertEqual(items[idx]['project_id'],
                             event['target']['project_id'],
                             "target attachment should contain target "
                             "project_id for cross-project create actions")
            payload_content = req_json['servers'][idx]
            # make sure the excluded attribute is hidden
            payload_attachment = {'name': 'payload',
                                  'content': json.dumps(payload_content,
                                                        separators=(',', ':')),
                                  'typeURI': 'mime:application/json'}
            self.assertIn(payload_attachment, event['attachments'],
                          "event attachments should contain payload")

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
                             suffix="action", res_id=rid)
        req_json = {
            "createBackup": {"name": "Backup 1", "backup_type": "daily",
                             "rotation": 1}}
        request, response = self.build_api_call('POST', url, req_json=req_json)
        event = self.build_event(request, response, record_payloads=True)

        self.check_event(request, response, event, "backup",
                         "compute/server", rid)
        # attachments should be produced on actions
        self.assertIn("attachments", event)
        self.assertEqual(json.loads(event['attachments'][0]['content']),
                         req_json)

    def test_put_key(self):
        rid = str(uuid.uuid4().hex)
        key = "somekey"
        payload_content = {"meta": {key: "ignored here"}}
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix=key, res_id=rid,
                             child_res="metadata")
        request, response = self.build_api_call('PUT', url,
                                                req_json=payload_content)
        event = self.build_event(request, response, record_payloads=True)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE +
                         "/set",
                         "compute/server/metadata", rid)
        key_attachment = {'name': 'key',
                          'typeURI': 'xs:string',
                          'content': key}
        self.assertIn(key_attachment, event['target']['attachments'],
                      "attachment should contain key " + key)
        # ensure that for key updates also payload recording takes place
        payload_attachment = {'name': 'payload',
                              'content': json.dumps(payload_content,
                                                    separators=(',', ':')),
                              'typeURI': 'mime:application/json'}
        self.assertIn(payload_attachment, event['attachments'],
                      "event attachments should contain payload")

    def test_post_action_missing_payload(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="action", res_id=rid)
        request, response = self.build_api_call('POST', url)
        event = self.build_event(request, response)

        self.assertIsNone(event, "malformed ./action with no payload should "
                                 "be ignored")

    def test_post_undefined_action_generic(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="action", res_id=rid)
        request, response = self.build_api_call('POST', url,
                                                req_json={"unknown": "bla"})
        event = self.build_event(request, response)
        self.check_event(request, response, event, taxonomy.ACTION_UPDATE +
                         "/unknown", "compute/server", rid)

    def test_post_resource_filtered(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="unknown_action", res_id=rid,
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
                             suffix="action", res_id=rid)
        request, response = self.build_api_call('POST', url, req_json={
            "confirmResize": None})
        event = self.build_event(request, response)

        self.check_event(request, response, event, "update/resize-confirm",
                         "compute/server", rid)

    def test_get_service_action(self):
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="detail")
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
