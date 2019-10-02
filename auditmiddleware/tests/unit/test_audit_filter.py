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

"""Test the event creation logic."""

import json
import uuid

from pycadf import cadftaxonomy as taxonomy

from auditmiddleware.tests.unit import base


class AuditApiLogicTest(base.BaseAuditMiddlewareTest):
    """This test suite checks the mapping from API calls to events."""

    def setUp(self):
        """Set up the test by setting the service info."""
        super(AuditApiLogicTest, self).setUp()
        self.service_name = 'nova'
        self.service_type = 'compute'

    def test_get_list(self):
        """Test listing of resources using GET."""
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "compute/servers", None,
                         self.service_name)

    def test_get_list_child(self):
        """Test listing of resource children using GET."""
        rid = str(uuid.uuid4().hex)
        key = "os-volume_attachments"
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res=key)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "compute/server/volume-attachments", rid)

    def test_get_read(self):
        """Test reading of resources using HTTP GET."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_READ,
                         "compute/server", rid)

    def test_head_read(self):
        """Test existence of resources using HTTP HEAD."""
        rid = str(uuid.uuid4().hex)
        # such API does not exist in Nova
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('HEAD', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_READ,
                         "compute/server", rid)

    def test_put(self):
        """Test upsert of resources using HTTP PUT."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('PUT', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server", rid)

    def test_patch(self):
        """Test selective update of resource attributes using HTTP PATCH."""
        rid = str(uuid.uuid4().hex)
        # such API does not exist in Nova
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('PATCH', url, req_json="{}")
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server", rid)

    def test_patch_custom_attr(self):
        """Test selective update of custom resource attributes using PATCH."""
        rid = str(uuid.uuid4().hex)
        custom_value = {'child1': 'test'}
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
        """Test deletion of resources using HTTP DELETE."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('DELETE', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_DELETE,
                         "compute/server", rid)

    def test_delete_child(self):
        """Test deletion of child resources using HTTP DELETE.

        regression test for
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
        """Test deletion of all child-resources at once."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res='tags')
        request, response = self.build_api_call('DELETE', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_DELETE,
                         "compute/server/tags", rid)

    def test_delete_fail(self):
        """Test proper event for failed resource delete actions."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('DELETE', url, resp_code=404)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_DELETE,
                         "compute/server", rid, outcome="failure")

    #  uncomment for swift (which requires a new API pattern)
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
        """Test resource updates using HTTP POST."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('POST', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server", rid)

    def test_put_update_child(self):
        """Test child resource updates using HTTP PUT."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="metadata")
        request, response = self.build_api_call('PUT', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/server/metadata", rid)

    def test_put_singleton_key(self):
        """Test setting keys (custom attributes) from singleton resources."""
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
        """Test deleting keys (custom attributes) from singleton resources."""
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
        """Test reading keys from singleton child resources."""
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
        """Test resource creation using HTTP POST."""
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
        """Test presence of payload attachment."""
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
        """Test creation of resources with target project-id in the URL."""
        rid = str(uuid.uuid4().hex)
        rname = 'server1'
        url = self.build_url('servers', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('POST', url, resp_json={
            'server': {'id': rid, 'name': rname}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/server", rid, rname)

    def test_post_create_cross_project_wrapped(self):
        """Test creation of resources in another project using HTTP POST."""
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
        """Test batch creation of resources using HTTP POST."""
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
        """Test batch creation of resources with mixture of target projects."""
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
        """Test creation of child resources via HTTP POST."""
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
        """Test invocation of custom actions via HTTP POST."""
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
        self.assertEqual(event['attachments'][0]['name'], "payload")
        self.assertEqual(json.loads(event['attachments'][0]['content']),
                         req_json)

    def test_post_action_generic_suppressed(self):
        """Test generic rules for path-encoded actions.

        Suppress event for a HTTP method by mapping to `null`,
        e.g. `POST:*: null`.
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="arbitrary", res_id=rid)
        request, response = self.build_api_call('POST', url)
        event = self.build_event(request, response)

        self.assertIsNone(event, "Event should have been suppressed")

    def test_post_action_suppressed(self):
        """Test rules for path-encoded actions.

        Suppress event for a specific action by mapping to `null`
        e.g. `suppress: null`.
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="suppressed", res_id=rid)
        request, response = self.build_api_call('POST', url)
        event = self.build_event(request, response)

        self.assertIsNone(event, "Event should have been suppressed")

    def test_get_action_generic(self):
        """Test generic rules for path-encoded actions.

        Map all HTTP methods to an action prefix,
        e.g. `GET:*: read/*` to put a `read/` prefix
        in front of any action suffix of the URL path.
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="generic", res_id=rid)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, "read/generic",
                         "compute/server", rid)

    def test_put_key(self):
        """Test attaching custom attributes (keys) to resources.

        Keys are used to add user-defined attributes to resources.
        """
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
        """Test that actions lacking a payload cause no event.

        Custom actions that do not created resources, do not always
        create a response message.
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="action", res_id=rid)
        request, response = self.build_api_call('POST', url)
        event = self.build_event(request, response)

        self.assertIsNone(event, "malformed ./action with no payload should "
                                 "be ignored")

    def test_post_undefined_action_generic(self):
        """Test that actions w/o declared mapping are still causing events.

        Actions encoded in the payload do not need require a mapping entry
        if they follow the standard OpenStack pattern for actions.

        That pattern is that the URL path ends with `/action` and the
        JSON payload has a root attribute named after the action.
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="action", res_id=rid)
        request, response = self.build_api_call('POST', url,
                                                req_json={"unknown": "bla"})
        event = self.build_event(request, response)
        self.check_event(request, response, event, taxonomy.ACTION_UPDATE +
                         "/unknown", "compute/server", rid)

    def test_post_resource_undeclared(self):
        """Test that resource paths w/o mapping are still causing events.

        Those events can be spotted by the "X" prefixing the resource
        name derived from the URL path.
        """
        rid = str(uuid.uuid4().hex)
        rname = "myname"
        url = self.build_url('yetunknowns', prefix='/v2/' + self.project_id)
        request, response = self.build_api_call('POST', url,
                                                resp_json={'yetunknown': {
                                                    'id': rid, 'name': rname}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "compute/Xyetunknown", rid, rname)

    def test_put_resource_undeclared(self):
        """Test that resource paths w/o mapping are still causing events.

        Those events can be spotted by the "X" prefixing the resource
        name derived from the URL path.
        """
        rid = str(uuid.uuid4().hex)
        rid2 = str(uuid.uuid4().hex)
        url = self.build_url('yetunknowns', prefix='/v2/' + self.project_id,
                             res_id=rid, child_res="uchilds",
                             child_res_id=rid2)
        request, response = self.build_api_call('PUT', url, req_json={})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_UPDATE,
                         "compute/Xyetunknown/Xuchild", rid2)

    def test_post_action_no_response(self):
        """Test events are created for POST actions with no response payload.

        The implementation must not assume that a response always has a
        payload.
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="action", res_id=rid)
        request, response = self.build_api_call('POST', url, req_json={
            "confirmResize": None})
        event = self.build_event(request, response)

        self.check_event(request, response, event, "update/resize-confirm",
                         "compute/server", rid)

    def test_get_service_action(self):
        """Test singleton actions directed at a service.

        Those should create events where the target has no ID but a name
        """
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             suffix="detail")
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, "read/list/details",
                         "compute/servers", None,
                         self.service_name)

        # this test needs to be passed for Swift. Currently audit-middleware
        # does not support the REST patterns implemented by Swift
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
