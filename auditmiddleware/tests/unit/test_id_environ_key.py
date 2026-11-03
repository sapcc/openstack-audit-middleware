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

"""Tests for resolving resource names to IDs via the WSGI environ."""

import uuid

from oslotest import createfile

from auditmiddleware import _api
from auditmiddleware.tests.unit import base

audit_map_ironic = """
service_type: 'compute/baremetal'
service_name: 'ironic'
prefix: '/v1'

resources:
    nodes:
        custom_id: uuid
        id_environ_key: ironic.node_idents
        children:
            states:
                children:
                    power:
    ports:
        custom_id: uuid
"""

KEY = 'ironic.node_idents'


class IdEnvironKeyTest(base.BaseAuditMiddlewareTest):
    """Names resolved by the service are reported with the real ID."""

    def setUp(self):
        """Use an ironic-like mapping."""
        super(IdEnvironKeyTest, self).setUp()
        self.service_name = 'ironic'
        self.service_type = 'compute/baremetal'
        self.cfg = self.useFixture(createfile.CreateFileWithContent(
            'ironic_map', audit_map_ironic, ext='.yaml')).path
        self.node_id = str(uuid.uuid4())

    def _target(self, method, path, idents=None):
        environ = self.get_environ_header()
        if idents is not None:
            environ[KEY] = idents
        request, response = self.build_api_call(
            method, 'http://admin_host:6385/v1' + path, environ=environ)
        event = self.build_event(request, response, middleware_cfg=self.cfg)
        return event['target']['typeURI'], event['target']['id']

    def test_name_resolved_like_uuid(self):
        """A name in the environ dict gives the same target as the UUID."""
        by_uuid = self._target('PUT', '/nodes/%s/states/provision'
                               % self.node_id)
        by_name = self._target('PUT', '/nodes/node008-gp007/states/provision',
                               {'node008-gp007': self.node_id})
        self.assertEqual(by_uuid, by_name)
        self.assertEqual(self.node_id, by_name[1])
        self.assertNotIn('/X', by_name[0])

    def test_name_resolved_nested(self):
        """Resolution also works for deeper children."""
        by_uuid = self._target('PUT', '/nodes/%s/states/power'
                               % self.node_id)
        by_name = self._target('PUT', '/nodes/node008-gp007/states/power',
                               {'node008-gp007': self.node_id})
        self.assertEqual(by_uuid, by_name)

    def test_name_resolved_last_segment(self):
        """A name as the last path segment resolves too."""
        type_uri, rid = self._target('GET', '/nodes/node008-gp007',
                                     {'node008-gp007': self.node_id})
        self.assertEqual('compute/baremetal/node', type_uri)
        self.assertEqual(self.node_id, rid)

    def test_unknown_name_falls_back(self):
        """Names not in the dict keep the on-demand X resource."""
        type_uri, rid = self._target('PUT',
                                     '/nodes/node008-gp007/states/provision',
                                     {'other': self.node_id})
        self.assertIn('/Xnode008-gp00', type_uri)
        self.assertNotEqual(self.node_id, rid)

    def test_no_environ_falls_back(self):
        """Without the environ dict nothing changes."""
        type_uri, _ = self._target('PUT',
                                   '/nodes/node008-gp007/states/provision')
        self.assertIn('/Xnode008-gp00', type_uri)

    def test_bad_environ_value_ignored(self):
        """A non-dict environ value is ignored."""
        type_uri, _ = self._target('PUT',
                                   '/nodes/node008-gp007/states/provision',
                                   'garbage')
        self.assertIn('/Xnode008-gp00', type_uri)

    def test_key_only_for_configured_resource(self):
        """Resources without id_environ_key do not use the dict."""
        port_id = str(uuid.uuid4())
        type_uri, rid = self._target('PUT', '/ports/myport/foo',
                                     {'myport': port_id})
        self.assertIn('/Xmyport', type_uri)
        self.assertNotEqual(port_id, rid)

    def _shared_target(self, mw, path, idents=None):
        environ = self.get_environ_header()
        if idents is not None:
            environ[KEY] = idents
        request, response = self.build_api_call(
            'PUT', 'http://admin_host:6385/v1' + path, environ=environ)
        event = mw.create_events(request, response)[0].as_dict()
        return event['target']['typeURI'], event['target']['id']

    def test_resolved_after_unresolved_same_worker(self):
        """An earlier unresolved request does not hide later resolution."""
        mw = _api.OpenStackAuditMiddleware(self.cfg, False, False)
        path = '/nodes/node009/states/provision'
        first = self._shared_target(mw, path)
        self.assertIn('/Xnode00', first[0])
        second = self._shared_target(mw, path, {'node009': self.node_id})
        self.assertEqual(self._shared_target(
            mw, '/nodes/%s/states/provision' % self.node_id), second)
        self.assertEqual(self.node_id, second[1])

    def test_id_like_names_resolved(self):
        """Names made of hex digits are resolved, not taken as IDs."""
        mw = _api.OpenStackAuditMiddleware(self.cfg, False, False)
        for name in ('beef', '1234'):
            type_uri, rid = self._shared_target(
                mw, '/nodes/%s/states/provision' % name,
                {name: self.node_id})
            self.assertEqual(self.node_id, rid, name)

    def test_id_in_path_wins_over_environ(self):
        """A node named like a child segment does not replace a path ID."""
        mw = _api.OpenStackAuditMiddleware(self.cfg, False, False)
        other_id = str(uuid.uuid4())
        path = '/nodes/%s/states/provision' % self.node_id
        expected = self._shared_target(mw, path)
        self.assertEqual(expected, self._shared_target(
            mw, path, {'states': other_id}))
        self.assertEqual(self.node_id, expected[1])
