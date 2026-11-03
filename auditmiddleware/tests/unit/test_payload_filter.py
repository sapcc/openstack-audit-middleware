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

"""Tests for filtering recorded payloads with include/exclude."""

import json
import types
import uuid

from auditmiddleware._api import OpenStackAuditMiddleware
from auditmiddleware.tests.unit import base


def _spec(**payloads):
    return types.SimpleNamespace(payloads=dict(enabled=True, **payloads))


clean = OpenStackAuditMiddleware._clean_payload


class CleanPayloadTest(base.BaseAuditMiddlewareTest):
    """Unit tests for _clean_payload."""

    def test_no_filter_keeps_body(self):
        """Without include/exclude the body is kept as is."""
        body = [{'a': 1}, 'x']
        self.assertEqual(body, clean(body, _spec()))

    def test_exclude_flat(self):
        """Excluded top-level keys are removed."""
        self.assertEqual({'a': 1},
                         clean({'a': 1, 'secret': 2},
                               _spec(exclude=['secret'])))

    def test_exclude_wrapped_and_nested(self):
        """Excluded keys are removed inside wrappers and lists."""
        body = {'server': {'secret': 1, 'a': 2,
                           'sub': [{'secret': 3, 'b': 4}]}}
        self.assertEqual({'server': {'a': 2, 'sub': [{'b': 4}]}},
                         clean(body, _spec(exclude=['secret'])))

    def test_exclude_list(self):
        """Excluded keys are removed from each list item."""
        self.assertEqual([{'a': 1}, 'x'],
                         clean([{'a': 1, 'secret': 2}, 'x'],
                               _spec(exclude=['secret'])))

    def test_exclude_does_not_change_request(self):
        """Filtering works on a copy of the request body."""
        body = {'server': {'secret': 1}}
        clean(body, _spec(exclude=['secret']))
        self.assertEqual({'server': {'secret': 1}}, body)

    def test_include_flat(self):
        """Only included top-level keys are kept."""
        self.assertEqual({'target': 'on'},
                         clean({'target': 'on', 'password': 'x'},
                               _spec(include=['target'])))

    def test_include_list_of_dicts(self):
        """An include list filters each dict in a list, drops the rest."""
        self.assertEqual([{'target': 'on'}, {}],
                         clean([{'target': 'on', 'password': 'x'},
                                {'password': 'y'}, 'z'],
                               _spec(include=['target'])))

    def test_include_scalar_dropped(self):
        """An include list records nothing for non-dict bodies."""
        self.assertEqual({}, clean('secret', _spec(include=['target'])))
        self.assertEqual({}, clean(None, _spec(include=['target'])))

    def test_include_wrapped_not_unwrapped(self):
        """An include list does not look into wrapper elements."""
        self.assertEqual({}, clean({'node': {'target': 'on',
                                             'password': 'x'}},
                                   _spec(include=['target'])))

    def test_include_keeps_falsy_values(self):
        """Included keys with false or empty values are kept."""
        self.assertEqual({'maintenance': False},
                         clean({'maintenance': False, 'x': 1},
                               _spec(include=['maintenance'])))

    def test_include_and_exclude(self):
        """Both include and exclude apply."""
        body = {'target': {'state': 'on', 'password': 'x'}, 'other': 1}
        self.assertEqual({'target': {'state': 'on'}},
                         clean(body, _spec(include=['target'],
                                           exclude=['password'])))


class PayloadFilterEventTest(base.BaseAuditMiddlewareTest):
    """End-to-end: filtered payloads in events (nova test mapping)."""

    def setUp(self):
        """Set the service info."""
        super(PayloadFilterEventTest, self).setUp()
        self.service_name = 'nova'
        self.service_type = 'compute'

    def _payload(self, req_json):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid)
        request, response = self.build_api_call('PUT', url,
                                                req_json=req_json)
        event = self.build_event(request, response, record_payloads=True,
                                 metrics_enabled=False)
        att = [a for a in event['attachments'] if a['name'] == 'payload']
        return json.loads(att[0]['content'])

    def test_list_body_excluded_attr_removed(self):
        """Excluded attribute is removed from a list body."""
        self.assertEqual([{'a': 1}],
                         self._payload([{'hidden_attr': 's', 'a': 1}]))

    def test_wrapped_body_excluded_attr_removed(self):
        """Excluded attribute is removed from a wrapped body."""
        self.assertEqual({'server': {'a': 1}},
                         self._payload({'server': {'hidden_attr': 's',
                                                   'a': 1}}))
