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

"""Tests for on-demand children of singleton resources."""

import uuid

from pycadf import cadftaxonomy as taxonomy

from auditmiddleware.tests.unit import base


class SingletonChildTest(base.BaseAuditMiddlewareTest):
    """Unmapped children of singletons keep the singleton's type URI."""

    def setUp(self):
        """Set the service info."""
        super(SingletonChildTest, self).setUp()
        self.service_name = 'nova'
        self.service_type = 'compute'

    def test_unmapped_child_of_singleton(self):
        """An unknown resource below a singleton is prefixed by it."""
        rid = str(uuid.uuid4().hex)
        url = self.build_url('mynamespace', prefix='/v2/' + self.project_id,
                             child_res='unknowns', child_res_id=rid)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_READ,
                         "compute/mynamespace/Xunknown", rid)

    def test_unmapped_child_of_nested_singleton(self):
        """Same for a singleton child of a regular resource."""
        rid = str(uuid.uuid4().hex)
        rid2 = str(uuid.uuid4().hex)
        url = self.build_url('servers', prefix='/v2/' + self.project_id,
                             res_id=rid,
                             child_res='metadata/unknowns',
                             child_res_id=rid2)
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_READ,
                         "compute/server/metadata/Xunknown", rid2)
