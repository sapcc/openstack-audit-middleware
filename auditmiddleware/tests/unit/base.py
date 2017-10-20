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

import webob.dec
from oslo_config import fixture as cfg_fixture
from oslo_messaging import conffixture as msg_fixture
from oslotest import createfile

import auditmiddleware
from auditmiddleware.tests.unit import utils

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
            os-interfaces:
                api_name: os-interface
                custom_id: port_id
            metadata:
                singleton: true
                custom_actions:
                  'GET:*': 'read/metadata/*'
                  'PUT:*': 'update/metadata/*'
                  'DELETE:*': 'delete/metadata/*'
"""

audit_map_content_glance = """
service_type: 'image'
service_name: 'glance'
prefix: '/v2'

resources:
    servers:
      custom_actions:
        '*':
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

        self.project_id = str(uuid.uuid4().hex)
        self.user_id = str(uuid.uuid4().hex)
        self.username = "test user " + str(user_counter)
        user_counter += 1

    def create_middleware(self, cb, **kwargs):
        @webob.dec.wsgify
        def _do_cb(req):
            return cb(req)

        kwargs.setdefault('audit_map_file', self.audit_map)
        kwargs.setdefault('service_name', 'pycadf')

        return auditmiddleware.AuditMiddleware(_do_cb, **kwargs)

    @property
    def audit_map(self):
        return self.audit_map_file_fixture.path

    def get_environ_header(self, req_type=None):
        env_headers = {'HTTP_X_USER_ID': self.user_id,
                       'HTTP_X_USER_NAME': self.username,
                       'HTTP_X_AUTH_TOKEN': 'token',
                       'HTTP_X_PROJECT_ID': self.project_id,
                       'HTTP_X_IDENTITY_STATUS': 'Confirmed'}
        if req_type:
            env_headers['REQUEST_METHOD'] = req_type
        return env_headers
