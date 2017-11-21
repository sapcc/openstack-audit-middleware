import os

from pycadf import cadftaxonomy as taxonomy

from auditmiddleware.tests.unit import base


class NovaAuditMappingTest(base.BaseAuditMiddlewareTest):
    def setUp(self):
        super(NovaAuditMappingTest, self).setUp()

        self.audit_map_file_fixture = "etc/nova_audit_map.yaml"

        self.audit_map_file_fixture = os.path.realpath(
            self.audit_map_file_fixture)

        self.service_name = 'nova'

    @property
    def audit_map(self):
        return self.audit_map_file_fixture

    def test_get_list(self):
        url = self.build_url('servers', prefix='/compute/v2.1')
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "service/compute/servers",
                         None, self.service_name)
