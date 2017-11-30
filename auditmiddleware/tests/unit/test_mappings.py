import os
import uuid

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


class NeutronAuditMappingTest(base.BaseAuditMiddlewareTest):
    def setUp(self):
        super(NeutronAuditMappingTest, self).setUp()

        self.audit_map_file_fixture = "etc/neutron_audit_map.yaml"

        self.audit_map_file_fixture = os.path.realpath(
            self.audit_map_file_fixture)

        self.service_name = 'neutron'

    @property
    def audit_map(self):
        return self.audit_map_file_fixture

    def test_get_list(self):
        url = self.build_url('networks', prefix='/v2.0')
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "service/network/networks",
                         None, self.service_name)

    def test_post_create_neutron_style(self):
        rid = str(uuid.uuid4().hex)
        rname = 'network1'
        url = self.build_url('networks', prefix='/v2.0')
        request, response = self.build_api_call('POST', url, resp_json={
            'network': {'id': rid, 'name': rname}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "network/network", rid, rname)

    def test_post_create_namespaced(self):
        """ tests the use of singleton resources for namespace prefixes
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('fwaas', prefix='/v2.0',
                             child_res="firewall_groups")
        request, response = self.build_api_call('POST', url,
                                                resp_json={'id': rid})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "network/firewall", target_id=rid)

    def test_post_create_merged_namespaced(self):
        """ check whether to namespace-like resources can be mapped to the
        same type URI
        """
        rid = str(uuid.uuid4().hex)
        url = self.build_url('fw', prefix='/v2.0',
                             child_res="firewalls")
        request, response = self.build_api_call('POST', url,
                                                resp_json={'id': rid})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "network/firewall", target_id=rid)

    def test_get_namespaced(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('fwaas', prefix='/v2.0',
                             child_res="firewall_rules", child_res_id=rid)
        request, response = self.build_api_call('GET', url,
                                                resp_json={'id': rid})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_READ,
                         "network/firewall/rule", target_id=rid)

    def test_list_namespaced(self):
        url = self.build_url('qos', prefix='/v2.0',
                             child_res="policies")
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "service/network/qos/policies", None,
                         self.service_name)

    def test_post_create_multiple(self):
        items = [{'id': str(uuid.uuid4().hex), 'name': 'name-' + str(i)} for
                 i in range(3)]

        url = self.build_url('networks', prefix='/v2.0')
        # Note: this batch create call is made up. it does not exist in nova
        request, response = self.build_api_call('POST', url, resp_json={
            "networks": items})

        events = self.build_event_list(request, response)

        for idx, event in enumerate(events):
            self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                             "network/network",
                             items[idx]['id'], items[idx]['name'])
