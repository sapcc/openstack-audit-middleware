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
        self.service_type = 'compute'

    @property
    def audit_map(self):
        return self.audit_map_file_fixture

    def test_get_list(self):
        url = self.build_url('servers', prefix='/compute/v2.1')
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "compute/servers",
                         None, self.service_name)


class NeutronAuditMappingTest(base.BaseAuditMiddlewareTest):
    def setUp(self):
        super(NeutronAuditMappingTest, self).setUp()

        self.audit_map_file_fixture = "etc/neutron_audit_map.yaml"

        self.audit_map_file_fixture = os.path.realpath(
            self.audit_map_file_fixture)

        self.service_name = 'neutron'
        self.service_type = 'network'

    @property
    def audit_map(self):
        return self.audit_map_file_fixture

    def test_get_list(self):
        url = self.build_url('networks', prefix='/v2.0')
        request, response = self.build_api_call('GET', url)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_LIST,
                         "network/networks",
                         None, self.service_name)

    def test_post_create_sgp(self):
        rid = str(uuid.uuid4().hex)
        rname = 'sgr1'
        url = self.build_url('security-group-rules', prefix='/v2.0')
        request, response = self.build_api_call('POST', url, resp_json={
            'security_group_rule': {'id': rid, 'description': rname}})
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "network/security-group-rule", rid, rname)

    def test_post_create_floatingips(self):
        rid = str(uuid.uuid4().hex)
        url = self.build_url('floatingips', prefix='/v2.0')
        fip_request = {"floatingip": {
            "floating_network_id": "376da547-b977-4cfe-9cba-275c80debf57",
            "port_id": "ce705c24-c1ef-408a-bda3-7bbd946164ab",
            "subnet_id": "278d9507-36e7-403c-bb80-1d7093318fe6",
            "fixed_ip_address": "10.0.0.3",
            "floating_ip_address": "172.24.4.228",
            "description": "floating ip for testing",
            "dns_domain": "my-domain.org.",
            "dns_name": "myfip"}}
        fip_response = {
            "floatingip": {"fixed_ip_address": "10.0.0.3",
                           "floating_ip_address": "172.24.4.228",
                           "floating_network_id":
                               "376da547-b977-4cfe-9cba-275c80debf57",
                           "id": rid,
                           "port_id":
                               "ce705c24-c1ef-408a-bda3-7bbd946164ab",
                           "router_id":
                               "d23abc8d-2991-4a55-ba98-2aaea84cc72f",
                           "status": "ACTIVE",
                           "project_id":
                               "4969c491a3c74ee4af974e6d800c62de",
                           "tenant_id":
                               "4969c491a3c74ee4af974e6d800c62de",
                           "description": "floating ip for "
                                          "testing",
                           "dns_domain": "my-domain.org.",
                           "dns_name": "myfip",
                           "created_at": "2016-12-21T01:36:04Z",
                           "updated_at": "2016-12-21T01:36:04Z",
                           "revision_number": 1}}
        request, response = self.build_api_call('POST', url,
                                                req_json=fip_request,
                                                resp_json=fip_response)
        event = self.build_event(request, response)

        self.check_event(request, response, event, taxonomy.ACTION_CREATE,
                         "network/floatingip", rid)

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
                         "network/qos/policies", None,
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
