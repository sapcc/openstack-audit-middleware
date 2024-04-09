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

"""HTTP methods are tested in test_http_methods.py."""

from auditmiddleware.tests.unit import base
import unittest
from unittest.mock import MagicMock


class TestHttpMethods(base.BaseAuditMiddlewareTest):
    """Test class for HTTP method handling in auditmiddleware."""

    def setUp(self):
        """Set up the test case."""
        super().setUp()
        self.service_name = 'nova'
        self.service_type = 'compute'

    def test_get_request(self):
        """Test handling of GET requests."""
        mock_request = MagicMock()
        mock_request.method = 'GET'
        mock_request.path = '/v2/servers/00000000-0000-0000-0000-00000000007b'
        mock_request.environ = {
            'HTTP_X_USER_ID': self.user_id,
            'HTTP_X_USER_NAME': self.username,
            'HTTP_X_PROJECT_ID': self.project_id
        }
        mock_request.user_agent = 'python-requests/2.25.1'
        mock_request.client_addr = '192.168.0.1'
        mock_response = MagicMock()
        mock_response.status_int = 200
        mock_response.status_code = 200
        mock_response.content_length = 0

        event = self.build_event(mock_request, mock_response)
        event['requestPath'] = mock_request.path

        self.check_event(mock_request, mock_response, event, 'read',
                         'compute/server', 
                         '00000000-0000-0000-0000-00000000007b',
                         None, 'success')
        self.assertEqual(event['initiator']['id'], self.user_id)

    def test_post_request(self):
        """Test handling of POST requests."""
        mock_request = MagicMock()
        mock_request.method = 'POST'
        mock_request.path = '/v2/servers'
        mock_request.environ = {
            'HTTP_X_USER_ID': self.user_id,
            'HTTP_X_USER_NAME': self.username,
            'HTTP_X_PROJECT_ID': self.project_id
        }
        mock_request.content_type = 'application/json'
        mock_request.json = {'name': 'test-server', 'flavorRef': '2'}
        mock_request.user_agent = 'python-requests/2.25.1'
        mock_request.client_addr = '192.168.0.1'
        mock_response = MagicMock()
        mock_response.status_int = 202
        mock_response.status_code = 202
        mock_response.content_length = 100  
        mock_response.content_type = 'application/json'
        mock_response.json = {'server': {'id': 'xyz'}}
        mock_response.text = '{"server": {"id": "xyz"}}'

        event = self.build_event(mock_request, mock_response)
        event['requestPath'] = mock_request.path

        self.check_event(mock_request, mock_response, event, 'create',
                        'compute/server', 'xyz', None, 'success')
        self.assertEqual(event['initiator']['id'], self.user_id)

    def test_delete_request_with_no_content_length(self):
        """Test handling of DELETE requests with no content length in resp."""
        mock_request = MagicMock()
        mock_request.method = 'DELETE'
        mock_request.path = '/v2/servers/00000000-0000-0000-0000-00000000007b'
        mock_request.environ = {
            'HTTP_X_USER_ID': self.user_id,
            'HTTP_X_USER_NAME': self.username,
            'HTTP_X_PROJECT_ID': self.project_id
        }
        mock_request.client_addr = '192.168.0.1'
        mock_request.user_agent = 'python-requests/2.25.1'
        mock_response = MagicMock()
        mock_response.status_int = 204
        mock_response.status_code = 204
        mock_response.content_length = None
        mock_response.content_type = 'application/json'
        mock_response.text = ''

        event = self.build_event(mock_request, mock_response)
        event['requestPath'] = mock_request.path

        self.check_event(mock_request, mock_response, event, 'delete',
                         'compute/server', 
                         '00000000-0000-0000-0000-00000000007b',
                         None, 'success')
        self.assertEqual(event['initiator']['id'], self.user_id)

    def test_update_request(self):
        """Test handling of UPDATE requests."""
        mock_request = MagicMock()
        mock_request.method = 'PUT'
        mock_request.path = '/v2/servers/00000000-0000-0000-0000-00000000007b'
        mock_request.environ = {
            'HTTP_X_USER_ID': self.user_id,
            'HTTP_X_USER_NAME': self.username,
            'HTTP_X_PROJECT_ID': self.project_id
        }
        mock_request.content_type = 'application/json'
        mock_request.json = {'name': 'updated-server'}
        mock_request.client_addr = '192.168.0.1'
        mock_request.user_agent = 'python-requests/2.25.1'
        mock_response = MagicMock()
        mock_response.status_int = 200
        mock_response.status_code = 200
        mock_response.content_length = 0
        mock_response.content_type = 'application/json'

        event = self.build_event(mock_request, mock_response)
        event['requestPath'] = mock_request.path

        self.check_event(mock_request, mock_response, event, 'update',
                         'compute/server', 
                         '00000000-0000-0000-0000-00000000007b',
                         None, 'success')
        self.assertEqual(event['initiator']['id'], self.user_id)


if __name__ == '__main__':
    unittest.main()
