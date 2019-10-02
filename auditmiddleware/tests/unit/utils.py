#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Common classes and utils for the tests."""

import fixtures
from oslo_log import log as logging
import oslotest.base as oslotest
import warnings
import webob
import webtest


class MiddlewareTestCase(oslotest.BaseTestCase):
    """Base class for all test-cases."""

    def setUp(self):
        """Set up the test."""
        super(MiddlewareTestCase, self).setUp()

        # If auditmiddleware calls any deprecated function this will raise
        # an exception.
        warnings.filterwarnings('error', category=DeprecationWarning,
                                module='^auditmiddleware\\.')
        self.addCleanup(warnings.resetwarnings)

        self.logger = self.useFixture(fixtures.FakeLogger(level=logging.DEBUG))

    def create_middleware(self, cb, **kwargs):
        """Create a middleware (abstract method to be redefined)."""
        raise NotImplementedError("implement this in your tests")

    def create_simple_middleware(self,
                                 status='200 OK',
                                 body='',
                                 headers=None,
                                 **kwargs):
        """Create a simple middleware with fixed responses.

        Parameters:
            status: HTTP status code to respond with (e.g. '200 OK')
            body: payload of the response
            headers: header fields of the response
            kwargs: custom parameters to be forwarded to create_middleware
        """
        def cb(req):
            resp = webob.Response(body, status)
            resp.headers.update(headers or {})
            return resp

        return self.create_middleware(cb, **kwargs)

    def create_app(self, *args, **kwargs):
        """Create a new app using create_middleware."""
        return webtest.TestApp(self.create_middleware(*args, **kwargs))

    def create_simple_app(self, *args, **kwargs):
        """Create a new app using the create_simple_middleware.

        Arguments are forwarded to create_simple_middleware.
        """
        return webtest.TestApp(self.create_simple_middleware(*args, **kwargs))
