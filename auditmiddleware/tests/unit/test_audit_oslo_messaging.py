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

"""Test the correct interaction with oslo messaging."""

from auditmiddleware.tests.unit import base
import mock
from oslo_messaging import MessagingException
import time


def delay(*args):
    """Interrupt briefly.

    Can be used as sideeffect parameter of @mock.patch().
    """
    time.sleep(0.1)


class AuditNotifierConfigTest(base.BaseAuditMiddlewareTest):
    """Tests that the various oslo messaging configuration options work."""

    def test_middleware_connect_fail(self):
        """Test that error counter is raised for connect errors."""
        transport_url = 'rabbit://me:passwd@host:5672/virtual_host'
        self.cfg.config(driver='messaging',
                        transport_url=transport_url,
                        group='audit_middleware_notifications')

        with mock.patch('oslo_messaging.notify.notifier.Notifier'
                        '._notify',
                        side_effect=MessagingException("test exception")) as \
                driver:
            app = self.create_simple_app(metrics_enabled=True)
            path = '/v2/' + self.project_id + '/servers'
            app.get(path, extra_environ=self.get_environ_header())
            # audit middleware conf has 'log' make sure that driver is invoked
            # and not the one specified in DEFAULT section
            time.sleep(1)
            self.assertTrue(driver.called)
            self.assert_statsd_counter('errors', 1)

    def test_conf_middleware_log_and_default_as_messaging(self):
        """Make sure log driver is invoked when configured.

        The setting in the audit_middleware_notifications section
        shall win over DEFAULT.
        """
        self.cfg.config(driver='log',
                        group='audit_middleware_notifications')
        app = self.create_simple_app()
        with mock.patch('oslo_messaging.notify._impl_log.LogDriver.notify') \
                as driver:
            path = '/v2/' + self.project_id + '/servers'
            app.get(path, extra_environ=self.get_environ_header())
            time.sleep(1)
            self.assertTrue(driver.called)

    @mock.patch('oslo_messaging.notify._impl_log.LogDriver'
                '.notify', side_effect=delay)
    def test_conf_middleware_log_and_oslo_msg_as_messaging(self, driver):
        """Test that audit_middleware_notifications section has priority.

        This test checks that the log driver will be called if configured
        event if the oslo_messaging_notifications section has 'messaging'.

        Settings in oslo_messaging_notifications section of the application
        configuration should be overridden by the
        audit_middleware_notifications section of the application
        configuration file (e.g. nova.cfg).
        """
        self.cfg.config(driver=['messaging'],
                        group='oslo_messaging_notifications')
        self.cfg.config(driver='log',
                        group='audit_middleware_notifications')

        app = self.create_simple_app()
        path = '/v2/' + self.project_id + '/servers'
        app.get(path, extra_environ=self.get_environ_header())
        # audit middleware conf has 'log'. Make sure that driver is invoked
        # and not the one specified in oslo_messaging_notifications section
        time.sleep(1)
        self.assertTrue(driver.called)

    @mock.patch('oslo_messaging.notify.messaging.MessagingDriver'
                '.notify', side_effect=delay)
    def test_conf_middleware_messaging_and_oslo_msg_as_log(self, driver):
        """Check that audit_middleware_notifications section has precedence.

        Settings in audit_middleware_notifications section of the application
        configuration should always override settings in the generic section
        oslo_messaging_notifications.

        In this case the 'messaging' driver should win over the 'log' driver.
        """
        self.cfg.config(driver=['log'], group='oslo_messaging_notifications')
        self.cfg.config(driver='messaging',
            group='audit_middleware_notifications')
        app = self.create_simple_app(metrics_enabled=True)
        path = '/v2/' + self.project_id + '/servers'
        invocations = 3
        for _ in range(0, invocations):
            app.get(path, extra_environ=self.get_environ_header())
        # check that the backlog has grown
        self.assert_statsd_gauge('backlog', 1)
        time.sleep(1)
        for _ in range(0, invocations):
            delay()
        self.assertTrue(driver.called)
        # check that the backlog has been reset
        self.assert_statsd_gauge('backlog', 0)

    @mock.patch('oslo_messaging.notify.messaging.MessagingDriver'
                '.notify', side_effect=delay)
    def test_with_no_middleware_notification_conf(self, driver):
        """Test that oslo_messaging_notifications section is used as fallback.

        In the audit_middleware_middleware config section no driver is set.
        So driver needs to be taken from oslo_messaging_notifications
        settings.
        """
        self.cfg.config(driver=['messaging'],
                        group='oslo_messaging_notifications')
        self.cfg.config(driver=None, group='audit_middleware_notifications')

        app = self.create_simple_app(metrics_enabled=True)
        path = '/v2/' + self.project_id + '/servers'
        app.get(path, extra_environ=self.get_environ_header())
        time.sleep(1)
        self.assertTrue(driver.called)

    @mock.patch('oslo_messaging.get_notification_transport')
    def test_conf_middleware_messaging_and_transport_set(self, m):
        """Test that the `transport_url` config attribute is considered."""
        transport_url = 'rabbit://me:passwd@host:5672/virtual_host'
        self.cfg.config(driver='messaging',
                        transport_url=transport_url,
                        group='audit_middleware_notifications')

        self.create_simple_middleware()
        time.sleep(1)
        self.assertTrue(m.called)
        # make sure first call kwarg 'url' is same as provided transport_url
        self.assertEqual(transport_url, m.call_args_list[0][1]['url'])
