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

"""Provides a oslo-messaging, log-based, and raw-AMQP messaging connector."""

import json
import os
import queue
import sys
from threading import Thread
from urllib.parse import urlparse

try:
    import oslo_messaging
except ImportError:
    oslo_messaging = None

try:
    import kombu
except ImportError:
    kombu = None


class _LogNotifier(object):
    """A notifier that dumps the event content into the log.

    The log entries have severity INFO, so logging needs to be configured
    to that level to see the contents.
    """

    def __init__(self, log):
        self._log = log

    def notify(self, context, payload):
        self._log.info(json.dumps(payload))


class _MessagingNotifier(Thread):
    """A notifier that publishes the events to the oslo bus.

    This is the default implementation. It will use any messaging
    provider configured in *oslo messaging*. Instead of pushing
    incoming events to the message bus synchronously, the events
    will be appended to a bounded queue. An asynchronous worker
    will fetch the events from there and deliver them to the
    oslo bus.

    When the queue's capacity is exhausted, all undelivered
    events will be flushed to the logs. This way we ensure that
    problems with the messaging system do not degrade availability
    of the service.

    This has implications though: Buffered events will be lost if the
    process is killed hardly. As can be observed through the
    openstack_audit_messaging_backlog metric, the number of buffered
    events usually hovers between 0 and 1 since event delivery is
    much faster than request processing.
    """

    def __init__(self, notifier, log, mem_queue_size, metrics_enabled):
        """Initialize the notifier.

        Parameters:
            notifier: oslo messaging notifier
            log: log sink
            mem_queue_size: capacity of the event buffer
            metrics_enabled: whether statsd metrics shall be emitted
        """
        super(_MessagingNotifier, self).__init__(
            name='async auditmiddleware notifications')
        self._log = log
        self._notifier = notifier
        self._queue_capacity = mem_queue_size
        self._queue = queue.Queue(mem_queue_size)

        self._statsd = self._create_statsd_client() \
            if metrics_enabled else None

    def _create_statsd_client(self):
        """Create a statsd client."""
        try:
            import datadog

            return datadog.dogstatsd.DogStatsd(
                host=os.getenv('STATSD_HOST', 'localhost'),
                port=int(os.getenv('STATSD_PORT', '8125')),
                namespace='openstack_audit_messaging')
        except ImportError:
            self._log.warning("Python datadog package not installed. No "
                              "openstack_audit_* metrics will be produced.")
            return None

    def notify(self, context, payload):
        self.enqueue_notification(payload, context)

    def enqueue_notification(self, payload, context):
        try:
            self._log.debug("enqueue event: %s", payload.get("id"))
            self._queue.put((payload, context), timeout=1)
            sz = self._queue.qsize()
            if self._statsd and sz >= 1:
                # push metric to show that queue lags
                self._statsd.gauge('backlog', sz)
        except queue.Full:
            self._log.error("Audit events could not be delivered ("
                            "buffer full). Payload follows ...")
            if self._statsd:
                self._statsd.increment('overflows', self._queue.qsize())
            self.flush_to_log()
            self.log_event(context, payload)

    def run(self):
        # reset sporadic metrics
        if self._statsd:
            self._statsd.gauge('backlog', 0)
            self._statsd.increment('errors', 0)
            self._statsd.increment('overflows', 0)
        while True:
            try:
                sz = self._queue.qsize()
                payload, context = self._queue.get()
                self._notifier.info(context, "audit.cadf", payload)
                # push metric to show that backlog moved back to 0..1
                # i.e. message queue caught up
                if self._statsd and sz == 1:
                    self._statsd.gauge('backlog', 0)
                self._log.debug("Push event: %s", payload.get("id"))
            except queue.Empty:
                # ignore
                pass
            except:  # noqa
                # switch to log output in case of errors
                self._log.error("Cannot push audit events to message queue: "
                                "%s", str(sys.exc_info()[0]))
                self.log_event(context, payload)
                if self._statsd:
                    self._statsd.increment('errors')
                self.flush_to_log()

    def log_event(self, context, payload):
        self._log.info('Event type: audit.cadf, Context: %(context)s, '
                       'Payload: %(payload)s',
                       {'context': context, 'event_type': 'audit.cadf',
                        'payload': payload})

    def flush_to_log(self):
        """Flush all queued messages to log, starting with context, payload."""
        try:
            while True:
                payload, context = self._queue.get_nowait()
                self.log_event(context, payload)
        except queue.Empty:
            pass


class _RawAmqpNotifier(Thread):
    """Publishes CADF events as plain JSON directly to an AMQP exchange.

    Unlike _MessagingNotifier, this bypasses oslo_messaging entirely so the
    message body on the wire is just the CADF dict serialised as JSON — no
    oslo envelope, no double-wrapped payload field.

    Wire format:
        routing_key : <topic>.info   (e.g. "notifications.info")
        content_type: application/json
        body        : json.dumps(cadf_event)
    """

    def __init__(self, transport_url, topics, log, mem_queue_size,
                 metrics_enabled):
        super(_RawAmqpNotifier, self).__init__(
            name='async auditmiddleware raw-amqp notifications')
        self._log = log
        self._transport_url = transport_url
        self._topics = topics or ['notifications']
        self._queue_capacity = mem_queue_size
        self._queue = queue.Queue(mem_queue_size)
        self._statsd = None
        if metrics_enabled:
            try:
                import datadog
                self._statsd = datadog.dogstatsd.DogStatsd(
                    host=os.getenv('STATSD_HOST', 'localhost'),
                    port=int(os.getenv('STATSD_PORT', '8125')),
                    namespace='openstack_audit_messaging')
            except ImportError:
                self._log.warning("Python datadog package not installed. "
                                  "No openstack_audit_* metrics will be "
                                  "produced.")

    def notify(self, context, payload):
        try:
            self._queue.put((payload, context), timeout=1)
        except queue.Full:
            self._log.error("Audit events could not be delivered (buffer "
                            "full). Payload follows ...")
            self._flush_to_log()
            self._log_event(context, payload)

    def _log_event(self, context, payload):
        self._log.info('Event type: audit.cadf, Context: %(context)s, '
                       'Payload: %(payload)s',
                       {'context': context, 'event_type': 'audit.cadf',
                        'payload': payload})

    def _flush_to_log(self):
        try:
            while True:
                payload, context = self._queue.get_nowait()
                self._log_event(context, payload)
        except queue.Empty:
            pass

    def _make_connection(self):
        url = self._transport_url
        if url and url.startswith('rabbit://'):
            url = 'amqp://' + url[len('rabbit://'):]
        return kombu.Connection(url)

    def run(self):
        while True:
            try:
                payload, context = self._queue.get()
                self._publish(payload)
                self._log.debug("Push event (raw): %s", payload.get("id"))
            except Exception:
                self._log.error("Cannot push raw audit event to AMQP: %s",
                                str(sys.exc_info()[0]))
                if 'payload' in dir():
                    self._log_event(context, payload)

    def _publish(self, payload):
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        with self._make_connection() as conn:
            conn.ensure_connection()
            for topic in self._topics:
                routing_key = '%s.info' % topic
                exchange = kombu.Exchange(
                    topic, type='topic', durable=False, auto_delete=False)
                with kombu.Producer(conn.channel(), exchange=exchange,
                                    routing_key=routing_key) as producer:
                    producer.publish(
                        body,
                        content_type='application/json',
                        content_encoding='utf-8',
                    )


def create_notifier(conf, log, metrics_enabled):
    """Create a new notifier."""
    driver = getattr(conf.audit_middleware_notifications, 'driver', None)

    if driver == 'raw_amqp':
        if kombu is None:
            raise ImportError(
                "kombu is required for driver=raw_amqp but is not installed")
        transport_url = conf.audit_middleware_notifications.transport_url
        topics = conf.audit_middleware_notifications.topics or ['notifications']
        mqs = conf.audit_middleware_notifications.mem_queue_size or 10000
        notf = _RawAmqpNotifier(transport_url, topics, log, mqs,
                                metrics_enabled)
        notf.daemon = True
        notf.start()
        return notf

    if oslo_messaging and conf.audit_middleware_notifications.get(
        'use_oslo_messaging'):
        transport = oslo_messaging.get_notification_transport(
            conf,
            url=conf.audit_middleware_notifications.transport_url)
        notifier = oslo_messaging.Notifier(
            transport,
            os.path.basename(sys.argv[0]),
            driver=conf.audit_middleware_notifications.driver,
            topics=conf.audit_middleware_notifications.topics)

        mqs = conf.audit_middleware_notifications.mem_queue_size
        if mqs is None:
            mqs = 10000
        notf = _MessagingNotifier(notifier, log, mqs, metrics_enabled)
        notf.daemon = True
        notf.start()
        return notf

    else:
        return _LogNotifier(log)
