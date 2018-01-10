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

import Queue as queue
import os
import sys
from threading import Thread

try:
    import oslo_messaging
except ImportError:
    oslo_messaging = None


class _LogNotifier(object):
    def __init__(self, log):
        self._log = log

    def notify(self, context, payload):
        self._log.info('Event type: audit.cadf, Context: %(context)s, '
                       'Payload: %(payload)s',
                       {'context': context, 'event_type': 'audit.cadf',
                        'payload': payload})


class _MessagingNotifier(Thread):
    def __init__(self, notifier, log, mem_queue_size):
        super(_MessagingNotifier, self).__init__(
            name='async auditmiddleware notifications')
        self._log = log
        self._notifier = notifier
        self._queue_capacity = mem_queue_size
        self._queue = queue.Queue(mem_queue_size)

    def notify(self, context, payload):
        self.enqueue_notification(payload, context)

    def enqueue_notification(self, payload, context):
        try:
            self._log.debug("enqueue event: %s", payload.get("id"))
            self._queue.put((payload, context), timeout=1)
            sz = self._queue.qsize()
            u = sz * 100 / self._queue_capacity
            if sz > 1 and u >= 10 and u % 10 == 0:
                self._log.debug("backlog: queue size reached %d items ("
                                "capacity: %d items)", sz,
                                self._queue_capacity)
                if u >= 90:
                    self._log.warn("backlog: queue size reached %d items ("
                                   "capacity: %d items)", sz,
                                   self._queue_capacity)
                elif u >= 50:
                    self._log.info("backlog: queue size reached %d items ("
                                   "capacity: %d items)", sz,
                                   self._queue_capacity)
        except queue.Full:
            self._log.error("Audit events could not be delivered ("
                            "buffer full). Payload follows ...")
            self.flush_to_log()
            self.log_event(context, payload)

    def run(self):
        while True:
            try:
                payload, context = self._queue.get()
                self._notifier.info(context, "audit.cadf", payload)
                self._log.debug("Push event: %s", payload.get("id"))
            except queue.Empty:
                # ignore
                pass
            except:  # noqa
                # switch to log output in case of errors
                self._log.error("Cannot push audit events to message queue: "
                                "%s", str(sys.exc_info()[0]))
                self.log_event(context, payload)
                self.flush_to_log()

    def log_event(self, context, payload):
        self._log.info('Event type: audit.cadf, Context: %(context)s, '
                       'Payload: %(payload)s',
                       {'context': context, 'event_type': 'audit.cadf',
                        'payload': payload})

    def flush_to_log(self):
        # flush all queued messages to log, starting with context, payload
        try:
            while True:
                payload, context = self._queue.get_nowait()
                self.log_event(context, payload)
        except queue.Empty:
            pass


def create_notifier(conf, log):
    if oslo_messaging:
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
        notf = _MessagingNotifier(notifier, log, mqs)
        notf.setDaemon(True)
        notf.start()
        return notf

    else:
        return _LogNotifier(log)
