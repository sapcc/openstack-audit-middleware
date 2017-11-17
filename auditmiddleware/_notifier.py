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

import os
import random
import sys
import Queue as queue

import time

from oslo_config import cfg

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


class _MessagingNotifier(object):
    def __init__(self, notifier, log):
        self._log = log
        self._notifier = notifier
        self._seq_errors = 0
        self._wait_until = time.time()
        self._queue = queue.Queue(10000)

    def __del__(self):
        if not self._queue.empty():
            self.flush_buffer()

    def notify(self, context, payload):
        if time.time() < self._wait_until:
            self.enqueue_notification(payload, context)
            return

        if self._queue.qsize() > 0:
            self.flush_buffer()

        try:
            self._notifier.info(context, "audit.cadf", payload)
            self._seq_errors = 0
        except Exception as err:
            self.enqueue_notification(payload, context)
            sleep = random.randrange(0, min(900, 60 * 2 ** self._seq_errors))
            self._wait_until = time.time() + self.backoff_delay
            self.seq_errors += 1

    def enqueue_notification(self, payload, context):
        try:
            self._queue.put_nowait((payload, context))
        except queue.Full:
            self._log.warning("Audit events could not be delivered ("
                              "buffer full). Payload follows ...")
            self.log_event(context, payload)

    def log_event(self, context, payload):
        self._log.info('Event type: audit.cadf, Context: %(context)s, '
                       'Payload: %(payload)s',
                       {'context': context, 'event_type': 'audit.cadf',
                        'payload': payload})

    def flush_buffer(self):
        self._log.info("Flushing %d messages from buffer")
        try:
            while True:
                payload, context = self._queue.get_nowait()
                self._notifier.info(context, "audit.cadf", payload)
                self._seq_errors = 0
        except queue.Empty:
            # ignore
            pass
        except Exception as e:
            # flush to log
            try:
                while True:
                    self.log_event(context, payload)
                    payload, context = self._queue.get_nowait()
            except queue.Empty:
                pass


def create_notifier(conf, log):
    if oslo_messaging:
        transport = oslo_messaging.get_notification_transport(
            conf.oslo_conf_obj,
            url=conf.get('transport_url'),)
        notifier = oslo_messaging.Notifier(
            transport,
            os.path.basename(sys.argv[0]),
            driver=conf.get('driver'),
            topics=conf.get('topics'),
            retry=0)


        return _MessagingNotifier(notifier, log)

    else:
        return _LogNotifier(log)
