#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Unit tests for the audit-middleware.

The tests here cover the following aspects:
    - proper integration into the paste pipeline of OpenStack services
      (test_audit_middleware.py)
    - completeness and correctness of CADF events created from OpenStack API
      calls (test_audit_filter.py)
    - correct interaction with oslo messaging (test_audit_oslo_messaging.py)
    - sustained availability when the message broker is down and fallback to
      logging output (test_logging_notifier.py)
    - validity of the mapping files for the various OpenStack services
      (test_mappings.py)
"""
