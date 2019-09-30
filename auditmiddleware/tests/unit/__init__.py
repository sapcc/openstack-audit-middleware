"""Unit tests for the audit-middleware.

The tests here cover the following aspects:
    - proper integration into the paste pipeline of OpenStack services  (test_audit_middleware.py)
    - completeness and correctness of CADF events created from OpenStack API calls (test_audit_filter.py)
    - correct interaction with oslo messaging (test_audit_oslo_messaging.py)
    - sustained availability when the message broker is down and fallback to logging output (test_logging_notifier.py)
    - validity of the mapping files for the various OpenStack services (test_mappings.py)
"""