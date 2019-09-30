"""Regression tests for the audit-middleware.

Currently only contains unit tests, shying away from the complexity of
testing full integrations with OpenStack services and RabbitMQ. Due to
the inherent modularity of paste pipeline filters, unit testing is quite
sufficient here as long as the integration tests for the OpenStack
services are run together with this middleware.
"""