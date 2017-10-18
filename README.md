# openstack-audit-middleware
Paste middleware to produce an CADF audit trail from OpenStack API calls.

It is a major redesign of the original _audit_ module within the [keystonemiddleware](https://github.com/openstack/keystonemiddleware). It has been invented to produce a more
verbose audit trail that can be consumed by auditors, end users and complex event processing infrastructures alike.

For that reason it does _not_ adhere to the existing OpenStack taxonomy for CADF. The biggest difference is that it populates
the _target_ part of the CADF event with the actual resource/object affected by the _action_. This is a prerequisite
to user friendly presentation of events, e.g. navigation from event to target objects. Previously, the essential information which target object has been affected by an audit-relevant action had been buried in the _requestPath_ attribute or was
not available at all.

For operators the difference is minor though. The integration of the new middleware in the OpenStack service works the same way with the only change being different mapping files and of course the new binaries.  

![Nova pipeline with audit middleware](./doc/source/images/audit.png)

The figure above shows the middleware in Nova's pipeline.

Enabling audit middleware
=========================
To enable auditing, _oslo.messaging_ should be installed. If not, the middleware
will write audit events to the application log instead. Auditing can be enabled for a specific
service by editing the services's `api-paste.ini` file to include the following
filter definition:

```
[filter:audit]
paste.filter_factory = auditmiddleware:filter_factory
audit_map_file = /etc/nova/api_audit_map.yaml
```

The filter must be included after Keystone middleware's *authtoken* filter so it can utilise request header variables set by it.

Below is an example using Nova's WSGI pipeline::

```
[composite:openstack_compute_api_v2]
use = call:nova.api.auth:pipeline_factory
noauth = faultwrap sizelimit noauth ratelimit osapi_compute_app_v2
keystone = faultwrap sizelimit authtoken keystonecontext ratelimit audit osapi_compute_app_v2
keystone_nolimit = faultwrap sizelimit authtoken keystonecontext audit osapi_compute_app_v2
```

Configure audit middleware
==========================
To properly audit api requests, the audit middleware requires a mapping
file. The mapping files describes how to generate CADF events out of REST API calls.
 
The location of the mapping file should be specified explicitly by adding the
path to the `audit_map_file` option of the filter definition::

```
[filter:audit]
paste.filter_factory = keystonemiddleware.audit:filter_factory
audit_map_file = /etc/nova/api_audit_map.yaml
```

For each supported OpenStack services, a mapping file named
_\<service\>\_api\_audit\_map.yaml_ is included in the _etc_ folder of this repo.

Additional options can be set::

```
[filter:audit]
paste.filter_factory = pycadf.middleware.audit:filter_factory
audit_map_file = /etc/nova/api_audit_map.yaml
service_name = test # opt to set HTTP_X_SERVICE_NAME environ variable
ignore_req_list = GET,POST # opt to ignore specific requests
```

Audit middleware can be configured to use its own exclusive notification driver
and topic(s) value. This can be useful when the service is already using oslo
messaging notifications and wants to use a different driver for auditing e.g.
service has existing notifications sent to queue via 'messagingv2' and wants to
send audit notifications to a log file via 'log' driver.

Example shown below:

```
[audit_middleware_notifications]
driver = log
```

When audit events are sent via 'messagingv2' or 'messaging', middleware can
specify a transport URL if its transport URL needs to be different from the
service's own messaging transport setting. Other Transport related settings are
read from oslo messaging sections defined in service configuration e.g.
'oslo_messaging_rabbit'.

Example shown below:
```
[audit_middleware_notifications]
driver = messagingv2
transport_url = rabbit://user2:passwd@host:5672/another_virtual_host
```

Customizing the CADF mapping rules
----------------------------------

The CADF mapping rules are essentially a model of resources. Due to REST principles, this model implies how the HTTP API
requests are formed. Additional hints are added to address exceptions to those principles and support custom values
for the CADF *action* attribute.

Example (Nova)::
```
  # default target endpoint type
  # should match the endpoint type defined in service catalog
  target_endpoint_type: public # retrieve service ID from this endpoint

  # service type as configured in the OpenStack catalog
  service_type: 'compute'
   
  # describe resources exposed by the REST API
  # URL paths follow one of the following patterns:
  # - /<resource>s: HTTP POST for create, GET for list
  # - /<resource>s/<resource-id>: HTTP GET for read, PUT for update, DELETE for remove
  # - /<resource>s/<resource-id>/<custom-action>: specified per resource
  # - /<resource>s/<resource-id>/<child-resource>: like parent
  # - /<resource>s/<resource-id>/<child-resource>/<child-resource-id>: like parent
  # - /<resource>s/<resource-id>/<child-resource-singleton>: singleton resource (e.g. attribute), no own ID
  resources:
      server: # resource name, placed first in the URL path (with an added "s"), followed by the ID
          # type_uri of the resource, defaults to <service-key>/<resource name>
          type_uri: compute/server
          # URL-endcoded actions, last part of the URL path, following the ID of the target (child-)resource
          # or "action" in which case the actual action is the first and only element of the JSON payload
          custom_actions:
              # <url-path-suffix>: <cadf-action>
              startup: start/startup
          # child resources, placed after the parent resource ID in the URL path
          children:
             migration:
                  # type_uri of the resource, defaults to <parent-type_uri>/<resource name>
                  type_uri: compute/server/migration
             os-server-password:
                  # this is an attribute, so there is only a single resource per parent
                  # that means no pluralization of the resource name in the URL and no ID
                  singleton: true
```
