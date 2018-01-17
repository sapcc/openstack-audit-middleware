# openstack-audit-middleware
[Paste middleware](https://pypi.python.org/pypi/Paste) to produce a [CADF](http://www.dmtf.org/sites/default/files/standards/documents/DSP0262_1.0.0.pdf) audit trail from OpenStack API calls. Currently the following OpenStack services are supported out-of-the-box today:

  * Nova
  * Neutron
  * Cinder

Additional APIs can be supported without major code changes through templates.

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

    [filter:audit]
    paste.filter_factory = auditmiddleware:filter_factory
    audit_map_file = /etc/nova/api_audit_map.yaml

The filter must be included after Keystone middleware's *authtoken* filter so it can utilise request header variables set by it.

Below is an example using Nova's WSGI pipeline::

    [composite:openstack_compute_api_v2]
    use = call:nova.api.auth:pipeline_factory
    noauth = faultwrap sizelimit noauth ratelimit osapi_compute_app_v2
    keystone = faultwrap sizelimit authtoken keystonecontext ratelimit audit osapi_compute_app_v2
    keystone_nolimit = faultwrap sizelimit authtoken keystonecontext audit osapi_compute_app_v2

Configure audit middleware
==========================

API Mapping
---------------

To properly audit api requests, the audit middleware requires a mapping
file. The mapping files describes how to generate CADF events out of REST API calls.

The location of the mapping file should be specified explicitly by adding the
path to the `audit_map_file` option of the filter definition::

    [filter:audit]
    paste.filter_factory = auditmiddleware:filter_factory
    audit_map_file = /etc/nova/api_audit_map.yaml

For each supported OpenStack services, a mapping file named
_\<service\>\_api\_audit\_map.yaml_ is included in the _etc_ folder of this repo.

Additional options can be set:

Certain types of HTTP requests can be ignored entirely. Typically GET and HEAD
requests should not cause the creation of an audit events due to sheer volume.

    # ignore any GET or HEAD requests
    ignore_req_list = GET, HEAD

Payload Recording
-----------------

The payload of the API response to a CRUD request can be attached to the event optionally. This will increase the size of the events, but brings a lot of value when it comes to diagnostics. Sensitive information can be filtered out using the `payloads` attribute of the resource mapping specification (see below).


    # turn on logging on request payloads
    record_payloads = True

Oslo Messaging
--------------

Audit middleware can be configured to use its own exclusive notification driver
and topic(s) value. This can be useful when the service is already using oslo
messaging notifications and wants to use a different driver for auditing e.g.
service has existing notifications sent to queue via 'messagingv2' and wants to
send audit notifications to a log file via 'log' driver.

Example shown below:

    [audit_middleware_notifications]
    driver = log

When audit events are sent via 'messagingv2' or 'messaging', middleware can
specify a transport URL if its transport URL needs to be different from the
service's own messaging transport setting. Other Transport related settings are
read from oslo messaging sections defined in service configuration e.g.
'oslo_messaging_rabbit'.

Example shown below:

    [audit_middleware_notifications]
    driver = messagingv2
    transport_url = rabbit://user2:passwd@host:5672/another_virtual_host

Statistics and Operational Metrics
----------------------------------

The middleware can emit statistics on emitted events using tagged _statsd_ metrics. This requires a DogStatsD compatible statsd service like the [Prometheus StatsD exporter](https://hub.docker.com/r/prom/statsd-exporter/).

    # turn on metrics
    metrics_enabled = True

The default StatsD host and port can be customized using environment variables:

    STATSD_HOST     the statsd hostname
    STATSD_PORT     the statsd portnumber

The following metrics and dimensions are supported

| Metric                           | Description      | Dimensions/Tags                                                  |
|----------------------------------|------------------|--------------------------------------------------------------------|
| openstack_audit_events     | Statistics on audit events per tenant. This includes not yet delivered ones. | action: CADF action ID, project_id: OpenStack project/domain ID, service: OpenStack service type, target_type: CADF type URI of the target resource, outcome: failed/success/unknown |
| openstack_audit_events_buffered | Events buffered in memory waiting for message queue to catch up | |
| openstack_audit_messaging_overflows | Number of lost events due to message queue latency or downtime | |
| openstack_audit_messaging_errors | Failed attempts to push to message queue, leading to events dumped into log files | |

Customizing the CADF mapping rules
==================================

The CADF mapping rules are essentially a model of resources. Due to REST principles, this model implies how the HTTP API requests are formed.

The path of the request specifies the resource that is the target of the request. It consists of a prefix and a resource path. The resource path is denoting the resource. The prefix is used for versioning and routing. Sometimes it is even used to specify the target project of an operation (e.g. in Cinder).

In the mapping file, the prefix is specified using a regular expression. In those cases where the prefix contains the target project id, the regular expression needs to capture the relevant part of the prefix using a _named_ match group called
_project\_id_

    prefix: '/v2.0/(?P<project_id>[0-9a-f\-]*)'

The resource path is a concatenation of resource names and IDs. URL paths follow one of the following patterns:

   - `/<resources>`: HTTP POST for create, GET for list
   - `/<resources>/<resource-id>`: HTTP GET for read, PUT for update, DELETE for remove
   - `/<resources>/<resource-id>/action`: POST to perform an action specified by the payload. The payload is expressed as `{<action>: {<parameter1>: <pvalue1>, ...}}`
   - `/<resources>/<resource-id>/<custom-action>`: perform a custom action specified in the mapping (otherwise this is interpreted as a field, see below)
   - `/<resources>/<resource-id>/<field>`: update a field of a resource
   - `/<resources>/<resource-id>/<child-resource>`: like top-level resource
   - `/<resources>/<resource-id>/<child-resource>/<child-resource-id>`: like top-level resource

For _singletons_, i.e. resources with only a single instance, the `<resource-id>` parts are omitted.

Additional hints are added to address exceptions to these design patterns.

Elements by Example
-------------------

The mapping file starts with general information on the service:
  - `service_type`: The type of service according to the CADF type taxonomy, i.e. the root of the type hierarchy. All resources of the service are added beneath that root.
  - `prefix`: The URL prefix used by the service. Some OpenStack services specify the target project/domain in the URL, others rely on the authorization scope or special parameters.

          # service type as configured in the OpenStack catalog
          service_type: compute
          # configure prefix, use the named match group 'project_id' to mark the tenant
          prefix: '/v2[0-9\.]*/(?P<project_id>[0-9a-f\-]*)'

This is followed by a description of the service's resource hierarchy.

The following defines a resource with the typeURI `compute/servers`.

         resources:
            servers:
                # type_uri: compute/servers (default)
                # el_type_uri: compute/server (default)
            custom_actions:
              startup: start/startup
            custom_attributes:
              # always attach the security_groups attribute value
              # which has type compute/server/security-groups
              security_groups: compute/server/security-groups

 It supports some custom actions and has attributes of special importance. The following attribute are used to describe these:

 * `custom_actions`: map REST action names to the CADF action taxonomy. Otherwise a default mapping `(create|update|delete|read|read/list)` is applied (default: `[]`)
 * `custom_attributes`: list attributes of special importance whose values should always be attached to the event; Assign a type URI, so they can be shown in UIs properly (default: [])

 This resource has a multitude of child resources nested. Some of them exist only once, others can exist several times. This is controlled by the following attribute:

  * `singleton`: `true` when only a single instance of a resource exists. Otherwise the resource is a _collection_, i.e. an ID needs to be specified for address individual resource instances in a URL (default: `false`)

 For some resources, the API design is not following the established naming patterns. Those exceptions can be modelled with the following settings:
 * `api_name`: resource name in the URL path (default: `<resource-name>`)
 * `type_uri`: type-URI of the resource, used in the target.typeURI attribute of the produced CADF event (default: `<parent-typeURI>/<resource-name>`)
 * `el_type_uri`: type-URI of the resource instances if the resource is not a singleton (default: `type_uri` omitting the last character)
 * `custom_id`: indicate which resource attribute contains the unique resource ID (default: `id`)
 * `custom_name`: indicate which resource attribute contains the resource readable name (default: `name`)
 * `type_name`: JSON name for the resource, used by API designs that wrap the resource attributes into a single top-level attribute (default: `api_name` without leading `os-` prefix resp. the original resource name)
 * `el_type_name`: JSON name of the resource instances (default: `type_name` omitting the last character)

            children:
              metadata:
                singleton: true
                # wrapped in a JSON element named "meta"
                type_name: meta
              migrations:
                # defaults are all fine for this resource
              interfaces:
                # for some reason Nova does not use plural for the os-interfaces of a server
                api_name: 'os-interface'
                # in JSON payloads the resource attributes are wrapped in an element called 'interfaceAttachment'
                type_name: interfaceAttachments
                # the unique ID of an os-interface is located in attribute 'port_id' (not 'id')
                custom_id: port_id

The configuration option to record request payloads needs some special consideration when sensitive or bulky information in involved:

* `payloads`: controls which attributes of the request payload may not be attached to the event (e.g. because they contain very sensitive information)
   - `enabled`: set to `false` to disable payload recording for this resource entirely (default: `true`)
   - `exclude`: exclude these payload attributes from the payload attachment (black-list approach, default: `[]`)
   - `include`: only include these payload attributes in the payload attachment(white-list approach, default: `all)

In out example this looks like this:

              ...
              os-server-password:
                singleton: true
                payloads:
                  # never record payloads for the os-server-password resource
                  enabled: False
        flavors:
          payloads:
            exclude:
              # filter lengthy fields with no real diagnostic value
              - description
              - links
