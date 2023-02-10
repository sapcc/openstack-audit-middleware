# openstack-audit-middleware
[Paste middleware](https://pypi.python.org/pypi/Paste) to produce a [CADF](http://www.dmtf.org/sites/default/files/standards/documents/DSP0262_1.0.0.pdf) audit trail from OpenStack API calls. Currently the following OpenStack services are supported out-of-the-box today:

  * Nova
  * Neutron
  * Cinder
  * Designate
  * Manila
  * Glance
  * Barbican
  * Ironic
  * Octavia

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

Embedding
=========
To enable auditing, _oslo.messaging_ should be installed. If not, the middleware
will write audit events to the application log instead.

Auditing is enabled by editing the services's `api-paste.ini` file to include the following
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

Configuration
=============

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

The oslo messaging configuration for the audit middleware is at the same place as
service's oslo messaging configuration: the service configuration file (e.g. `neutron.conf`)

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
| openstack_audit_events  | Statistics on audit events per tenant. This includes not yet delivered ones. | action: CADF action ID, project_id: OpenStack project/domain ID, service: OpenStack service type, target_type: CADF type URI of the target resource, outcome: failed/success/unknown |
| openstack_audit_events_backlog | Events buffered in memory waiting for message queue to catch up | |
| openstack_audit_messaging_overflows | Number of lost events due to message queue latency or downtime | |
| openstack_audit_messaging_errors | Failed attempts to push to message queue, leading to events dumped into log files | |

Mapping Rules
=============

The creation of audit events is driven by so called _mapping rules_. The CADF mapping rules are essentially a model of resources. Using OpenStack API design patterns, this model implies how the HTTP API requests are formed.

The path of an HTTP request specifies the resource that is the target of the request. It consists of a prefix and a resource path. The resource path is denoting the resource. The prefix is used for versioning and routing. Sometimes it is even used to specify the target project of an operation (e.g. in Cinder).

In the mapping file, the prefix is specified using a regular expression. In those cases where the prefix contains the target project id, the regular expression needs to capture the relevant part of the prefix using a _named_ match group called
_project\_id_

    prefix: '/v2.0/(?P<project_id>[0-9a-f\-]*)'

The resource path is a concatenation of resource names and IDs. URL paths follow one of the following patterns:

   - `/<resources>`: HTTP POST for create, GET for list
   - `/<resources>/<resource-id>`: HTTP GET for read, PUT for update, DELETE for remove
   - `/<resources>/<resource-id>/action`: POST to perform an action specified by the payload. The payload is expressed as `{<action>: {<parameter1>: <pvalue1>, ...}}`
   - `/<resources>/<resource-id>/<custom-action>`: perform a custom action specified in the mapping (otherwise this is interpreted as a key, see below)
   - `/<resources>/<resource-id>/<key>`: update a key of a resource
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

In addition to the basic resource actions implied by the HTTP _method_, OpenStack services can expose custom actions that go beyond CRUD. Two ways how to encoded action names in the HTTP request are common:
  
  * *payload-encoded*: the last component of the URL path is the action name ([example](https://developer.openstack.org/api-ref/shared-file-system/#id382))
  * *path-encoded*: the last component of the URL path is `action` and the payload contains the action name as the first JSON element ([example](https://developer.openstack.org/api-ref/shared-file-system/#grant-access])
  
Usually all custom actions should be listed in the mapping because otherwise the last path component will be taken as a custom _key_ of the resource or ignored right-away:

 * `custom_actions`: map custom action names to the CADF action taxonomy (default: `[]`).
 
 The mapping of actions is complex: For payload-encoded actions a default-mapping will be applied which determines the primary action (e.g. `update`) from the HTTP method and adds the action name from the payload (e.g. `update/myaction`).

 For path-encoded actions you can reach a similar behaviour with a generic rule of the form `"<method>:*": "<action>"` (e.g. `"POST:*": "read"`). You can refer to the actual action name in the path via `*` (e.g. `"POST:*": "update/*"`). If the right side of the rule is `null, the `entire request will be suppressed, so that no event is emitted (e.g. `"POST:*": null`).

 If there is no rule matching the path suffix, it will be interpreted as a _key_, not as an action. That means that the action will be determined from the HTTP method only and an attachment with the name `key` and the name of the key as `content` will be added to the event.

Attributes of special importance can be added to every update-like event by specifying _custom attributes_:

 * `custom_attributes`: list attributes of special importance whose values should always be attached to the event; Assign a type URI, so they can be shown in UIs properly (default: [])


A singleton resource is a api url call that will always lead to only one resource. Some resources exist only once,
i.e. they only have a single _instance_ and thus no unique ID.  This is controlled by the following attribute:

  * `singleton`: `true` when only a single instance of a resource exists. Otherwise the resource is a _collection_, i.e. an ID needs to be specified for address individual resource instances in a URL (default: `false`)

For some resources, some API designs do not follow the common OpenStack naming patterns. Those exceptions can be modelled with the following settings:
 * `api_name`: resource name in the URL path (default: `<resource-name>`); must be unique
 * `type_uri`: type-URI of the resource, used in the target.typeURI attribute of the produced CADF event (default: `<parent-typeURI>/<resource-name>`)
 * `el_type_uri`: type-URI of the resource instances (default: `type_uri` omitting the last character); not applicable to singletons
 * `custom_id`: indicate which resource attribute contains the unique resource ID (default: `id`)
 * `custom_name`: indicate which resource attribute contains the resource readable name (default: `name`)
 * `type_name`: JSON name for the resource, used by API designs that wrap the resource attributes into a single top-level attribute (default: `api_name` without leading `os-` prefix resp. the original resource name, but with `-` replaced by `_`)
 * `el_type_name`: JSON name of the resource instances (default: `type_name` omitting the last character)

Resources can be nested, meaning that a resource is part of another resource. Nesting is used to model various design patterns:

  * _composition_: a resource is really part of another resource, so that e.g. the resource is deleted when its parent is deleted.
  * _grouping_: a _singleton_ resource is used to group related resources or _custom fields_.

        children:
          metadata:
            # collection of fields/keys
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
   - `include`: only include these payload attributes in the payload attachment(white-list approach, default: all)

In our example this looks like this:

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

Undeclared Resources
--------------------

Resources that are not declared in the mapping file will be reported as _unknown_ in the operational logs.  Still the middleware tries to create events for them based on heuristics. They can be recognized by the `X` prefix in the resource name.

When those X-resources show up, the mapping file should be extended with an appropriate resource definition. The reason is that the heuristics to discover and map undeclared resources are not covering all kinds of requests. There are ambiguities. 

Developing Audit Middleware
===========================

Contributing
------------

This project is open for external contributions. The issue list shows what is planned for upcoming releases.

Pull-requests are welcome as long as you follow a few rules:

* Ensure that the middleware cannot degrade availabilty (no crashes, no deadlocks, no synchronous remote calls)
* Do not degrade performance
* Include unit tests for new or modified code
* Pass the static code checks
* Keep the architecture intact, don't add shortcuts, layers, ...

## Software Design

The purpose of this middleware is to create audit records from API calls. 

Each record describes a user or system activity following the 5W1H principle:
* who: which user?
* what: which action? which parameters?
* where: on which target resource?
* when: what timestamp?
* why: which service URL?
* how: with what outcome (outcome, HTTP response code)

This information is gathered from the URL path and the exchanged payloads which may contain important information like resource IDs or names. Discovering that information based on the hints in the mapping file is what most of the code is about.

Complexity comes from:
* different styles of encoding actions and payloads
* _create_ calls, where the target resource ID needs to be fetched from the result payload
* mass vs. single operations

Components/Packages

* api: Implementation of actual pipeline filter
* notifier: Implementation of the asynchronous event push to the oslo bus
* tests: unit and component tests
