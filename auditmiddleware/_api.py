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

"""This package contains the logic for creating events from API requests."""

import collections
import os
import re

import six
import yaml
from oslo_log import log as logging
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import eventfactory
from pycadf import host
from pycadf import reason
from pycadf import resource
from pycadf.attachment import Attachment

from . import parsing_utils as utils

ResourceSpec = collections.namedtuple('ResourceSpec',
                                      ['type_name', 'el_type_name',
                                       'type_uri', 'el_type_uri', 'singleton',
                                       'id_field', 'name_field',
                                       'custom_actions', 'custom_attributes',
                                       'children', 'payloads'])

# default mappings from HTTP methods to CADF actions
# action suffixes for operations on custom keys (modelled as path suffixes)
_key_action_suffix_map = {taxonomy.ACTION_READ: '/get',
                          taxonomy.ACTION_UPDATE: '/set',
                          taxonomy.ACTION_CREATE: '/put',
                          taxonomy.ACTION_LIST: '/read/list',
                          taxonomy.ACTION_DELETE: '/unset'}

_method_action_map = {'GET': taxonomy.ACTION_READ,
                      'HEAD': taxonomy.ACTION_READ,
                      'PUT': taxonomy.ACTION_UPDATE,
                      'PATCH': taxonomy.ACTION_UPDATE,
                      'POST': taxonomy.ACTION_CREATE,
                      'DELETE': taxonomy.ACTION_DELETE}

TargetResource = collections.namedtuple('TargetResource',
                                        ['id', 'parent_id', 'spec'])

# matcher for UUIDs
_UUID_RE = re.compile("[0-9a-f-]+$")


class ConfigError(Exception):
    """Error raised when pyCADF fails to configure correctly."""

    pass


class OpenStackResource(resource.Resource):
    """Extended CADF resource class with custom fields for OpenStack scope."""

    def __init__(self, project_id=None, domain_id=None, **kwargs):
        """Initialize a new resource that has an OpenStack scope."""
        super(OpenStackResource, self).__init__(**kwargs)
        if project_id:
            self.project_id = project_id
        if domain_id:
            self.domain_id = domain_id

    def __getattr__(self, item):
        """Circumvent the magic attribute handling of pycadf here."""
        if item in ['project_id', 'domain_id']:
            return None
        else:
            return super(OpenStackResource, self).__getattribute__(item)


class OpenStackAuditMiddleware(object):
    """The actual middleware implementation, a filter for the paste pipe."""

    def __init__(self, cfg_file, payloads_enabled, metrics_enabled,
                 log=logging.getLogger(__name__)):
        """Configure to recognize and map known API paths."""
        self._log = log

        try:
            with open(cfg_file, 'r') as f:
                conf = yaml.safe_load(f)

            self._payloads_enabled = payloads_enabled
            self._service_type = conf['service_type']
            self._service_name = conf.get('service_name', self._service_type)
            self._service_id = utils._build_service_id(self._service_name)
            self._prefix_re = re.compile(conf['prefix'])
            # default_target_endpoint_type = conf.get('target_endpoint_type')
            # self._service_endpoints = conf.get('service_endpoints', {})
            self._resource_specs = self._build_audit_map(conf['resources'])

        except KeyError as err:
            raise ConfigError('Missing config property in %s: %s', cfg_file,
                              str(err))
        except (OSError, yaml.YAMLError) as err:
            raise ConfigError('Error opening config file %s: %s',
                              cfg_file, str(err))

        self._statsd = self._create_statsd_client() \
            if metrics_enabled else None

    def _create_statsd_client(self):
        """Create the statsd client (if datadog package is present)."""
        try:
            import datadog

            return datadog.dogstatsd.DogStatsd(
                host=os.getenv('STATSD_HOST', 'localhost'),
                port=int(os.getenv('STATSD_PORT', '8125')),
                namespace='openstack_audit',
                constant_tags=['service:{0}'.format(self._service_type)]
            )
        except ImportError:
            self._log.warning("Python datadog package not installed. No "
                              "openstack_audit_* metrics will be produced.")

    def _build_audit_map(self, res_dict, parent_type_uri=None):
        """Build the resourc hierarchy in a dictionary.

        The dictionary maps the resource name used in the REST API's URL
        path to the ResourceSpec descriptor. That descriptor contains all
        the information needed to produce the CADF events from HTTP requests.
        """
        result = {}

        for name, s in six.iteritems(res_dict):
            res_spec, rest_name = self._build_res_spec(name, parent_type_uri, s)

            # ensure that cust
            result[rest_name] = res_spec

        return result

    def _build_res_spec(self, name, parent_type_uri, spec=None):
        """Build the resource descriptor from and entry in the mapping file.

        Parameters:
            name: CADF name of the resource type
            parent_type_uri: type URI of the parent CADF resource type
                             (acting as prefix)
            spec: mapping entry from the config to be parsed
        """
        if not spec:
            spec = {}

        if parent_type_uri:
            pfx = parent_type_uri
        else:
            pfx = self._service_type
        # REST path segment normally equals resource name
        rest_name = spec.get('api_name', name)
        singleton = spec.get('singleton', False)
        type_name = spec.get('type_name')
        # derive the type name used for resource representations in JSON from
        # the REST name
        if not type_name:
            type_name = rest_name.replace('-', '_')
            if type_name.startswith('os_'):
                type_name = type_name[3:]
        type_uri = spec.get('type_uri', pfx + "/" + name)

        if not singleton:
            # derive the name of the individual resource instances (elements)
            # by omitting the last character of the resource name
            el_type_name = spec.get('el_type_name', type_name[:-1])
            el_type_uri = type_uri[:-1]
            childs_parent_type_uri = el_type_uri
        else:
            el_type_name = None
            el_type_uri = None
            childs_parent_type_uri = type_uri
        res_spec = ResourceSpec(type_name, el_type_name,
                                type_uri, el_type_uri, singleton,
                                spec.get('custom_id', 'id'),
                                spec.get('custom_name', 'name'),
                                utils.str_map(spec.get('custom_actions')),
                                utils.str_map(spec.get('custom_attributes')),
                                self._build_audit_map(
                                    spec.get('children', {}),
                                    childs_parent_type_uri),
                                utils.payloads_config(spec.get('payloads')))
        return res_spec, rest_name

    def create_events(self, request, response=None):
        """Build a CADF event from request and response."""
        # drop the endpoint's path prefix
        path, target_project = self._handle_url_prefix(request)
        if not path:
            self._log.info("ignoring request with path: %s",
                           request.path)
            return []

        # normalize url: remove trailing slash and .json suffix
        path_segments = utils.to_path_segments(path)
        # reverse to pop first elements first
        path_segments.reverse()
        target_config, suffix = self._map_path_to_resource(self._resource_specs, None, None, request, path_segments)

        action, key = self._get_action_and_key(target_config, request, suffix)
        if not action:
            self._log.info("ignoring request with path: %s; "
                           "because action was suppressed by config or not found", request.path)
            return []

        payloads_enabled = self._payloads_enabled and target_config.spec.payloads['enabled']
        relevant_response_json = utils.get_json_if(request.method[0] == 'P', response)
        bulk_operation_payloads = utils.find_bulk_targets(relevant_response_json, target_config.spec)
        attachable_request_body = utils.get_json_if(request.method[0] == 'P' and payloads_enabled, request)

        request_payloads, response_payloads = \
            utils.clean_or_unwrap(attachable_request_body, bulk_operation_payloads,
                                  relevant_response_json, target_config)

        targets = self._build_targets(key, response_payloads, target_config, target_project)

        events = [self._create_cadf_event(request, response, action, target) for target in targets]

        for event, payload in zip(events, response_payloads):
            utils.attach_custom_attributes(event, target_config.spec, payload)

        for event, payload in zip(events, request_payloads):
            utils.attach_payload(event, payload, target_config.spec)

        for event in events:
            if self._statsd:
                self._statsd.increment('events',
                                       tags=utils.make_tags(event))
        return events

    def _map_path_to_resource(
            self, res_spec, res_id, res_parent_id,
            request, segments):
        """Parse a request recursively and builds CADF events from it.

        This methods parses the URL path from left to right and maps it
        to the configured resource hierarchy. The res_spec resource tree is used to
        interpret the path segments properly, e.g. known when a path
        segment represents a resource name, an ID or an attribute name.

        Parameters:
            res_spec: resource tree constructed from the mapping file
            res_id: ID of the target resource
            res_parent_id: ID of the parent resource of the target resource
            request: incoming request to parse
            segments: Remaining URL path segments from left to right (reversed to pop() in order)
        """
        # Check if the end of path is reached and return configuration for target
        if not segments:
            # end of path reached, create the event
            return TargetResource(res_id, res_parent_id, res_spec), None

        token = segments.pop()

        if isinstance(res_spec, dict):
            # the resource tree node contains a dict => the token contains the top-level resource name
            # get sub_resource or create one for unexpected resource names
            res_spec = res_spec.get(token, None) or self.register_resource(None, token, res_spec)
            res_id, res_parent_id = None, None
            return self._map_path_to_resource(res_spec, res_id, res_parent_id, request, segments)

        elif isinstance(res_spec, ResourceSpec):
            # if the ID is set or it is a singleton, then the next token will
            # be an action or child
            child_res_spec = res_spec.children.get(token, None)
            if child_res_spec:
                # the ID is still the one of the parent (or its parent if
                # the direct parent is a singleton)
                res_parent_id = res_id or res_parent_id
                return self._map_path_to_resource(child_res_spec, None, res_parent_id, request, segments)
            elif _UUID_RE.match(token):
                # next up should be an ID (unless it is a known action)
                res_id = token
                return self._map_path_to_resource(res_spec, res_id, res_parent_id, request, segments)

            if segments:
                # unknown resource name
                # create resource spec on demand ...
                child_res_spec = self.register_resource(res_spec.el_type_uri, token, res_spec.children)
                return self._map_path_to_resource(child_res_spec, res_id, res_parent_id, request, segments)
            else:
                # last path segment --> token must be an action or a key
                return TargetResource(res_id, res_parent_id, res_spec), token

        self._log.warning(
            "Unexpected continuation of resource path after segment %s: %s",
            token, request.path)
        return None, None

    def register_resource(self, parent_type_uri, token, parent_resource):
        """Register an unknown resource to avoid missed events.

        The resulting events are a bit raw but contain enough
        information to understand what happened. This allows for
        incremental improvement.
        """
        self._log.warning("unknown resource: %s (created on demand)",
                          token)
        trimmed_res_name = token.replace('_', '-').replace('os-', '')
        trimmed_res_name = 'X' + trimmed_res_name
        res_dict = {'api_name': token}
        sub_res_spec, _ = self._build_res_spec(trimmed_res_name,
                                               parent_type_uri,
                                               res_dict)
        parent_resource[token] = sub_res_spec

        return sub_res_spec

    def _create_cadf_event(self, request, response, action, target):

        initiator = self._build_initiator(request)
        observer = self._build_observer()

        if response:
            if 200 <= response.status_int < 400:
                action_result = taxonomy.OUTCOME_SUCCESS
            else:
                action_result = taxonomy.OUTCOME_FAILURE

            event_reason = reason.Reason(
                reasonType='HTTP', reasonCode=str(response.status_int))
        else:
            action_result = taxonomy.UNKNOWN
            event_reason = None

        event = eventfactory.EventFactory().new_event(
            eventType=cadftype.EVENTTYPE_ACTIVITY,
            outcome=action_result,
            action=action,
            initiator=initiator,
            observer=observer,
            reason=event_reason,
            target=target)
        event.requestPath = request.path_qs

        # add reporter step again?
        # event.add_reporterstep(
        #    reporterstep.Reporterstep(
        #        role=cadftype.REPORTER_ROLE_MODIFIER,
        #        reporter=resource.Resource(id='observer'),
        #        reporterTime=timestamp.get_utc_now()))

        return event

    @staticmethod
    def _build_initiator(request):
        return OpenStackResource(
            project_id=request.environ.get('HTTP_X_PROJECT_ID', taxonomy.UNKNOWN),
            domain_id=request.environ.get('HTTP_X_DOMAIN_ID', taxonomy.UNKNOWN),
            typeURI=taxonomy.ACCOUNT_USER,
            id=request.environ.get('HTTP_X_USER_ID', taxonomy.UNKNOWN),
            name=request.environ.get('HTTP_X_USER_NAME', taxonomy.UNKNOWN),
            domain=request.environ.get('HTTP_X_USER_DOMAIN_NAME',
                                       taxonomy.UNKNOWN),
            host=host.Host(address=request.client_addr,
                           agent=request.user_agent))

    def _build_targets(self, key, response_payloads, target_config, target_project):
        return [self._build_target_from_payload(target_project, target_config, payload, key)
                for payload in response_payloads] or \
               [self._build_default_target(key, target_project, target_config)]

    def _build_default_target(self, key, project, target_config):
        if target_config.id or target_config.parent_id:
            name = None
        else:
            name = self._service_name

        rid = utils.make_uuid(target_config.id or target_config.parent_id or self._service_id)
        type_uri = target_config.spec.el_type_uri \
            if target_config.id else target_config.spec.type_uri
        target = OpenStackResource(project_id=project, id=rid,
                                   typeURI=type_uri, name=name)

        # provide name of custom keys in attachment of target
        if key:
            target.add_attachment(Attachment(typeURI="xs:string",
                                             content=key, name='key'))

        return target

    def _build_target_from_payload(self, target_project, target_config: TargetResource,
                                   payload=None, key=None):
        """Build the event's target element from  the payload."""
        project_id = target_project
        name = None
        res_id, res_parent_id, res_spec = target_config
        # fetch IDs from payload if possible
        if isinstance(payload, dict):
            name = payload.get(res_spec.name_field)
            # some custom ID fields are no UUIDs/strings but just integers
            if not res_id:
                custom_id = payload.get(res_spec.id_field, '')
                res_id = str(custom_id) if custom_id else None

            project_id = (target_project or payload.get('project_id', '') or
                          payload.get('tenant_id', ''))
        else:
            self._log.warning(
                "mapping error, malformed resource payload %s (no dict) "
                "in operation on resource: %s",
                payload,
                res_spec)

        rid = utils.make_uuid(res_id or res_parent_id or taxonomy.UNKNOWN)
        type_uri = res_spec.el_type_uri if res_id else res_spec.type_uri
        target = OpenStackResource(project_id=project_id, id=rid,
                                   typeURI=type_uri, name=name)
        # provide name of custom keys in attachment of target
        if key:
            target.add_attachment(Attachment(typeURI="xs:string",
                                             content=key, name='key'))

        return target

    def _build_observer(self):
        """Build the observer element representing this middleware."""
        observer = resource.Resource(typeURI='service/' + self._service_type,
                                     id=self._service_id,
                                     name=self._service_name)

        return observer

    def _get_action_and_key(self, target_config,
                            request, suffix):
        """Determine the CADF action and key from the request.

        Depending on already known information, this function will
        either use the HTTP method or the payload to determine
        which CADF action to report.

        Parameters:
            target_config: target resource descriptor
            request: the request
            suffix: the last path component (already known)
        """
        if suffix is None:
            return get_action_from_method(request.method, target_config.spec,
                                          target_config.id), None

        if suffix == 'action':
            action = self._get_action_from_payload(request, target_config.spec,
                                                   target_config.id)
            return action, None

        return self._get_action_and_key_from_path_suffix(
            suffix, request.method, target_config.spec,
            target_config.id)

    @staticmethod
    def _get_action_and_key_from_path_suffix(path_suffix, method,
                                             res_spec, res_id):
        """Determine the CADF action from the URL path."""
        rest_action = path_suffix
        # check for individual mapping of action
        action = res_spec.custom_actions.get(rest_action, None)
        if action:
            return action, None

        # check for generic mapping
        rule = method + ':*'
        if rule in res_spec.custom_actions:
            action = res_spec.custom_actions.get(rule)
            if action:
                return action.replace('*', rest_action), None
            else:
                # action suppressed by intention
                return None, None

        # no action mapped to suffix => custom key
        action = get_action_from_method(method, res_spec, res_id)
        action += _key_action_suffix_map[action]
        return action, path_suffix

    def _get_action_from_payload(self, request, res_spec, res_id):
        """Determine the CADF action from the payload."""
        payload = utils.get_json_if(True, request)
        if payload:
            rest_action = next(iter(payload))
            # check for individual mapping of action
            action = res_spec.custom_actions.get(rest_action, None)
            if action:
                return action

            # apply generic default mapping rule here
            return get_action_from_method(
                request.method, res_spec, res_id) + '/' + rest_action
        else:
            self._log.warning("/action URL without payload: %s",
                              request.path)
            return None

    def _handle_url_prefix(self, request):
        """Process the prefix from the URL path and remove it.

        :param request: incoming request
        :return: URL request path without the leading prefix or None if prefix
        was missing and optional target tenant or None
        """
        g = self._prefix_re.match(request.path)
        if g:
            path = request.path[g.end():]
            project = g.groupdict().get('project_id', '')
            return path, project
        return None, None


def get_action_from_method(method, res_spec, res_id):
    """Determine the CADF action from the HTTP method."""
    if method == 'POST':
        if res_id or res_spec.singleton:
            return taxonomy.ACTION_UPDATE

        return taxonomy.ACTION_CREATE
    elif method == 'GET' or method == 'HEAD':
        if res_id or res_spec.singleton:
            return taxonomy.ACTION_READ
        return taxonomy.ACTION_LIST
    elif method == "PATCH":
        return taxonomy.ACTION_UPDATE

    return _method_action_map[method]
