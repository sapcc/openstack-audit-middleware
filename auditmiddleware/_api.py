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
import hashlib
import json
import os
import re
import six
import socket
import uuid
import yaml

from oslo_log import log as logging
from pycadf.attachment import Attachment
from pycadf import cadftaxonomy as taxonomy
from pycadf import cadftype
from pycadf import eventfactory
from pycadf import host
from pycadf import reason
from pycadf import resource

ResourceSpec = collections.namedtuple('ResourceSpec',
                                      ['type_name', 'el_type_name',
                                       'type_uri', 'el_type_uri', 'singleton',
                                       'id_field', 'name_field',
                                       'custom_actions', 'custom_attributes',
                                       'children', 'payloads'])

# default mappings from HTTP methods to CADF actions
_method_action_map = {'GET': taxonomy.ACTION_READ,
                      'HEAD': taxonomy.ACTION_READ,
                      'PUT': taxonomy.ACTION_UPDATE,
                      'PATCH': taxonomy.ACTION_UPDATE, 'POST':
                          taxonomy.ACTION_CREATE,
                      'DELETE': taxonomy.ACTION_DELETE}
# action suffixes for operations on custom keys (modelled as path suffixes)
_key_action_suffix_map = {taxonomy.ACTION_READ: '/get',
                          taxonomy.ACTION_UPDATE: '/set',
                          taxonomy.ACTION_CREATE: '/put',
                          taxonomy.ACTION_DELETE: '/unset'}

# matcher for UUIDs
_UUID_RE = re.compile("[0-9a-f-]+$")


def _make_uuid(s):
    if s.isdigit():
        return str(uuid.UUID(int=int(s)))
    else:
        return s


class ConfigError(Exception):
    """Error raised when pyCADF fails to configure correctly."""

    pass


class OpenStackResource(resource.Resource):
    """Extended CADF resource class with custom fields for OpenStack scope."""

    def __init__(self, project_id=None, domain_id=None,
                 application_credential_id=None, **kwargs):
        """Initialize a new resource that has an OpenStack scope."""
        super(OpenStackResource, self).__init__(**kwargs)
        if project_id:
            self.project_id = project_id
        if domain_id:
            self.domain_id = domain_id
        if application_credential_id:
            self.application_credential_id = application_credential_id

    def __getattr__(self, item):
        """Circumvent the magic attribute handling of pycadf here."""
        if item in ['project_id', 'domain_id', 'application_credential_id']:
            return None
        else:
            return super(OpenStackResource, self).__getattribute__(item)


def str_map(param):
    """Ensure that a dictionary contains only string values."""
    if not param:
        return {}

    for k, v in six.iteritems(param):
        if v is not None and (not isinstance(k, six.string_types) or
                              not isinstance(v, six.string_types)):
            raise Exception("Invalid config entry %s:%s (not strings)",
                            k, v)

    return param


def payloads_config(param):
    """Create a valid payloads config from the config file contents."""
    if not param:
        return {'enabled': True}

    payloads_config = param.copy()
    payloads_config['enabled'] = bool(param.get('enabled', True))

    return payloads_config


def _make_tags(ev):
    """Build statsd metric tags from CADF event."""
    return [
        'project_id:{0}'.format(ev.target.project_id or
                                ev.initiator.project_id or
                                ev.initiator.domain_id),
        'target_type_uri:{0}'.format(ev.target.typeURI),
        'action:{0}'.format(ev.action),
        'outcome:{0}'.format(ev.outcome)]


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
            self._service_id = self._build_service_id(self._service_name)
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
            res_spec, rest_name = self._build_res_spec(name, parent_type_uri,
                                                       s)

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
        el_type_name = None
        el_type_uri = None
        childs_parent_type_uri = None
        if not singleton:
            # derive the name of the individual resource instances (elements)
            # by omitting the last character of the resource name
            el_type_name = spec.get('el_type_name', type_name[:-1])
            el_type_uri = type_uri[:-1]
            childs_parent_type_uri = el_type_uri
        else:
            childs_parent_type_uri = type_uri
        res_spec = ResourceSpec(type_name, el_type_name,
                                type_uri, el_type_uri, singleton,
                                spec.get('custom_id', 'id'),
                                spec.get('custom_name', 'name'),
                                str_map(spec.get('custom_actions')),
                                str_map(spec.get('custom_attributes')),
                                self._build_audit_map(
                                    spec.get('children', {}),
                                    childs_parent_type_uri),
                                payloads_config(spec.get('payloads')))
        return res_spec, rest_name

    def create_events(self, request, response=None):
        """Build a CADF event from request and response."""
        # drop the endpoint's path prefix
        path, target_project = self._handle_url_prefix(request)
        if not path:
            self._log.info("ignoring request with path: %s",
                           request.path)
            return None

        # normalize url: remove trailing slash and .json suffix
        path = path[:-1] if path.endswith('/') else path
        path = path[:-5] if path.endswith('.json') else path
        return self._build_events(target_project, self._resource_specs,
                                  None, None, request, response, path, 0)

    def _build_events(self, target_project, res_spec, res_id, res_parent_id,
                      request, response, path, cursor=0):
        """Parse a request recursively and builds CADF events from it.

        This methods parses the URL path from left to right and builds the
        resource hierarchy from it. The res_spec resource tree is used to
        interpret the path segments properly, e.g. known when a path
        segment represents a resource name, an ID or an attribute name.

        Parameters:
            target_project: target project ID if specified in the path
            res_spec: resource tree constructed from the mapping file
            res_id: ID of the target resource
            parent_res_id: ID of the parent resource of the target resource
            request: incoming request to parse
            response: resulting response to parse (e.g. to obtain results,
                      just created resource IDs)
            path: URL path being parsed
            cursor: current position in the path as it is parsed
        """
        # Check if the end of path is reached and event can be created finally
        if cursor == -1:
            # end of path reached, create the event
            return self._create_events(target_project, res_id,
                                       res_parent_id,
                                       res_spec, request, response)

        # Find next path segment (skip leading / with +1)
        next_pos = path.find('/', cursor + 1)
        # token = scanned token (NOT keystone token)
        token = None
        if next_pos != -1:
            # that means there are more path segments
            token = path[cursor + 1:next_pos]
        elif (cursor + 1) < len(path):
            # last path segment found, not more '/' right of it
            token = path[cursor + 1:]

        # handle the current token
        if isinstance(res_spec, dict):
            # the resource tree node contains a dict => the token contains the
            # top-level resource name
            sub_res_spec = res_spec.get(token)
            if sub_res_spec is None:
                # create resource spec on demand using defaults
                sub_res_spec = self.register_resource(None, token)
                res_spec[token] = sub_res_spec

            return self._build_events(target_project, sub_res_spec, None, None,
                                      request,
                                      response,
                                      path, next_pos)
        elif isinstance(res_spec, ResourceSpec):
            # if the ID is set or it is a singleton, then the next token will
            # be an action or child
            if res_id or res_spec.singleton or token in res_spec.children:
                child_res = res_spec.children.get(token)
                if child_res:
                    # the ID is still the one of the parent (or its parent if
                    # the direct parent is a singleton)
                    return self._build_events(target_project, child_res, None,
                                              res_id or res_parent_id, request,
                                              response, path, next_pos)
            elif _UUID_RE.match(token):
                # next up should be an ID (unless it is a known action)
                return self._build_events(target_project, res_spec, token,
                                          res_parent_id, request, response,
                                          path, next_pos)

            if next_pos == -1:
                # last path segment --> token must be an action or a key
                return self._create_events(target_project, res_id,
                                           res_parent_id, res_spec, request,
                                           response, token)
            else:
                # unknown resource name
                # create resource spec on demand ...
                res_spec.children[token] = self.register_resource(
                    res_spec.el_type_uri,
                    token)

                # ... then repeat same call with res_spec now existing
                return self._build_events(target_project, res_spec, res_id,
                                          res_parent_id, request, response,
                                          path, cursor)

        self._log.warning(
            "Unexpected continuation of resource path after segment %s: %s",
            token, request.path)
        return None

    def register_resource(self, parent_type_uri, token):
        """Register an unknown resource to avoid missed events.

        The resulting events are a bit raw but contain enough
        information to understand what happened. This allows for
        incremental improvement.
        """
        self._log.warning("unknown resource: %s (created on demand)",
                          token)
        res_name = token.replace('_', '-')
        if res_name.startswith('os-'):
            res_name = res_name[3:]
        res_name = 'X' + res_name
        res_dict = {'api_name': token}
        sub_res_spec, _ = self._build_res_spec(res_name,
                                               parent_type_uri,
                                               res_dict)

        return sub_res_spec

    def _create_events(self, target_project, res_id,
                       res_parent_id,
                       res_spec, request, response, suffix=None):
        events = []

        # check for update operations (POST, PUT, PATCH)
        if request.method[0] == 'P' and response \
                and response.content_length > 0 \
                and response.content_type == "application/json":
            res_payload = response.json

            # check for bulk-operation
            if not res_spec.singleton and res_payload and \
                    isinstance(res_payload.get(res_spec.type_name), list):
                # payloads contain an attribute named like the resource
                # which contains a list of items
                res_pl = res_payload[res_spec.type_name]
                req_pl = None
                if self._payloads_enabled and res_spec.payloads['enabled'] \
                        and request.content_type == 'application/json':
                    req_pl = iter(request.json.get(res_spec.type_name))

                # create one event per item
                for subpayload in res_pl:
                    ev = self._create_event_from_payload(target_project,
                                                         res_spec,
                                                         res_id,
                                                         res_parent_id,
                                                         request, response,
                                                         subpayload, suffix)
                    pl = next(req_pl) if req_pl else None
                    if ev:
                        if pl:
                            # attach payload if requested
                            self._attach_payload(ev, pl, res_spec)
                        events.append(ev)

            else:
                # remove possible wrapper elements
                if res_payload:
                    res_payload = res_payload.get(res_spec.el_type_name,
                                                  res_payload)

                event = self._create_event_from_payload(target_project,
                                                        res_spec,
                                                        res_id,
                                                        res_parent_id,
                                                        request, response,
                                                        res_payload, suffix)

                if not event:
                    return []

                # attach payload if requested
                if self._payloads_enabled and res_spec.payloads['enabled'] \
                   and request.content_length > 0 \
                   and request.content_type == "application/json":
                    req_pl = request.json
                    # remove possible wrapper elements
                    if isinstance(req_pl, dict):
                        req_pl = req_pl.get(res_spec.el_type_name, req_pl)
                    self._attach_payload(event, req_pl, res_spec)

                events.append(event)
        else:
            event = self._create_cadf_event(target_project, res_spec, res_id,
                                            res_parent_id,
                                            request, response, suffix)
            if not event:
                return []

            if event and request.method[0] == 'P' \
                    and self._payloads_enabled \
                    and res_spec.payloads['enabled'] \
                    and request.content_type == 'application/json':
                self._attach_payload(event, request.json, res_spec)

            events = [event]

        for ev in events:
            if self._statsd:
                self._statsd.increment('events',
                                       tags=_make_tags(ev))

        return events

    def _create_event_from_payload(self, target_project, res_spec, res_id,
                                   res_parent_id, request, response,
                                   subpayload, suffix=None):
        self._log.debug("create event from payload: %s",
                        self._clean_payload(subpayload, res_spec))
        ev = self._create_cadf_event(target_project, res_spec, res_id,
                                     res_parent_id, request,
                                     response, suffix)
        if not ev:
            return None

        ev.target = self._create_target_resource(target_project, res_spec,
                                                 res_id, res_parent_id,
                                                 subpayload)

        # extract custom attributes from the payload
        for attr, typeURI in six.iteritems(res_spec.custom_attributes):
            value = subpayload.get(attr)
            if value:
                if not isinstance(value, six.string_types):
                    value = json.dumps(value, separators=(',', ':'))
                attach_val = Attachment(typeURI=typeURI, content=value,
                                        name=attr)
                ev.add_attachment(attach_val)

        return ev

    def _create_cadf_event(self, project, res_spec, res_id, res_parent_id,
                           request, response, suffix):

        action, key = self._get_action_and_key(res_spec, res_id, request,
                                               suffix)
        if not action:
            return None

        project_id = request.environ.get('HTTP_X_PROJECT_ID')
        # If project_id is undefined, look for another variable. This is
        # added specific to catching delete events from Neutron
        if project_id is None:
            adhoc_attrs = request.environ.get('webob.adhoc_attrs', {})
            context = adhoc_attrs.get('context', {})
            original_resources = context.get('original_resources', [])
            if original_resources and isinstance(original_resources, list):
                first_resource = original_resources[0]
                if isinstance(first_resource, dict):
                    project_id = first_resource.get('project_id')

        domain_id = request.environ.get('HTTP_X_DOMAIN_ID')
        application_credential_id = None
        token_info = request.environ.get('keystone.token_info')
        if token_info:
            application_credential = token_info['token'].get(
                'application_credential')
            if application_credential:
                application_credential_id = application_credential['id']

        initiator = OpenStackResource(
            project_id=project_id, domain_id=domain_id,
            application_credential_id=application_credential_id,
            typeURI=taxonomy.ACCOUNT_USER,
            id=request.environ.get('HTTP_X_USER_ID', taxonomy.UNKNOWN),
            name=request.environ.get('HTTP_X_USER_NAME', taxonomy.UNKNOWN),
            domain=request.environ.get('HTTP_X_USER_DOMAIN_NAME',
                                       taxonomy.UNKNOWN),
            host=host.Host(address=request.client_addr,
                           agent=request.user_agent))

        action_result = None
        event_reason = None
        if response:
            if 200 <= response.status_int < 400:
                action_result = taxonomy.OUTCOME_SUCCESS
            else:
                action_result = taxonomy.OUTCOME_FAILURE

            event_reason = reason.Reason(
                reasonType='HTTP', reasonCode=str(response.status_int))
        else:
            action_result = taxonomy.UNKNOWN

        target = None
        if res_id or res_parent_id:
            target = self._create_target_resource(project, res_spec, res_id,
                                                  res_parent_id, key=key)
        else:
            target = self._create_target_resource(project, res_spec,
                                                  None, self._service_id,
                                                  key=key)
            target.name = self._service_name

        observer = self._create_observer_resource()

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
    def _clean_payload(payload, res_spec):
        """Clean request payload of sensitive info."""
        incl = res_spec.payloads.get('include')
        excl = res_spec.payloads.get('exclude')
        res_payload = {}
        if excl and isinstance(payload, dict):
            # make a copy so we do not change the original request
            res_payload = payload.copy()
            # remove possible wrapper elements
            for k in excl:
                if k in res_payload:
                    del res_payload[k]
        elif incl and isinstance(payload, dict):
            for k in incl:
                v = payload.get(k)
                if v:
                    res_payload[k] = v
        else:
            res_payload = payload

        return res_payload

    @staticmethod
    def _attach_payload(event, payload, res_spec):
        """Attach request payload to event."""
        res_payload = OpenStackAuditMiddleware._clean_payload(
            payload, res_spec)

        attach_val = Attachment(typeURI="mime:application/json",
                                content=json.dumps(res_payload,
                                                   separators=(',', ':')),
                                name='payload')

        event.add_attachment(attach_val)

    def _create_target_resource(self, target_project, res_spec, res_id,
                                res_parent_id=None, payload=None, key=None):
        """Build the event's target element from  the payload."""
        project_id = target_project
        rid = res_id
        name = None
        # fetch IDs from payload if possible
        if payload:
            if isinstance(payload, dict):
                name = payload.get(res_spec.name_field)
                # some custom ID fields are no UUIDs/strings but just integers
                if not rid:
                    custom_id = payload.get(res_spec.id_field)
                    rid = str(custom_id) if custom_id else None

                project_id = (target_project or payload.get('project_id') or
                              payload.get('tenant_id'))
            else:
                project_id = target_project
                self._log.warning(
                    "mapping error, malformed resource payload %s (no dict) "
                    "in bulk operation on resource: %s",
                    payload,
                    res_spec)

        type_uri = res_spec.el_type_uri if rid else res_spec.type_uri
        rid = _make_uuid(rid or res_parent_id or taxonomy.UNKNOWN)
        target = OpenStackResource(project_id=project_id, id=rid,
                                   typeURI=type_uri, name=name)

        # provide name of custom keys in attachment of target
        if key:
            target.add_attachment(Attachment(typeURI="xs:string",
                                             content=key, name='key'))

        return target

    def _create_observer_resource(self):
        """Build the observer element representing this middleware."""
        observer = resource.Resource(typeURI='service/' + self._service_type,
                                     id=self._service_id,
                                     name=self._service_name)

        return observer

    def _get_action_and_key(self, res_spec, res_id, request, suffix):
        """Determine the CADF action and key from the request.

        Depending on already known information, this function will
        either use the HTTP method or the payload to determine
        which CADF action to report.

        Parameters:
            res_spec: target resource descriptor
            request: the request
            suffix: the last path component (already known)
        """
        if suffix is None:
            return self._get_action_from_method(request.method, res_spec,
                                                res_id), None

        if suffix == 'action':
            action = self._get_action_from_payload(request, res_spec, res_id)
            return action, None

        return self._get_action_and_key_from_path_suffix(
            suffix, request.method, res_spec, res_id)

    @staticmethod
    def _get_action_from_method(method, res_spec, res_id):
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

    def _get_action_and_key_from_path_suffix(self, path_suffix, method,
                                             res_spec, res_id):
        """Determine the CADF action from the URL path."""
        rest_action = path_suffix
        # check for individual mapping of action
        action = res_spec.custom_actions.get(rest_action)
        if action is not None:
            return action, None

        # check for generic mapping
        rule = method + ':*'
        if rule in res_spec.custom_actions:
            action = res_spec.custom_actions.get(rule)
            if action is not None:
                return action.replace('*', rest_action), None
            else:
                # action suppressed by intention
                return None, None

        # no action mapped to suffix => custom key
        action = self._get_action_from_method(method, res_spec, res_id)
        action += _key_action_suffix_map[action]
        return action, path_suffix

    def _get_action_from_payload(self, request, res_spec, res_id):
        """Determine the CADF action from the payload."""
        try:
            payload = request.json
            if payload:
                rest_action = next(iter(payload))
                # check for individual mapping of action
                action = res_spec.custom_actions.get(rest_action)
                if action is not None:
                    return action

                # apply generic default mapping rule here
                return self._get_action_from_method(
                    request.method, res_spec, res_id) + '/' + rest_action
            else:
                self._log.warning("/action URL without payload: %s",
                                  request.path)
                return None
        except ValueError:
            self._log.warning("unexpected empty action payload for path: %s",
                              request.path)
            return None

    @staticmethod
    def _build_service_id(name):
        """Invent stable UUID for the service itself."""
        md5_hash = hashlib.md5(name.encode('utf-8'))  # nosec
        ns = uuid.UUID(md5_hash.hexdigest())
        return str(uuid.uuid5(ns, socket.getfqdn()))

    def _handle_url_prefix(self, request):
        """Process the prefix from the URL path and remove it.

        :param request: incoming request
        :return: URL request path without the leading prefix or None if prefix
        was missing and optional target tenant or None
        """
        g = self._prefix_re.match(request.path)
        if g:
            path = request.path[g.end():]
            project = None
            try:
                # project needs to be specified in a named group in order to
                #  be detected
                project = g.group('project_id')
            except IndexError:
                project = None

            return path, project

        return None, None
