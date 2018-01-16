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

import collections
import hashlib
import json
import os
import re
import socket
import uuid

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

ResourceSpec = collections.namedtuple('ResourceSpec',
                                      ['type_name', 'el_type_name',
                                       'type_uri', 'el_type_uri', 'singleton',
                                       'id_field', 'name_field',
                                       'custom_actions', 'custom_attributes',
                                       'children', 'payloads'])

method_action_map = {'GET': taxonomy.ACTION_READ,
                     'HEAD': taxonomy.ACTION_READ,
                     'PUT': taxonomy.ACTION_UPDATE,
                     'PATCH': taxonomy.ACTION_UPDATE, 'POST':
                         taxonomy.ACTION_CREATE,
                     'DELETE': taxonomy.ACTION_DELETE}
action_suffix_map = {taxonomy.ACTION_READ: '/get',
                     taxonomy.ACTION_UPDATE: '/set',
                     taxonomy.ACTION_CREATE: '/put',
                     taxonomy.ACTION_DELETE: '/unset'}

# matcher for UUIDs
_UUID_RE = re.compile("[0-9a-f\-]+$")


def _make_uuid(s):
    if s.isdigit():
        return str(uuid.UUID(int=int(s)))
    else:
        return s


class ConfigError(Exception):
    """Error raised when pyCADF fails to configure correctly."""

    pass


class OpenStackResource(resource.Resource):
    def __init__(self, project_id=None, domain_id=None, **kwargs):
        super(OpenStackResource, self).__init__(**kwargs)
        if project_id:
            self.project_id = project_id
        if domain_id:
            self.domain_id = domain_id

    def __getattr__(self, item):
        if item in ['project_id', 'domain_id']:
            return None
        else:
            return super(self, OpenStackResource).__getattribute__(self, item)


def str_map(param):
    if not param:
        return {}

    for k, v in six.iteritems(param):
        if not isinstance(k, str) or not isinstance(v, str):
            raise Exception("Invalid config entry %s:%s (not strings)",
                            k, v)

    return param


def payloads_map(param):
    if not param:
        return {'enabled': True}

    param['enabled'] = bool(param.get('enabled', True))

    incl = param.get('include')
    if incl:
        param['include'] = [x.strip() for x in incl.split(',')]
    excl = param.get('exclude')
    if excl:
        param['exclude'] = [x.strip() for x in excl.split(',')]

    return param


def _make_tags(ev):
    return [
        'project_id:{0}'.format(ev.target.project_id or
                                ev.initiator.project_id or
                                ev.initiator.domain_id),
        'target_type_uri:{0}'.format(ev.target.typeURI),
        'action:{0}'.format(ev.action),
        'outcome:{0}'.format(ev.outcome)]


class OpenStackAuditMiddleware(object):
    def __init__(self, cfg_file, payloads_enabled, metrics_enabled,
                 log=logging.getLogger(__name__)):
        """Configure to recognize and map known api paths."""
        self._log = log

        try:
            conf = yaml.safe_load(open(cfg_file, 'r'))

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
        result = {}

        for name, s in six.iteritems(res_dict):
            if not s:
                spec = {}
            else:
                spec = s

            if parent_type_uri:
                pfx = parent_type_uri
            else:
                pfx = self._service_type

            rest_name = spec.get('api_name', name)
            singleton = spec.get('singleton', False)
            type_name = spec.get('type_name', rest_name.replace('-', '_'))
            type_uri = spec.get('type_uri', pfx + "/" + name)
            el_type_name = None
            el_type_uri = None
            childs_parent_type_uri = None
            if not singleton:
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
                                    payloads_map(spec.get('payloads')))

            # ensure that cust
            result[rest_name] = res_spec

        return result

    def create_events(self, request, response=None):
        # drop the endpoint's path prefix
        path, target_project = self._strip_url_prefix(request)
        if not path:
            self._log.info("ignoring request with path: %s",
                           request.path)
            return None

        path = path[:-1] if path.endswith('/') else path
        path = path[:-5] if path.endswith('.json') else path
        return self._build_events(target_project, self._resource_specs,
                                  None, None, request, response, path, 0)

    def _build_events(self, target_project, res_spec, res_id, res_parent_id,
                      request, response, path, cursor=0):
        """ Parse a resource request recursively and build CADF events from it

        :param res_tree:
        :param path:
        :param cursor:
        :return: an array of built events
        """

        # Check if the end of path is reached and event can be created finally
        if cursor == -1:
            # end of path reached, create the event
            return self._create_events(target_project, res_id,
                                       res_parent_id,
                                       res_spec, request, response)

        # Find next path segment (skip leading / with +1)
        next_pos = path.find('/', cursor + 1)
        token = None
        if next_pos != -1:
            # that means there are more path segments
            token = path[cursor + 1:next_pos]
        elif (cursor + 1) < len(path):
            token = path[cursor + 1:]

        # handle the current token
        if isinstance(res_spec, dict):
            # the node contains a dict => handle token as resource name
            res_spec = res_spec.get(token)
            if res_spec is None:
                # no such name, ignore/filter the resource
                self._log.debug("unknown resource: %s", token)

                return None

            return self._build_events(target_project, res_spec, None, None,
                                      request,
                                      response,
                                      path, next_pos)
        elif isinstance(res_spec, ResourceSpec):
            # if the ID is set or it is a singleton
            # next up is an action or child
            if res_id or res_spec.singleton or token in res_spec.children:
                child_res = res_spec.children.get(token)
                if child_res:
                    # the ID is still the one of the parent
                    return self._build_events(target_project, child_res, None,
                                              res_id or res_parent_id, request,
                                              response, path, next_pos)
            elif _UUID_RE.match(token):
                # next up should be an ID (unless it is a known action)
                return self._build_events(target_project, res_spec, token,
                                          res_parent_id, request, response,
                                          path, next_pos)

            if next_pos == -1:
                # this must be an action or a key
                return self._create_events(target_project, res_id,
                                           res_parent_id, res_spec, request,
                                           response, token)

        self._log.warning(
            "Unexpected continuation of resource path after segment %s: %s",
            token, request.path)
        return None

    def _create_events(self, target_project, res_id,
                       res_parent_id,
                       res_spec, request, response, suffix=None):
        events = []

        # check for update operations
        if request.method[0] == 'P' and response \
                and response.content_length > 0 \
                and response.content_type == "application/json":
            res_payload = response.json

            # check for bulk-operation
            if not res_spec.singleton and \
                    isinstance(res_payload.get(res_spec.type_name), list):
                # payloads contain an attribute named like the resource
                # which contains a list of items
                res_pl = res_payload[res_spec.type_name]
                req_pl = None
                if self._payloads_enabled and res_spec.payloads['enabled']:
                    req_pl = iter(request.json.get(res_spec.type_name))

                for subpayload in res_pl:
                    ev = self._create_event_from_payload(target_project,
                                                         res_spec,
                                                         res_id,
                                                         res_parent_id,
                                                         request, response,
                                                         subpayload, suffix)
                    pl = req_pl.next() if req_pl else None
                    if ev:
                        if pl:
                            self._attach_payload(ev, pl, res_spec)
                        events.append(ev)

            else:
                # remove possible wrapper elements
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

                # attach payload if configured
                if self._payloads_enabled and res_spec.payloads['enabled']:
                    req_pl = request.json
                    # remove possible wrapper elements
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
                    and res_spec.payloads['enabled']:
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
        self._log.debug("create event from payload:\n%s", subpayload)
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
                if not isinstance(value, basestring):
                    value = json.dumps(value, separators=(',', ':'))
                attach_val = Attachment(typeURI=typeURI, content=value,
                                        name=attr)
                ev.add_attachment(attach_val)

        return ev

    def _create_cadf_event(self, project, res_spec, res_id, res_parent_id,
                           request, response, suffix):
        action = self._get_action(res_spec, res_id, request, suffix)
        key = None
        if not action:
            # ignored unknown actions
            if suffix == 'action':
                return None

            # suffix must be a key
            key = suffix
            # determine action from method (never None)
            action = self._get_action(res_spec, res_id, request, None)
            action += action_suffix_map[action]

        project_id = request.environ.get('HTTP_X_PROJECT_ID')
        domain_id = request.environ.get('HTTP_X_DOMAIN_ID')
        initiator = OpenStackResource(
            project_id=project_id, domain_id=domain_id,
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

        observer = self._create_observer_resource(request)

        event = eventfactory.EventFactory().new_event(
            eventType=cadftype.EVENTTYPE_ACTIVITY,
            outcome=action_result,
            action=action,
            initiator=initiator,
            observer=observer,
            reason=event_reason,
            target=target)
        event.requestPath = request.path_qs

        #
        if key and request.method[0] == 'P' and self._payloads_enabled and \
                res_spec.payloads['enabled']:
            req_pl = request.json
            # remove possible wrapper elements
            req_pl = req_pl.get(res_spec.el_type_name, req_pl)
            self._attach_payload(event, req_pl, res_spec)

        # TODO add reporter step again?
        # event.add_reporterstep(
        #    reporterstep.Reporterstep(
        #        role=cadftype.REPORTER_ROLE_MODIFIER,
        #        reporter=resource.Resource(id='observer'),
        #        reporterTime=timestamp.get_utc_now()))

        return event

    def _attach_payload(self, event, payload, res_spec):
        incl = res_spec.payloads.get('include')
        excl = res_spec.payloads.get('exclude')
        res_payload = {}
        if excl:
            res_payload = payload
            # remove possible wrapper elements
            for k in excl:
                if k in res_payload:
                    del res_payload[k]
        elif incl:
            for k in incl:
                v = payload.get(k)
                if v:
                    res_payload[k] = v
        else:
            res_payload = payload

        attach_val = Attachment(typeURI="mime:application/json",
                                content=json.dumps(res_payload,
                                                   separators=(',', ':')),
                                name='payload')

        event.add_attachment(attach_val)

    def _create_target_resource(self, target_project, res_spec, res_id,
                                res_parent_id=None, payload=None, key=None):
        """ builds a target resource from payload
        """
        project_id = target_project
        rid = res_id
        name = None

        # fetch IDs from payload if possible
        if payload:
            name = payload.get(res_spec.name_field)
            rid = rid or payload.get(res_spec.id_field)

            project_id = (target_project or payload.get('project_id') or
                          payload.get('tenant_id'))

        type_uri = res_spec.el_type_uri if rid else res_spec.type_uri
        rid = _make_uuid(rid or res_parent_id or taxonomy.UNKNOWN)
        target = OpenStackResource(project_id=project_id, id=rid,
                                   typeURI=type_uri, name=name)

        if key:
            target.add_attachment(Attachment(typeURI="xs:string",
                                             content=key, name='key'))

        return target

    def _create_observer_resource(self, req):
        """Build target resource."""
        observer = resource.Resource(typeURI='service/' + self._service_type,
                                     id=self._service_id,
                                     name=self._service_name)

        return observer

    def _get_action(self, res_spec, res_id, request, suffix):
        """Given a resource spec, a request and a path suffix, deduct
        the correct CADF action.
        """
        method = request.method
        if suffix is None:
            return self._map_method_to_action(method, res_spec, res_id)

        return self._map_action_suffix(res_spec, suffix, method,
                                       res_id, request)

    def _map_method_to_action(self, method, res_spec, res_id):
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

        return method_action_map[method]

    def _map_action_suffix(self, res_spec, action_suffix, method, res_id,
                           request):
        rest_action = ''
        if action_suffix == 'action':
            try:
                payload = request.json
                if payload:
                    rest_action = next(iter(payload))
                    # check for individual mapping of action
                    action = res_spec.custom_actions.get(rest_action)
                    if not action:
                        return self._map_method_to_action(
                            method, res_spec, res_id) + '/' + rest_action
                else:
                    self._log.warning("/action URL without payload: %s",
                                      request.path)
                    return None
            except ValueError:
                self._log.warning(
                    "unexpected empty action payload for path: %s",
                    request.path)
                return None
        else:
            rest_action = action_suffix

        # check for individual mapping of action
        action = res_spec.custom_actions.get(rest_action)
        if action is not None:
            return action

        # check for generic mapping
        action = res_spec.custom_actions.get(method + ':*')
        if action is not None and action is not '':
            return action.replace('*', rest_action)

        # no action mapped to suffix
        self._log.debug("unknown action: %s", rest_action)
        return None

    @staticmethod
    def _build_service_id(name):
        md5_hash = hashlib.md5(name.encode('utf-8'))  # nosec
        ns = uuid.UUID(md5_hash.hexdigest())
        return str(uuid.uuid5(ns, socket.getfqdn()))

    def _strip_url_prefix(self, request):
        """ Removes the prefix from the URL paths
        :param req: incoming request
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
