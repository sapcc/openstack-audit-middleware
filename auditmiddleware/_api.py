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
import re
import socket
import uuid

import yaml
from oslo_log import log as logging
from pycadf import cadftaxonomy as taxonomy, endpoint
from pycadf import cadftype
from pycadf import eventfactory
from pycadf import host
from pycadf import reason
from pycadf import resource

ResourceSpec = collections.namedtuple('ResourceSpec',
                                      ['type_uri', 'el_type_uri', 'singleton',
                                       'id_field', 'custom_actions',
                                       'children'])

method_taxonomy_map = {'GET': taxonomy.ACTION_READ,
                       'HEAD': taxonomy.ACTION_READ, 'PUT':
                           taxonomy.ACTION_UPDATE,
                       'PATCH': taxonomy.ACTION_UPDATE, 'POST':
                           taxonomy.ACTION_CREATE,
                       'DELETE': taxonomy.ACTION_DELETE}


def _make_uuid(s):
    if s.isdigit():
        return str(uuid.UUID(int=int(s)))
    else:
        return s


class ConfigError(Exception):
    """Error raised when pyCADF fails to configure correctly."""

    pass


class ClientResource(resource.Resource):
    def __init__(self, project_id=None, **kwargs):
        super(ClientResource, self).__init__(**kwargs)
        self.project_id = project_id


class OpenStackAuditMiddleware(object):
    def __init__(self, cfg_file, log=logging.getLogger(__name__)):
        """Configure to recognize and map known api paths."""
        self._log = log

        try:
            conf = yaml.safe_load(open(cfg_file, 'r'))

            self._service_type = conf['service_type']
            self._service_name = conf.get('service_name', self._service_type)
            self._service_id = self._build_service_id(self._service_name)
            self._prefix_re = re.compile(conf['prefix'])
            # default_target_endpoint_type = conf.get('target_endpoint_type')
            # self._service_endpoints = conf.get('service_endpoints', {})
            self._resource_specs = self._parse_resources(conf['resources'])

        except KeyError as err:
            raise ConfigError('Missing config property in %s: %s', cfg_file,
                              str(err))
        except (OSError, yaml.YAMLError) as err:
            raise ConfigError('Error opening config file %s: %s',
                              cfg_file, str(err))

    def _parse_resources(self, res_dict, parent_type_uri=None):
        result = {}

        for name, s in res_dict.iteritems():
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
            type_uri = spec.get('type_uri', pfx + "/" + name)
            el_type_uri = None
            childs_parent_type_uri = None
            if not singleton:
                el_type_uri = type_uri[:-1]
                childs_parent_type_uri = el_type_uri
            else:
                childs_parent_type_uri = type_uri

            spec = ResourceSpec(type_uri, el_type_uri,
                                singleton,
                                spec.get('custom_id', 'id'),
                                spec.get('custom_actions', {}),
                                self._parse_resources(spec.get('children', {}),
                                                      childs_parent_type_uri))
            result[rest_name] = spec

        return result

    def _build_event(self, res_spec, res_id, res_parent_id, request, response,
                     path, cursor=0):
        """ Parse a resource item

        :param res_tree:
        :param path:
        :param cursor:
        :return: the event
        """

        # Check if the end of path is reached and event can be created finally
        if cursor == -1:
            # end of path reached, create the event
            return self._create_crud_event(res_id, res_parent_id,
                                           res_spec, request, response)

        # Find next path segment (skip leading / with +1)
        next_pos = path.find('/', cursor + 1)
        token = None
        if next_pos != -1:
            # that means there are more path segments
            token = path[cursor + 1:next_pos]
        else:
            token = path[cursor + 1:]

        # handle the current token
        if isinstance(res_spec, dict):
            # the node contains a dict => handle token as resource name
            res_spec = res_spec.get(token)
            if res_spec is None:
                # no such name, ignore/filter the resource
                return None

            return self._build_event(res_spec, None, None, request, response,
                                     path, next_pos)
        elif isinstance(res_spec, ResourceSpec):
            # if the ID is set or it is a singleton
            # next up is an action or child
            if res_id or res_spec.singleton:
                child_res = res_spec.children.get(token)
                if child_res:
                    # the ID is still the one of the parent
                    return self._build_event(child_res, None,
                                             res_id or res_parent_id, request,
                                             response, path, next_pos)
            elif res_spec.custom_actions and token not in \
                    res_spec.custom_actions:
                # next up should be an ID (unless it is a known action)
                return self._build_event(res_spec, token, res_parent_id,
                                         request, response, path, next_pos)

            if next_pos == -1:
                # this must be an action
                return self._create_event(res_spec, res_id, res_parent_id,
                                          request, response, token)

        self._log.warning(
            "Unexpected continuation of resource path after segment %s: %s",
            token, request.path)
        return None

    def _create_crud_event(self, res_id, res_parent_id, res_spec, request,
                           response):

        event = self._create_event(res_spec, res_id, res_parent_id,
                                   request, response, None)
        # on create, requests the ID is available only after the response
        if not res_id and event.action.startswith(taxonomy.ACTION_CREATE)\
           and response and response.content_length > 0 \
           and response.content_type == "application/json":
            payload = response.json
            name = payload.get('name')
            if name is None:
                name = payload.get('displayName')
            event.target = resource.Resource(payload.get(
                res_spec.id_field, res_parent_id),
                res_spec.el_type_uri or res_spec.type_uri, name)

        return event

    def _get_action(self, res_spec, res_id, request, action_suffix):
        """Given a resource spec, a request and a path suffix, deduct
        the correct CADF action.

        Depending on req.method:

        if POST:

        - path ends with 'action', read the body and use as action;
        - path ends with known custom_action, take action from config;
        - request ends with known (child-)resource type, assume is create
        action
        - request ends with unknown path, assume is update action.

        if GET:

        - request ends with known path, assume is list action;
        - request ends with unknown path, assume is read action.

        if PUT, assume update action.
        if DELETE, assume delete action.
        if HEAD, assume read action.

        """
        method = request.method
        if action_suffix is None:
            return self._map_method_to_action(method, res_id)

        return self._map_action_suffix(res_spec, action_suffix, method,
                                       res_id, request)

    def _map_method_to_action(self, method, res_id):
        if method == 'POST':
            return taxonomy.ACTION_UPDATE if res_id else \
                taxonomy.ACTION_CREATE
        elif method == 'GET':
            return taxonomy.ACTION_READ if res_id else taxonomy.ACTION_LIST
        return method_taxonomy_map[method]

    def _map_action_suffix(self, res_spec, action_suffix, method, res_id,
                           request):
        rest_action = ''
        if action_suffix == 'action':
            try:
                payload = request.json
                if payload:
                    rest_action = next(iter(payload))
                else:
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

        # use defaults if no custom action mapping exists
        if not res_spec.custom_actions:
            # if there are no custom_actions defined, we will just ...
            return (self._map_method_to_action(method, res_id) + "/" +
                    rest_action)
        else:
            self._log.debug("action %s is filtered out", rest_action)
            return None

    def create_event(self, request, response=None):
        # drop the endpoint's path prefix
        path = self._strip_url_prefix(request)
        if not path:
            self._log.debug("ignoring request (wrong prefix): %s",
                            request.path)
            return None

        path = path[:-1] if path.endswith('/') else path
        path = path[:-5] if path.endswith('.json') else path
        return self._build_event(self._resource_specs, None, None, request,
                                 response, path, 0)

    def _create_event(self, res_spec, res_id, res_parent_id, request, response,
                      action_suffix):
        action = self._get_action(res_spec, res_id, request, action_suffix)
        if not action:
            # skip if action filtered out
            return

        project_or_domain_id = request.environ.get(
            'HTTP_X_PROJECT_ID') or request.environ.get(
            'HTTP_X_DOMAIN_ID', taxonomy.UNKNOWN)
        initiator = ClientResource(
            typeURI=taxonomy.ACCOUNT_USER,
            id=request.environ.get('HTTP_X_USER_ID', taxonomy.UNKNOWN),
            name=request.environ.get('HTTP_X_USER_NAME', taxonomy.UNKNOWN),
            host=host.Host(address=request.client_addr,
                           agent=request.user_agent),
            project_id=project_or_domain_id)

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
            rtype = None
            if not res_id:
                rtype = res_spec.type_uri
            else:
                rtype = res_spec.el_type_uri
            target = resource.Resource(id=_make_uuid(res_id or res_parent_id),
                                       typeURI=rtype)
        else:
            # use the service as resource if element has been addressed
            target = self._build_target_service_resource(res_spec, request)

        event = eventfactory.EventFactory().new_event(
            eventType=cadftype.EVENTTYPE_ACTIVITY,
            outcome=action_result,
            action=action,
            initiator=initiator,
            # TODO add observer again?
            reason=event_reason,
            target=target)
        event.requestPath = request.path_qs
        # TODO add reporter step again?
        # event.add_reporterstep(
        #    reporterstep.Reporterstep(
        #        role=cadftype.REPORTER_ROLE_MODIFIER,
        #        reporter=resource.Resource(id='observer'),
        #        reporterTime=timestamp.get_utc_now()))

        return event

    def _build_target_service_resource(self, res_spec, req):
        """Build target resource."""
        target_type_uri = 'service/' + res_spec.type_uri
        target = resource.Resource(typeURI=target_type_uri,
                                   id=self._service_id,
                                   name=self._service_name)
        target.add_address(endpoint.Endpoint(req.path_url))

        return target

    @staticmethod
    def _build_service_id(name):
        md5_hash = hashlib.md5(name.encode('utf-8'))  # nosec
        ns = uuid.UUID(md5_hash.hexdigest())
        return str(uuid.uuid5(ns, socket.getfqdn()))

    def _strip_url_prefix(self, request):
        """ Removes the prefix from the URL paths
        :param req: incoming request
        :return: URL request path without the leading prefix or None if prefix
        was missing
        """
        g = self._prefix_re.match(request.path)
        return request.path[g.end():] if g else None
