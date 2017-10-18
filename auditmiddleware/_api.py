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

import yaml
from oslo_log import log as logging
from oslo_serialization import jsonutils

from pycadf import cadftype, timestamp
from pycadf import credential
from pycadf import endpoint
from pycadf import eventfactory
from pycadf import host
from pycadf import identifier
from pycadf import reason
from pycadf import reporterstep
from pycadf import resource
from pycadf import tag
from pycadf import cadftaxonomy as taxonomy
from six.moves.urllib import parse as urlparse

# Define value object classes
Service = collections.namedtuple('Service',
                                 ['id', 'name', 'type', 'admin_endp',
                                  'public_endp', 'private_endp'])

AuditConfig = collections.namedtuple('AuditConfig',
                                     ['resources',
                                      'service_endpoints',
                                      'default_target_endpoint_type'])

ResourceSpec = collections.namedtuple('ResourceSpec',
                                      ['type_uri', 'singleton', 'custom_actions',
                                       'children'])


class AuditMiddlewareConfigError(Exception):
    """Error raised when pyCADF fails to configure correctly."""

    pass


class ClientResource(resource.Resource):
    def __init__(self, project_id=None, **kwargs):
        super(ClientResource, self).__init__(**kwargs)
        if project_id is not None:
            self.project_id = project_id


class KeystoneCredential(credential.Credential):
    def __init__(self, identity_status=None, **kwargs):
        super(KeystoneCredential, self).__init__(**kwargs)
        if identity_status is not None:
            self.identity_status = identity_status

def _put_hier(dct, hier_name, object):
    """
    Puts an object with an hierarchical name (a/b/c/...) into a dictionary.
    The hierarchy implied by the name is mapped to the dictionary hierarchy.
    :param dct: target dict
    :param hier_name: hierarchical name h1/h2/.../hn/myname
    :param object: the object to be placed at the leaf
    """

    pos = hier_name.find('/')
    if pos >= 0:
        segment, rest = hier_name[0:pos], hier_name[pos + 1:]
        if segment not in dct:
            dct[segment] = {}
        _put_hier(dct[segment], rest, object)
    else:
        dct[hier_name] = object

class OpenStackAuditMiddleware(object):
    def __init__(self, cfg_file, log=logging.getLogger(__name__)):
        """Configure to recognize and map known api paths."""
        self._log = log

        try:
            conf = yaml.load(open(cfg_file, 'r'))

            self._service_type = conf.get('service_type')
            # default_target_endpoint_type = conf.get('target_endpoint_type')
            # self._service_endpoints = conf.get('service_endpoints', {})
            self._resource_specs = self._parse_resources(conf.get('resources'))

        except (OSError, yaml.YAMLError) as err:
            raise AuditMiddlewareConfigError('Error opening config file %s: %s',
                                             cfg_file, err)

    def _parse_resources(self, res_dict, parentTypeURI=None):
        result = {}

        for name, s in res_dict.iteritems():
            if not s:
                spec = {}
            else:
                spec = s

            if parentTypeURI:
                pfx = parentTypeURI
            else:
                pfx = "service/" + self._service_type

            singular = name[:-1] if name.endswith('s') else name
            type_uri = spec.get('type_uri', pfx + "/" + singular)

            spec = ResourceSpec(type_uri,
                                spec.get('singleton', False),
                                spec.get('custom_actions', {}),
                                self._parse_resources(spec.get('children', {}),
                                                      type_uri))
            _put_hier(result, name, spec)

        return result

    @staticmethod
    def _clean_path(value):
        """Clean path if path has json suffix."""
        return value[:-5] if value.endswith('.json') else value

    def _build_event(self, res_node, res_id, request, response, path, cursor=0):
        """

        :param res_tree:
        :param path:
        :param cursor:
        :return: the event
        """
        # Check if the end of path is reached and event can be created finally
        if cursor == -1:
            # end of path reached, create the event
            event = self._create_event(res_node, res_id, request, response, path, None)
            if request.method == 'POST' and response and response.json:
                payload = response.json
                name = payload.get('name')
                if name is None:
                    name = payload.get('displayName')
                event.target = resource.Resource(payload.get('id'),res_node.type_uri,name)

            return event

        # Find next path segment (skip leading / with +1)
        next_pos = path.find('/', cursor+1)
        token = None
        if next_pos != -1:
            # that means there are more path segments
            token = path[cursor+1:next_pos]
        else:
            token = path[cursor+1:]

        # handle the current token
        if isinstance(res_node, dict):
            # the node contains a dict => handle token as resource name
            node = res_node.get(token)
            if node is None:
                # no such name, ignore/filter the resource
                self._log.warning("Incomplete resource path after segment %s: %s", token, request.path)
                return None

            return self._build_event(node, res_id, request, response, path, next_pos)
        elif isinstance(res_node, ResourceSpec):
            # check if the token is a resource type
            child_res = res_node.children.get(token)
            if child_res:
                return self._build_event(child_res, res_id, request, response, path, next_pos)

            if next_pos == -1:
                # if there are no more tokens and the token was no child
                # this is an action
                return self._create_event(res_node, res_id, request, response, token)

            # the node contains a resource that is not a singleton
            # => since this is not a singleton, the token must be a resource ID
            # recurse first ...
            event = self._build_event(res_node, token, request, response, path, next_pos)
            # then set the target if not done already by the nested call

            return event

    def _get_action(self, res_spec, res_id, request, action_suffix):
        """Given a resource spec, a request and a path suffix, deduct
        the correct CADF action.

        Depending on req.method:

        if POST:

        - path ends with 'action', read the body and use as action;
        - path ends with known custom_action, take action from config;
        - request ends with known (child-)resource type, assume is create action
        - request ends with unknown path, assume is update action.

        if GET:

        - request ends with known path, assume is list action;
        - request ends with unknown path, assume is read action.

        if PUT, assume update action.
        if DELETE, assume delete action.
        if HEAD, assume read action.

        """
        method = request.method

        if method == 'POST':
            if action_suffix is None:
                return taxonomy.ACTION_CREATE

            return self._get_custom_action(res_spec, action_suffix, request)
        elif method == 'GET':
            if action_suffix is None:
                return taxonomy.ACTION_READ if res_id else taxonomy.ACTION_LIST

            return self._get_custom_action(res_spec, action_suffix, request)
        elif method == 'PUT' or method == 'PATCH':
            return taxonomy.ACTION_UPDATE
        elif method == 'DELETE':
            return taxonomy.ACTION_DELETE
        elif method == 'HEAD':
            return taxonomy.ACTION_READ
        else:
            return None

    def _get_custom_action(self, res_spec, action_suffix, request):
        rest_action = ''
        if action_suffix == 'action':
            try:
                payload = request.json
                if payload:
                    rest_action = next(iter(payload))
                else:
                    return None
            except ValueError:
                self._log.warning("unexpected empty action payload",
                                  request.path)
                return None
        else:
            rest_action = action_suffix
        action = res_spec.custom_actions.get(rest_action)
        if action is not None:
            return action
        action = res_spec.custom_actions.get('*')
        if action is not None:
            return action.replace('*', rest_action)
        elif not res_spec.custom_actions:
            # if there are no custom_actions defined, we will just
            return taxonomy.ACTION_UPDATE + "/" + rest_action
        else:
            self._log.debug("action %s is filtered out", rest_action)
            return None

    def create_event(self, request, response=None):
        # drop the endpoint's path prefix configured in the keystone catalog
        prefix = self.get_url_prefix(request)
        path = request.path[len(prefix):]
        path = path[:-1] if path.endswith('/') else path
        return self._build_event(self._resource_specs, None, request, response, path, 0)

    def _create_event(self, res_spec, res_id, request, response, action_suffix):
        action = self._get_action(res_spec, res_id, request, action_suffix)
        if not action:
            # skip if action filtered out
            return

        initiator = ClientResource(
            typeURI=taxonomy.ACCOUNT_USER,
            id=request.environ.get('HTTP_X_USER_ID', taxonomy.UNKNOWN),
            name=request.environ.get('HTTP_X_USER_NAME', taxonomy.UNKNOWN),
            host=host.Host(address=request.client_addr, agent=request.user_agent),
            credential=KeystoneCredential(
                token=request.environ.get('HTTP_X_AUTH_TOKEN', ''),
                identity_status=request.environ.get('HTTP_X_IDENTITY_STATUS',
                                                    taxonomy.UNKNOWN)),
            project_id=request.environ.get('HTTP_X_PROJECT_ID', taxonomy.UNKNOWN))

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

        event = eventfactory.EventFactory().new_event(
            eventType=cadftype.EVENTTYPE_ACTIVITY,
            outcome=action_result,
            action=action,
            initiator=initiator,
            # TODO add observer again?
            reason=event_reason,
            target=resource.Resource(id=res_id, typeURI=res_spec.type_uri))
        event.requestPath = request.path_qs
        # TODO add reporter step again?
        #event.add_reporterstep(
        #    reporterstep.Reporterstep(
        #        role=cadftype.REPORTER_ROLE_MODIFIER,
        #        reporter=resource.Resource(id='observer'),
        #        reporterTime=timestamp.get_utc_now()))
        print event.as_dict()

        return event

############### unused ###########################

    def _get_service_info(self, endp):
        service = Service(
            type=self._service_endpoints.get(
                endp['type'],
                taxonomy.UNKNOWN),
            name=endp['name'],
            id=endp['endpoints'][0].get('id', endp['name']),
            admin_endp=endpoint.Endpoint(
                name='admin',
                url=endp['endpoints'][0].get('adminURL', taxonomy.UNKNOWN)),
            private_endp=endpoint.Endpoint(
                name='private',
                url=endp['endpoints'][0].get('internalURL', taxonomy.UNKNOWN)),
            public_endp=endpoint.Endpoint(
                name='public',
                url=endp['endpoints'][0].get('publicURL', taxonomy.UNKNOWN)))

        return service

    def _build_target_service_resource(self, req, service):
        """Build target resource."""
        target_type_uri = (
            self._build_type_uri(req, service.type)
            if service.type != taxonomy.UNKNOWN else service.type)
        target = resource.Resource(typeURI=target_type_uri,
                                   id=service.id, name=service.name)
        if service.admin_endp:
            target.add_address(service.admin_endp)
        if service.private_endp:
            target.add_address(service.private_endp)
        if service.public_endp:
            target.add_address(service.public_endp)
        return target

    def get_url_prefix(self, req):
        catalog = {}
        try:
            catalog = jsonutils.loads(req.environ['HTTP_X_SERVICE_CATALOG'])
        except KeyError:
            self._log.warning(
                'Unable to discover target information because '
                'service catalog is missing. Either the incoming '
                'request does not contain an auth token or auth '
                'token does not contain a service catalog. For '
                'the latter, please make sure the '
                '"include_service_catalog" property in '
                'auth_token middleware is set to "True"')

        req_url = urlparse.urlparse(req.host_url)
        for endp in catalog:
            endpoint_urls = endp['endpoints'][0]
            if endp['type'] != self._service_type:
                continue

            for k in ['publicURL', 'internalURL', 'adminURL']:
                url = urlparse.urlparse(endpoint_urls.get(k, ''))
                if req_url.netloc == url.netloc:
                    return url.path

    def get_service_resource(self, req):
        """Retrieve target information.

        If discovery is enabled, target will attempt to retrieve information
        from service catalog. If not, the information will be taken from
        given config file.
        """
        service_info = Service(type=taxonomy.UNKNOWN, name=taxonomy.UNKNOWN,
                               id=taxonomy.UNKNOWN, admin_endp=None,
                               private_endp=None, public_endp=None)

        catalog = {}
        try:
            catalog = jsonutils.loads(req.environ['HTTP_X_SERVICE_CATALOG'])
        except KeyError:
            self._log.warning(
                'Unable to discover target information because '
                'service catalog is missing. Either the incoming '
                'request does not contain an auth token or auth '
                'token does not contain a service catalog. For '
                'the latter, please make sure the '
                '"include_service_catalog" property in '
                'auth_token middleware is set to "True"')

        default_endpoint = None
        for endp in catalog:
            endpoint_urls = endp['endpoints'][0]
            admin_urlparse = urlparse.urlparse(
                endpoint_urls.get('adminURL', ''))
            public_urlparse = urlparse.urlparse(
                endpoint_urls.get('publicURL', ''))
            req_url = urlparse.urlparse(req.host_url)
            if req_url.netloc == admin_urlparse.netloc or \
                            req_url.netloc == public_urlparse.netloc:
                service_info = self._get_service_info(endp)
                break
            elif (self._MAP.default_target_endpoint_type and
                          endp[
                              'type'] ==
                          self._MAP.default_target_endpoint_type):
                default_endpoint = endp
        else:
            if default_endpoint:
                service_info = self._get_service_info(default_endpoint)
        return self._build_target_service_resource(req, service_info)


