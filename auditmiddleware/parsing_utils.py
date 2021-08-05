import hashlib
import json
import socket
import uuid

import six
from pycadf.attachment import Attachment


def payloads_config(param):
    """Create a valid payloads config from the config file contents."""
    if not param:
        return {'enabled': True}

    paylds_config = param.copy()
    paylds_config['enabled'] = bool(param.get('enabled', True))

    return payloads_config


def make_tags(ev):
    """Build statsd metric tags from CADF event."""
    return [
        'project_id:{0}'.format(ev.target.project_id or
                                ev.initiator.project_id or
                                ev.initiator.domain_id),
        'target_type_uri:{0}'.format(ev.target.typeURI),
        'action:{0}'.format(ev.action),
        'outcome:{0}'.format(ev.outcome)]


def make_uuid(s):
    """Produce a uuid from digit inputs, return other input unmodified"""
    if s.isdigit():
        return str(uuid.UUID(int=int(s)))
    else:
        return s


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
            res_payload.pop(k, None)
    elif incl and isinstance(payload, dict):
        for k in incl:
            v = payload.get(k)
            if v:
                res_payload[k] = v
    else:
        res_payload = payload

    return res_payload


def build_service_id(name):
    """Invent stable UUID for the service itself."""
    md5_hash = hashlib.md5(name.encode('utf-8'))  # nosec
    ns = uuid.UUID(md5_hash.hexdigest())
    return str(uuid.uuid5(ns, socket.getfqdn()))


def to_path_segments(path_string):
    """Remove leading or trailing slashes and '.json' suffix and
     split path into segments. """
    path_string = path_string.rstrip("/").replace(".json", "")
    path_segments = path_string.lstrip('/').split('/')
    return path_segments


def get_json_if(condition, req_or_resp):
    """
    If condition is true, return the json body of the second argument
    or an empty dict if there is none.
    """
    useful_payload = {}
    if condition \
            and req_or_resp \
            and req_or_resp.content_length > 0 \
            and req_or_resp.content_type == "application/json":
        useful_payload = req_or_resp.json
    return useful_payload


def find_bulk_targets(response_payload, res_spec):
    """Check if a given payload contains targets of a bulk request.
     If so, return them"""
    if not response_payload or res_spec.singleton:
        return []
    resource = response_payload.get(res_spec.type_name, [])
    list_of_targets = resource if isinstance(resource, list) else []
    return list_of_targets


def attach_payload(event, payload, res_spec):
    """Attach request payload to event."""
    res_payload = _clean_payload(
        payload, res_spec)
    if res_payload:
        attach_val = Attachment(typeURI="mime:application/json",
                                content=json.dumps(res_payload,
                                                   separators=(',', ':')),
                                name='payload')
        event.add_attachment(attach_val)


def clean_or_unwrap(attachable_request_body, bulk_operation_payloads,
                    relevant_response_json, target_config):
    """Remove wrapping elements from payload
    or filter payload based on configuration"""
    if bulk_operation_payloads:
        response_payloads = [_clean_payload(payload, target_config.spec)
                             for payload in bulk_operation_payloads]
        request_payloads = \
            iter(attachable_request_body.get(target_config.spec.type_name, []))

    elif relevant_response_json:
        response_payloads = [relevant_response_json.get(
            target_config.spec.el_type_name, relevant_response_json)]
        request_payloads = [attachable_request_body.get(
            target_config.spec.el_type_name, attachable_request_body)]

    else:
        response_payloads = []
        request_payloads = [attachable_request_body]
    return request_payloads, response_payloads


def attach_custom_attributes(ev, spec, subpayload):
    """Add given payload to given event as Attachment"""
    for attr, typeURI in six.iteritems(spec.custom_attributes):
        value = subpayload.get(attr)
        if value:
            if not isinstance(value, six.string_types):
                value = json.dumps(value, separators=(',', ':'))
            attach_val = Attachment(typeURI=typeURI, content=value,
                                    name=attr)
            ev.add_attachment(attach_val)
