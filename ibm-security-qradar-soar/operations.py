"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import requests, json
from connectors.core.connector import get_logger, ConnectorError
from .constant import *

logger = get_logger('ibm-security-qradar-soar')


class IBMResilient(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        self.api_secret = config.get('api_secret')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/rest/orgs/{1}'.format(url, config.get('org_id'))
        else:
            self.url = url + '/rest/orgs/{0}'.format(config.get('org_id'))
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, endpoint, method, data=None, params=None):
        try:
            url = self.url + endpoint
            headers = {
                'Content-Type': 'application/json'
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, auth=(self.api_key, self.api_secret), data=data, params=params,
                                        headers=headers, verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            elif response.status_code == 404:
                return response
            else:
                logger.error("{0}".format(response.status_code))
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def create_incident(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents'
        payload = {
            "name": params.get('incident_name'),
            "discovered_date": 0
        }
        additional_fields = params.pop('additional_fields')
        if additional_fields:
            payload.update(additional_fields)
        payload = {k: v for k, v in payload.items() if v is not None and v != ''}
        response = ir.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_open_incidents(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents/open'
        response = ir.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_details(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents/{0}'.format(params.get('incident_id'))
        response = ir.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def update_incident(config, params):
    try:
        data = []
        ir = IBMResilient(config)
        incident_id = params.pop('incident_id')
        incident_details = get_incident_details(config, params={'incident_id': incident_id})
        additional_fields = params.pop('additional_fields')
        if additional_fields:
            params.update(additional_fields)
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        if 'severity' in params:
            old_severity = incident_details['severity_code']
            new_severity = SEVERITY.get(params.get('severity'))
            data.append({
                'field': 'severity_code',
                'old_value': {
                    'id': old_severity
                },
                'new_value': {
                    'id': new_severity
                }
            })
        if 'incident_type' in params:
            old_incident_type = incident_details['incident_type_ids']
            new_incident_type = INCIDENT_TYPE.get(params.get('incident_type'))
            new_incident_type_list = old_incident_type[:]
            new_incident_type_list.append(new_incident_type)
            data.append({
                'field': 'incident_type_ids',
                'old_value': {
                    'ids': old_incident_type
                },
                'new_value': {
                    'ids': new_incident_type_list
                }
            })
        if 'nist' in params:
            old_nist = incident_details['nist_attack_vectors']
            new_nist = NIST.get(params.get('nist'))
            new_nist_list = old_nist[:]
            new_nist_list.append(new_nist)
            data.append({
                'field': 'nist_attack_vectors',
                'old_value': {
                    'ids': old_nist
                },
                'new_value': {
                    'ids': new_nist_list
                }
            })
        if 'resolution' in params:
            old_resolution = incident_details['resolution_id']
            new_resolution = RESOLUTION_TO_ID.get(params.get('resolution'))
            data.append({
                'field': 'resolution_id',
                'old_value': {
                    'id': old_resolution
                },
                'new_value': {
                    'id': new_resolution
                }
            })
        if 'resolution_summary' in params:
            old_resolution_summary = incident_details['resolution_summary']
            new_resolution_summary = params.get('resolution_summary')
            data.append({
                'field': 'resolution_summary',
                'old_value': {
                    'textarea': old_resolution_summary
                },
                'new_value': {
                    'textarea': {
                        'format': 'html',
                        'content': new_resolution_summary
                    }
                }
            })
        if 'description' in params:
            old_description = incident_details['description']
            new_description = params.get('description')
            data.append({
                'field': 'description',
                'old_value': {
                    'textarea': old_description
                },
                'new_value': {
                    'textarea': {
                        'format': 'html',
                        'content': new_description
                    }
                }
            })
        if 'name' in params:
            old_name = incident_details['name']
            new_name = params.get('name')
            data.append({
                'field': 'name',
                'old_value': {
                    'text': old_name
                },
                'new_value': {
                    'text': new_name
                }
            })
        payload = {
            'changes': data
        }
        endpoint = '/incidents/{0}'.format(incident_id)
        response = ir.make_rest_call(endpoint, 'PATCH', data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def close_incident(config, params):
    try:
        ir = IBMResilient(config)
        incident_id = params.get('incident_id')
        incident_details = get_incident_details(config, params={'incident_id': incident_id})
        if not incident_details['resolution_id'] or not incident_details['resolution_summary']:
            return 'Resolution and resolution summary of the incident should be updated before closing an incident.'
        old_incident_status = incident_details['plan_status']
        data = {
            'changes': [
                {
                    'field': 'plan_status',
                    'old_value': {
                        'text': old_incident_status
                    },
                    'new_value': {
                        'text': 'C'
                    }
                }
            ]
        }
        endpoint = '/incidents/{0}'.format(incident_id)
        response = ir.make_rest_call(endpoint, 'PATCH', data=json.dumps(data))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config):
    try:
        response = get_open_incidents(config, params={})
        if response:
            return True
    except Exception as err:
        logger.info(str(err))
        raise ConnectorError(str(err))


operations = {
    'create_incident': create_incident,
    'get_open_incidents': get_open_incidents,
    'get_incident_details': get_incident_details,
    'update_incident': update_incident,
    'close_incident': close_incident
}
