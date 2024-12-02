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


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value != '' and value is not None:
            updated_payload[key] = value
    return updated_payload


def create_incident(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents'
        query_params = {
            "want_full_data": params.get('want_full_data'),
            "want_tasks": params.get('want_tasks')
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ''}
        payload = {
            "name": params.get('name'),
            "discovered_date": params.get('discovered_date'),
            "description": params.get('description'),
            "dtm": params.get('dtm'),
            "cm": params.get('cm'),
            "regulators": params.get('regulators'),
            "hipaa": params.get('hipaa'),
            "artifacts": params.get('artifacts'),
            "findings": params.get('findings'),
            "comments": params.get('comments')
        }
        additional_fields = params.pop('additional_fields')
        if additional_fields:
            payload.update(additional_fields)
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = ir.make_rest_call(endpoint, 'POST', params=query_params, data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def search_incidents(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents/query_paged'
        query_params = {
            "include_records_total": params.get('include_records_total'),
            "return_level": params.get('return_level'),
            "field_handle": params.get('field_handle')
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ''}
        payload = {
            "start": params.get('start'),
            "length": params.get('length'),
            "recordsTotal": params.get('recordsTotal'),
            "sorts": params.get('sorts'),
            "filters": params.get('filters'),
            "logic_type": params.get('logic_type')
        }
        payload = check_payload(payload)
        logger.debug("Query Parameters {0}".format(query_params))
        logger.debug("Payload {0}".format(payload))
        response = ir.make_rest_call(endpoint, 'POST', params=query_params, data=json.dumps(payload))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_simulations(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents/simulations'
        response = ir.make_rest_call(endpoint, 'GET', params=params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_tasks(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents/{0}/tasks'.format(params.pop('incident_id'))
        response = ir.make_rest_call(endpoint, 'GET', params=params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_details(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents/{0}'.format(params.pop('incident_id'))
        params = {k: v for k, v in params.items() if v is not None and v != ''}
        response = ir.make_rest_call(endpoint, 'GET', params=params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def update_incident(config, params):
    try:
        ir = IBMResilient(config)
        endpoint = '/incidents/{0}'.format(params.pop('incident_id'))
        query_parameter = {
            "return_dto": True
        }
        payload = {
            "changes": params.get('changes'),
            "version": params.get('version')
        }
        payload = check_payload(payload)
        logger.debug("Payload {0}".format(payload))
        response = ir.make_rest_call(endpoint, 'PATCH', params=query_parameter, data=json.dumps(payload))
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
            "changes": [
                {
                    "field": "plan_status",
                    "old_value": {
                        "text": old_incident_status
                    },
                    "new_value": {
                        "text": "C"
                    }
                }
            ]
        }
        endpoint = '/incidents/{0}'.format(incident_id)
        logger.debug("Payload {0}".format(data))
        response = ir.make_rest_call(endpoint, 'PATCH', data=json.dumps(data))
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config):
    try:
        response = get_incident_simulations(config, params={"want_closed": True})
        if response:
            return True
    except Exception as err:
        logger.info(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_incident_tasks': get_incident_tasks,
    'create_incident': create_incident,
    'search_incidents': search_incidents,
    'get_incident_simulations': get_incident_simulations,
    'get_incident_details': get_incident_details,
    'update_incident': update_incident,
    'close_incident': close_incident
}
