import json
import uuid
import isodate
import requests
from datetime import datetime, timedelta
from MicrosoftAzureSentinelParser import MicrosoftAzureSentinelParser
from MicrosoftAzureSentinelCommon import (
    MicrosoftAzureSentinelCommon,
    read_backlog_ids,
    validate_backlog
)
from SiemplifyUtils import convert_string_to_datetime
from datamodels import TagCollection, CustomHuntingRuleRequest
from exceptions import (
    MicrosoftAzureSentinelManagerError,
    MicrosoftAzureSentinelValidationError,
    MicrosoftAzureSentinelPermissionError,
    MicrosoftAzureSentinelUnauthorizedError,
    MicrosoftAzureSentinelBadRequestError,
    MicrosoftAzureSentinelNotFoundError,
    MicrosoftAzureSentinelTimeoutError,
    MicrosoftAzureSentinelConflictError,
)
from urllib.parse import urljoin
from utils import convert_list_to_comma_separated_string, LOGGER
from enum import Enum
from AzureQueryBuilder import QueryBuilder, Condition, QueryOperatorEnum, OperatorEnum
from constants import ALERT_TYPES_WITH_EVENTS


HEADERS = {
    "Content-Type": "application/json"
}
# @TODO remove after refactor
DEFAULT_API_VERSION = '2019-01-01-preview'

LOGIN_ENDPOINT = "/{}/oauth2/token"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
MIN_PT_DURATION = timedelta(minutes=5)
MAX_PT_DURATION = timedelta(days=14)


API_ENDPOINTS = {
    'base_url': {
       'url': '{api_root}/subscriptions/{subscriptions}/resourcegroups/{resource}'
             '/providers/microsoft.operationalinsights/workspaces/{workspace}/'
    },
    'incidents': {
        'url': 'providers/Microsoft.SecurityInsights/incidents',
        'version': '2019-01-01-preview'
    },
    'incident': {
        'url': 'providers/Microsoft.SecurityInsights/Incidents/{incident_name}',
        'version': '2019-01-01-preview'
    },
    'incident_comment': {
        'url': 'providers/Microsoft.SecurityInsights/Incidents/{incident_number}/comments/{incident_comment_id}',
        'version': '2019-01-01-preview'
    },
    'incident_cases': {
        'url': 'providers/Microsoft.SecurityInsights/Cases',
        'version': '2019-01-01-preview'
    },
    'INCIDENT_AGGREGATION': {
        'URL': 'providers/Microsoft.SecurityInsights/aggregations/Cases',
        'VERSION': '2019-01-01-preview'
    },
    'custom_hunting_rules_listing': {
        'url': 'savedSearches',
        'version': '2015-03-20'
    },
    'custom_hunting_rules': {
        'url': 'savedSearches/{custom_hunting_rule_id}',
        'version': '2015-03-20'
    },
    'alert_rules_listing': {
        'url': 'providers/Microsoft.SecurityInsights/alertRules',
        'version': '2019-01-01-preview'
    },
    'alert_rules': {
        'url': 'providers/Microsoft.SecurityInsights/alertRules/{alert_rule_id}',
        'version': '2019-01-01-preview'
    },
    'kql_query': {
        'url': 'query',
        'version': '2017-10-01',
    },
    'incident_aggregation': {
        'url': 'providers/Microsoft.SecurityInsights/aggregations/Cases',
        'version': '2019-01-01-preview'
    },
    'ping': {
        'url': 'providers/Microsoft.SecurityInsights/incidents',
        'version': '2019-01-01-preview'
    },
    'GET_INCIDENT_ALERTS': {
        'URL': 'providers/Microsoft.SecurityInsights/incidents/{incident_name}/alerts',
        'VERSION': '2019-01-01-preview'
    },
    'GET_ALERT_ENTITIES': {
        'URL': 'providers/Microsoft.SecurityInsights/entities/{alert_id}/expand',
        'VERSION': '2019-01-01-preview',
        'DEFAULT_EXPANSION_ID': '98b974fd-cc64-48b8-9bd0-3a209f5b944b'
    },
    'GET_INCIDENT_ENTITIES': {
        'URL': 'providers/Microsoft.SecurityInsights/Incidents/{incident_id}/entities',
        'VERSION': '2019-01-01-preview'
    }
}

ADDITIONAL_DEFAULT_FOR_VALIDATION = ['Not Updated']
CLOSED = 'Closed'

DEFAULT_SEVERITIES = [
    'Informational',
    'Low',
    'Medium',
    'High',
]

DEFAULT_ALERT_RULE_SEVERITIES = [
    'Informational',
    'Low',
    'Medium',
    'High',
]

DEFAULT_STATUSES = [
    'New',
    'Active',
    'Closed'
]

DEFAULT_UPDATE_INCIDENT_STATUSES = [
    'Resolved',
    'Dismissed',
    'TruePositive',
    'FalsePositive',
    'Other'
]

DEFAULT_TRIGGER_OPERATORS = [
    'GreaterThan',
    'LessThan',
    'Equal',
    'NotEqual'
]

DEFAULT_CLOSE_REASONS = [
    "True Positive - suspicious activity",
    "Benign Positive - suspicious but expected",
    "False Positive - incorrect alert logic",
    "False Positive - inaccurate data",
    "Undetermined"
]

CLOSE_REASON_DELIMITER = '-'

DEFAULT_TACTICS = [
    'InitialAccess',
    'Execution',
    'Persistence',
    'PrivilegeEscalation',
    'DefenseEvasion',
    'CredentialAccess',
    'Discovery',
    'LateralMovement',
    'Collection',
    'Exfiltration',
    'CommandAndControl'
]

DEFAULT_TIME_FRAME = 3


class QueryFilterKeyEnum(Enum):
    ORDER_BY = '$orderBy'
    LIMIT = '$top'
    START_TIME = 'startTime'
    END_TIME = 'endTime'
    TIME_SPAN = 'timespan'
    FILTER = '$filter'


class MicrosoftAzureSentinelManager(object):
    """
    MicrosoftAzureSentinel Manager
    """
    def __init__(
            self,
            api_root,
            client_id,
            client_secret,
            tenant_id,
            workspace_id,
            resource,
            subscription_id,
            login_url,
            verify_ssl=False,
            logger=None,
            force_check_connectivity=False
    ):
        self.api_root = api_root
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.workspace_id = workspace_id
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers = HEADERS
        self.resource = resource
        self.subscription_id = subscription_id
        self.login_url = login_url
        self.verify_ssl = verify_ssl
        self.token = self.fetch_token()
        self.session.headers.update({"Authorization": f'Bearer {self.token}'})
        self.logger = LOGGER(logger)
        self.sentinel_parser = MicrosoftAzureSentinelParser(self.logger)
        self.sentinel_common = MicrosoftAzureSentinelCommon(self.logger)
        self.base_url = self._get_base_url()

        if force_check_connectivity:
            self.test_connectivity()

    @classmethod
    def get_api_error_message(cls, exception):
        """
        Get API error message
        :param exception: {Exception} The api error
        :return: {str} error message
        """
        context = exception.response.content.decode()
        try:
            return exception.response.json().get('error', {}).get('message') or context
        except:
            return context

    @classmethod
    def validate_response(cls, response, error_msg='An error occurred'):
        # type: (requests.Response, str) -> None
        """
        Login Response Validation
        @param response: API Response
        @param error_msg: Error message to change raised one
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            error_message = cls.get_api_error_message(error) or error_msg

            error_context = {
                "request_uri": error.request.url,
                "request_body": error.request.body,
                "response_status": error.response.status_code
            }

            if response.status_code == 429:
                raise MicrosoftAzureSentinelTimeoutError(error_message)

            if response.status_code == 504:
                raise MicrosoftAzureSentinelManagerError(
                    f"Search didn't completed due to timeout. Error: {error_message}")

            if response.status_code == 409:
                raise MicrosoftAzureSentinelConflictError(error_message)

            if response.status_code == 404:
                raise MicrosoftAzureSentinelNotFoundError(error_message, error_context=error_context)

            if response.status_code == 403:
                raise MicrosoftAzureSentinelPermissionError(error_message)

            if response.status_code == 401:
                raise MicrosoftAzureSentinelUnauthorizedError(error_message)

            if response.status_code == 400:
                raise MicrosoftAzureSentinelBadRequestError(error_message, error_context=error_context)

            raise MicrosoftAzureSentinelManagerError(f'{error_msg}: {error} {error_message}')

        if not response.ok:
            raise

    def _remove_session_header(self, header):
        if self._has_session_header(header):
            del self.session.headers[header]

    def _add_session_header(self, header, value):
        self.session.headers[header] = value

    def _has_session_header(self, header):
        return header in self.session.headers

    def _get_base_url(self):
        return self._get_endpoint_url(
            url_id='base_url',
            api_root=self.api_root,
            subscriptions=self.subscription_id,
            resource=self.resource,
            workspace=self.workspace_id)

    def test_connectivity(self):
        try:
            response = self.session.get(
                self._get_full_url('ping'),
                params={
                    'api-version': self._get_endpoint_version('ping'),
                    QueryFilterKeyEnum.LIMIT.value: 1
                })
            self.validate_response(response)
        except Exception as e:
            raise MicrosoftAzureSentinelManagerError(f'Failed to connect to the Azure Sentinel Workspace. Reason: {e}')

    def fetch_token(self):
        # type: () -> str
        """
        Fetch authentication token for Devices payloads.
        @return: Access token
        """
        url = urljoin(self.login_url, LOGIN_ENDPOINT.format(self.tenant_id))
        response = requests.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "resource": self.api_root,
                "client_secret": self.client_secret
            },
            verify=self.verify_ssl
        )
        self.validate_login_response(response, "Failed to connect to the Azure Sentinel Workspace")
        access_token = response.json().get('access_token')

        if access_token:
            return access_token

        raise MicrosoftAzureSentinelManagerError("Failed fetching token. Error code: {}. Description: {}".format(
            response.status_code,
            response.json().get("error_description", response.content))
        )

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url for session.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        url = urljoin(self.base_url, self._get_endpoint_url(url_id).format(**kwargs))

        return url

    def _get_endpoint_version(self, url_id):
        """
        Get version for endpoint
        :param url_id: {str} The id of url
        :return: {str} Endpoint version
        """
        return API_ENDPOINTS[url_id]['version']

    def _get_endpoint_url(self, url_id, **kwargs):
        """
        Get version for endpoint
        :param url_id: {str} The id of url
        :return: {str} Endpoint url
        """
        url = API_ENDPOINTS[url_id]['url']
        if kwargs:
            return url.format(**kwargs)

        return url

    def get_alert_rules(self, severities=None, types=None, tactics=None, only_enabled_rules=False, limit=None):
        # type: (list, list, list, bool, int) -> [object]
        """
        Get all alert rules including filters
        @param severities: Severities list of the alert rules to look for
        @param types: Alert types
        @param tactics: Alert rule tactics
        @param only_enabled_rules: Only enabled alert rules
        @param limit: returned alert rules count
        @return: List of the alert rules
        """
        url = self._get_full_url('alert_rules_listing')
        params = {
            'api-version': self._get_endpoint_version('alert_rules_listing')
        }

        response = self.session.get(url, params=params)
        self.validate_response(response)
        alert_rules_list = self.sentinel_parser.build_results(response.json(), 'build_siemplify_alert_rule_obj')

        return self._filter_alert_rules(alert_rules_list, severities, types, tactics, only_enabled_rules, limit)

    def get_alert_rule(self, alert_rule_id):
        """
        Get alert rule by ID
        @param alert_rule_id: ID of the alert rule
        @return: {AlertRule} instance
        """
        params = {
            'api-version': self._get_endpoint_version('alert_rules')
        }
        response = self.session.get(self._get_full_url('alert_rules', alert_rule_id=alert_rule_id), params=params)
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_alert_rule_obj(response.json())

    def create_alert_rule(self, enable_alert_rule, name, severity, query, frequency, lookup_period, trigger_operator,
                          trigger_threshold, enable_suppression, suppression_duration, description=None, tactics=None):
        # type: (bool, str, str, str, str, str, str, int, bool, str, str, list) -> object
        """
        Create new alert rule
        @param enable_alert_rule: Enables or Disables alert rule
        @param name: Alert Rule name
        @param severity: Alert Rule severity
        @param query: Alert rule query
        @param frequency: How frequently to run the query
        @param lookup_period: Time of the last lookup data
        @param trigger_operator: Alert Rule trigger operator
        @param trigger_threshold: Alert Rule trigger threshold
        @param enable_suppression: Whether you want to stop running query after alert is generated
        @param suppression_duration: How long you want to stop running query after alert is generated
        @param description: Alert Rule description
        @param tactics: Alert Rule tactics
        @return: New Alert Rule
        """
        params = {
            'api-version': self._get_endpoint_version('alert_rules')
        }

        json_payload = {
            'properties': {
                'enabled': enable_alert_rule,
                'displayName': name,
                'severity': severity,
                'query': query,
                'queryFrequency': frequency,
                'queryPeriod': lookup_period,
                'triggerOperator': trigger_operator,
                'triggerThreshold': trigger_threshold,
                'suppressionEnabled': enable_suppression,
                'suppressionDuration': suppression_duration,
                'description': description,
                'tactics': tactics
            }
        }

        response = self.session.put(
            self._get_full_url('alert_rules', alert_rule_id=uuid.uuid4()),
            params=params,
            json=json_payload
        )
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_alert_rule_obj(response.json())

    def update_alert_rule(self, alert_rule_id, enable_alert_rule=None, name=None, severity=None, query=None,
                          frequency=None, lookup_period=None, trigger_operator=None, trigger_threshold=None,
                          enable_suppression=None, suppression_duration=None, description=None, tactics=None):
        # type: (str, bool, str, str, str, str, str, str, int, bool, str, str, list) -> object
        """
        Update existing alert rule
        @param alert_rule_id: ID of the Alert Rule to update
        @param enable_alert_rule: Enables or Disables alert rule
        @param name: Alert Rule name
        @param severity: Alert Rule severity
        @param query: Alert rule query
        @param frequency: How frequently to run the query
        @param lookup_period: Time of the last lookup data
        @param trigger_operator: Alert Rule trigger operator
        @param trigger_threshold: Alert Rule trigger threshold
        @param enable_suppression: Whether you want to stop running query after alert is generated
        @param suppression_duration: How long you want to stop running query after alert is generated
        @param description: Alert Rule description
        @param tactics: Alert Rule tactics
        @return: Updated Alert Rule
        """
        alert_rule = self.get_alert_rule(alert_rule_id)
        json_payload = self.modify_alert_rule_json_payload(alert_rule, enable_alert_rule, name, severity, query,
                                                           frequency, lookup_period, trigger_operator, trigger_threshold,
                                                           enable_suppression, suppression_duration, description,
                                                           tactics)
        params = {
            'api-version': self._get_endpoint_version('alert_rules')
        }

        response = self.session.put(
            self._get_full_url('alert_rules', alert_rule_id=alert_rule_id),
            params=params,
            json=json_payload
        )
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_alert_rule_obj(response.json())

    def modify_alert_rule_json_payload(self, alert_rule, enable_alert_rule=None, name=None,
                                       severity=None, query=None, frequency=None, lookup_period=None,
                                       trigger_operator=None, trigger_threshold=None, enable_suppression=None,
                                       suppression_duration=None, description=None, tactics=None):
        """
        Get updating modified data
        @param alert_rule: AlertRule object
        @param enable_alert_rule: Enables or Disables alert rule
        @param name: Alert Rule name
        @param severity: Alert Rule severity
        @param query: Alert rule query
        @param frequency: How frequently to run the query
        @param lookup_period: Time of the last lookup data
        @param trigger_operator: Alert Rule trigger operator
        @param trigger_threshold: Alert Rule trigger threshold
        @param enable_suppression: Whether you want to stop running query after alert is generated
        @param suppression_duration: How long you want to stop running query after alert is generated
        @param description: Alert Rule description
        @param tactics: Alert Rule tactics
        @return: Updated Alert Rule
        """
        alert_rule_data = alert_rule.get_original_data()

        tactics = alert_rule.properties.tactics + [tactic for tactic in tactics if tactic not in alert_rule.properties.tactics]
        properties = {
            'enabled': enable_alert_rule,
            'displayName': name,
            'severity': severity,
            'query': query,
            'queryFrequency': frequency,
            'queryPeriod': lookup_period,
            'triggerOperator': trigger_operator,
            'triggerThreshold': trigger_threshold,
            'suppressionEnabled': enable_suppression,
            'suppressionDuration': suppression_duration,
            'description':  description,
            'tactics': list(set(tactics))
        }
        properties = {key: value for key, value in properties.items() if value is not None}
        # READ-ONLY field
        del alert_rule_data['properties']['lastModifiedUtc']
        alert_rule_data['properties'].update(properties)

        return alert_rule_data

    def delete_alert_rule(self, alert_rule_id):
        # type: (str) -> None
        """
        Delete Alert Rule
        @param alert_rule_id: ID of the Alert Rule to delete
        """
        # To check if alert exists
        self.get_alert_rule(alert_rule_id=alert_rule_id)
        params = {
            'api-version': self._get_endpoint_version('alert_rules')
        }

        response = self.session.delete(self._get_full_url('alert_rules', alert_rule_id=alert_rule_id), params=params)
        self.validate_response(response)

    def get_custom_hunting_rules(self, names=None, tactics=None, limit=None):
        # type: (list, list, int) -> [object]
        """
        Get all Custom Hunting Rules including filters
        @param names: Custom Hunting Rules names
        @param tactics: Custom Hunting Rules tactics
        @param limit: Limited items to return
        @return: Filtered Custom Hunting Rules
        """
        params = {
            'api-version': self._get_endpoint_version('custom_hunting_rules_listing'),
            QueryFilterKeyEnum.LIMIT.value: limit
        }
        response = self.session.get(
            self._get_full_url('custom_hunting_rules_listing'),
            params=params
        )
        hunting_rules = self.sentinel_parser.build_results(response.json(), 'build_siemplify_custom_hunting_rule_obj')

        return self._filter_custom_hunting_rules(hunting_rules, names, tactics)[:limit]

    def get_custom_hunting_rule(self, custom_hunting_rule_id):
        # type: (str) -> object
        """
        Get specific Custom Hunting Rule
        @param custom_hunting_rule_id: Custom Hunting Rule ID
        @return: Custom Hunting Rule
        """
        hunting_rule = self._get_custom_hunting_rule(custom_hunting_rule_id)

        return self.sentinel_parser.build_siemplify_custom_hunting_rule_obj(hunting_rule)

    def _get_custom_hunting_rule(self, custom_hunting_rule_id):
        params = {
            'api-version': self._get_endpoint_version('custom_hunting_rules'),
        }
        response = self.session.get(
            self._get_full_url('custom_hunting_rules', custom_hunting_rule_id=custom_hunting_rule_id),
            params=params
        )
        self.validate_response(response)

        return response.json()

    def create_custom_hunting_rule(self, query, display_name, description=None, tactics=None):
        # type: (str, str, str, list) -> object
        """
        Create new Custom Hunting Rule
        @param query: Custom Hunting Rule query
        @param display_name: Custom Hunting Ruled display name
        @param description: Custom Hunting Rule description
        @param tactics: Custom Hunting Rule tactics
        @return: New Custom Hunting Rule
        """
        params = {
            'api-version': self._get_endpoint_version('custom_hunting_rules'),
        }

        tags = TagCollection()

        if tactics:
            tags.set_from_list('tactics', tactics)
        if description:
            tags.set('description', description)

        custom_hunting_rule = CustomHuntingRuleRequest()
        custom_hunting_rule.name = custom_hunting_rule.id = uuid.uuid4()
        custom_hunting_rule.properties.query = query
        custom_hunting_rule.properties.display_name = display_name
        custom_hunting_rule.properties.tags = tags

        response = self.session.put(
            self._get_full_url('custom_hunting_rules', custom_hunting_rule_id=custom_hunting_rule.id),
            params=params,
            json=custom_hunting_rule.to_create_json()
        )
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_custom_hunting_rule_obj(response.json())

    def update_custom_hunting_rule(self, custom_hunting_rule_id, display_name=None, query=None, description=None,
                                   tactics=None):
        # type: (str, str, str, str, list) -> object
        """
        Update existing Custom Hunting Rule
        @param custom_hunting_rule_id: Custom Hunting Rule ID
        @param display_name: Custom Hunting Rule display name
        @param query: Custom Hunting Rule query
        @param description: Custom Hunting Rule description
        @param tactics: Custom Hunting Rule tactics
        @return: Updated Custom Hunting Rule
        """
        hunting_rule = self._get_custom_hunting_rule(custom_hunting_rule_id)
        custom_hunting_rule = self.sentinel_parser.build_siemplify_custom_hunting_rule_req_obj(hunting_rule)

        display_name_to_update = display_name or custom_hunting_rule.properties.display_name
        custom_hunting_rule.properties.display_name = display_name_to_update

        query_to_update = query or custom_hunting_rule.properties.query
        custom_hunting_rule.properties.query = query_to_update

        if description:
            custom_hunting_rule.properties.tags.remove_all('description')
            custom_hunting_rule.properties.tags.set('description', description)

        if tactics:
            custom_hunting_rule.properties.tags.set_from_list_unique_values(name='tactics', values=tactics,
                                                                            unique_tag_name='tactics')
        response = self.session.put(
            self._get_full_url('custom_hunting_rules', custom_hunting_rule_id=custom_hunting_rule_id),
            params={'api-version': self._get_endpoint_version('custom_hunting_rules')},
            json=custom_hunting_rule.to_update_json()
        )
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_custom_hunting_rule_obj(response.json())

    def delete_custom_hunting_rule(self, custom_hunting_rule_id):
        # type: (str) -> None
        """
        Delete Custom Hunting Rule
        @param custom_hunting_rule_id: Custom Hunting Rule ID
        """
        # To check if custom hunting rule exists
        self.get_custom_hunting_rule(custom_hunting_rule_id=custom_hunting_rule_id)

        params = {
            'api-version': self._get_endpoint_version('custom_hunting_rules'),
        }

        response = self.session.delete(
            self._get_full_url('custom_hunting_rules', custom_hunting_rule_id=custom_hunting_rule_id),
            params=params
        )
        self.validate_response(response)

    def run_custom_hunting_rule(self, custom_hunting_rule_id, timeout=None):
        # type: (str, int) -> object
        """
        Run query of Custom Hunting Rule
        @param custom_hunting_rule_id: Custom Hunting Rule ID
        @param timeout: timeout value for the Azure Sentinel hunting rule API call.
        @return: Query Result
        """
        custom_hunting_rule = self.get_custom_hunting_rule(custom_hunting_rule_id)

        return self.run_kql_query(custom_hunting_rule.properties.query, timeout=timeout)

    def run_kql_query(self, query, timespan=None, timeout=None, duration=None, limit=None):
        # type: (str, str, int, str, int) -> object or list
        """
        Run query
        @param query: Query
        @param timespan: Time span to look for
        @param timeout: timeout value for the Azure Sentinel hunting rule API call
        @param duration: Duration (servertimeout)
        @param limit: How much results should be fetched
        @return: Query Result
        """
        params = {
            'api-version': self._get_endpoint_version('kql_query'),
            'timespan': timespan,
        }

        json_request = {
            'query': f'{query} | limit {limit}' if limit else query,
            'servertimeout': duration
        }

        json_request = {k: v for k, v in json_request.items() if v}

        if timeout:
            self._add_session_header('Prefer', f'wait={timeout}')

        response = self.session.post(self._get_full_url('kql_query'), params=params, json=json_request)

        self._remove_session_header('Prefer')

        self.validate_response(response)

        query_result = self.sentinel_parser.build_results(
            raw_json=response.json(),
            method='build_siemplify_primary_result_obj',
            data_key='tables'
        )

        return query_result and query_result[0]

    def get_incidents_by_filter(self, creation_time=None, time_frame=None, statuses=None, severities=None, limit=None,
                                asc=False):
        # type: (datetime, int, list, list, int, bool) -> [object]
        """
        Get all Incidents including filters
        @param creation_time: Get incidents with creationTimeUtc greater than passed datetime
        @param time_frame: Time frame for which to show the statistics
        @param statuses: Statuses of the incidents to look for
        @param severities: Severities of the incidents to look for
        @param limit: How much results should be fetched
        @param asc: Whether to bring incidents in ascending or descending order
        @return: Incidents
        """
        params = {
            'api-version': self._get_endpoint_version('incidents'),
        }

        query = str(QueryBuilder([
            Condition(field='properties/createdTimeUtc', operator=OperatorEnum.GE.value,
                      value_formatter=('format_time', TIME_FORMAT), value=creation_time),
            Condition(field='properties/createdTimeUtc', operator=OperatorEnum.GE.value,
                      value_formatter=('set_hours_back', TIME_FORMAT), value=time_frame),
            Condition(field='properties/status', operator=OperatorEnum.EQ.value, value=statuses,
                      value_with_quotes=True, join_values_with=QueryOperatorEnum.OR.value),
            Condition(field='properties/severity', operator=OperatorEnum.EQ.value, value=severities,
                      value_with_quotes=True, join_values_with=QueryOperatorEnum.OR.value)
        ]))
        if query:
            params[QueryFilterKeyEnum.FILTER.value] = query

        if asc:
            params[QueryFilterKeyEnum.ORDER_BY.value] = 'properties/createdTimeUtc asc'

        if limit:
            params[QueryFilterKeyEnum.LIMIT.value] = limit

        response = self.session.get(self._get_full_url('incidents'), params=params)
        self.validate_response(response)

        return self.sentinel_parser.build_results(response.json(), 'build_siemplify_incident_obj', limit=limit)

    def get_incidents(self, creation_time=None, time_frame=None, statuses=None, severities=None, limit=None, extend_alerts=False,
                      asc=True):
        # type: (datetime, int, list, list, int, bool, bool) -> [object]
        """
        Get all Incidents including filters
        @param creation_time: Get incidents with creationTimeUtc greater than passed datetime
        @param time_frame: Time frame for which to show the statistics
        @param statuses: Statuses of the incidents to look for
        @param severities: Severities of the incidents to look for
        @param limit: How much results should be fetched
        @param extend_alerts: Convert
        @param asc: Whether to bring incidents in ascending or descending order
        @return: Incidents
        """
        api_parameters = self._build_api_parameters(
            api_version=self._get_endpoint_version('incident_cases'),
            creation_time=creation_time,
            time_frame=time_frame,
            statuses=statuses,
            severities=severities,
            asc=asc,
            limit=limit
        )

        response = self.session.get(self._get_full_url('incident_cases'), params=api_parameters)
        self.validate_response(response)

        incidents_data = response.json().get('value')

        incidents = []
        for incident_data in incidents_data:
            incident = self.sentinel_parser.build_siemplify_incident_obj(incident_data)

            if extend_alerts:
                if not incident.properties.related_alert_ids:
                    self.logger.info(f'Incorrect formatted incident "{incident.id}". Skipping...')
                    continue

                incident.properties.alerts = self._get_alerts_by_id(*incident.properties.related_alert_ids,
                                                                    incident_number=incident.properties.case_number)
                for alert in incident.properties.alerts:
                    alert['Events'] = self._get_alert_events(alert) \
                        if alert.get('ProviderName') == 'ASI Scheduled Alerts' else []

            incidents.append(incident)

        return incidents

    def get_incidents_with_new_endpoint(self, creation_time=None, time_frame=None, statuses=None,
                                        severities=None, limit=None, asc=True, use_same_approach=False,
                                        existing_ids=None, next_page_link=None, connector_starting_time=None,
                                        python_process_timeout=None, scheduled_alerts_events_limit=None,
                                        incidents_alerts_limit_to_ingest=None, backlog_ids=None):
        """
        Get all Incidents including filters
        :param creation_time: {datetime} Get incidents with creationTimeUtc greater than passed datetime
        :param time_frame: {int} Time frame for which to show the statistics
        :param statuses: {list} Statuses of the incidents to look for
        :param severities: {list} Severities of the incidents to look for
        :param limit: {int} How much results should be fetched
        :param asc: {bool} Whether to bring incidents in ascending or descending order
        :param use_same_approach: {bool} Whether to use the same approach with event creation for all alert types
        :param existing_ids: {list} The incident ids that were already processed
        :param next_page_link: {str} The next page link, to use pagination across connector execution
        :param connector_starting_time: {int} Connector start time
        :param python_process_timeout: {int} The python process timeout
        :param scheduled_alerts_events_limit: {int} Limit for scheduled alerts events
        :param incidents_alerts_limit_to_ingest: {int} Limit for alerts per single Azure Sentinel incident
        :param backlog_ids: {dict} Backlog ids dict
        :return: {list} List of Incident objects
        """
        api_parameters = self._build_api_parameters(
            api_version=self._get_endpoint_version('incidents'),
            creation_time=creation_time,
            time_frame=time_frame,
            statuses=statuses,
            severities=severities,
            asc=asc,
            limit=limit
        )

        request_url, api_parameters = (next_page_link, None) if next_page_link else \
            (self._get_full_url('incidents'), api_parameters)

        response = self.session.get(request_url, params=api_parameters)

        self.validate_response(response)

        json_response = response.json()
        next_page_link = self.sentinel_parser.get_next_page_link(json_response)

        incidents_data = json_response.get('value')

        incidents = self.adjust_incidents_data(
            incidents_data=incidents_data,
            existing_ids=existing_ids,
            use_same_approach=use_same_approach,
            connector_starting_time=connector_starting_time,
            python_process_timeout=python_process_timeout,
            scheduled_alerts_events_limit=scheduled_alerts_events_limit,
            incidents_alerts_limit_to_ingest=incidents_alerts_limit_to_ingest,
            backlog_ids=backlog_ids
        )

        return incidents, next_page_link

    def adjust_incidents_data(self, incidents_data, existing_ids, use_same_approach,
                              connector_starting_time=None, python_process_timeout=None,
                              scheduled_alerts_events_limit=None, incidents_alerts_limit_to_ingest=None,
                              backlog_ids=None):
        """
        Update incident data
        :param incidents_data: {list} Incidents json
        :param existing_ids: {list} The incident ids that were already processed
        :param use_same_approach: {bool} Whether to use the same approach with event creation for all alert types
        :param connector_starting_time: {int} Connector start time
        :param python_process_timeout: {int} The python process timeout
        :param scheduled_alerts_events_limit: {int} Limit for scheduled alerts events
        :param incidents_alerts_limit_to_ingest: {int} Limit for alerts per single Azure Sentinel incident
        :param backlog_ids: {dict} Backlog ids dict
        return {list} List of Incident objets
        """
        incidents = []
        fetched_incidents = []
        MicrosoftAzureSentinelCommon.raise_if_timeout(connector_starting_time, python_process_timeout)
        for incident_data in incidents_data:
            incident = self.sentinel_parser.build_siemplify_incident_obj(incident_data)
            fetched_incidents.append(incident)

        MicrosoftAzureSentinelCommon.raise_if_timeout(connector_starting_time, python_process_timeout)

        filtered_incidents = self.sentinel_common.filter_old_ids(fetched_incidents, existing_ids)

        for incident in filtered_incidents:
            incident.properties.alerts = self.adjust_incidents_alerts_data(
                incident=incident,
                connector_starting_time=connector_starting_time,
                python_process_timeout=python_process_timeout,
                incidents_alerts_limit_to_ingest=incidents_alerts_limit_to_ingest,
                use_same_approach=use_same_approach,
                scheduled_alerts_events_limit=scheduled_alerts_events_limit,
                backlog_ids=backlog_ids
            )
            incidents.append(incident)

        return sorted(incidents, key=lambda _alert: _alert.properties.created_time_unix)

    def adjust_incidents_alerts_data(self, incident, connector_starting_time, python_process_timeout,
                                     incidents_alerts_limit_to_ingest, use_same_approach, scheduled_alerts_events_limit,
                                     backlog_ids):
        """
        Get and adjust incident alerts data
        :param incident: {Incident} Incidents object
        :param use_same_approach: {bool} Whether to use the same approach with event creation for all alert types
        :param connector_starting_time: {int} Connector start time
        :param python_process_timeout: {int} The python process timeout
        :param scheduled_alerts_events_limit: {int} Limit for scheduled alerts events
        :param incidents_alerts_limit_to_ingest: {int} Limit for alerts per single Azure Sentinel incident
        :param backlog_ids: {dict} Backlog ids dict
        return {list} List of Incident objets
        """
        MicrosoftAzureSentinelCommon.raise_if_timeout(connector_starting_time, python_process_timeout)
        incident.properties.alerts = self.get_incident_alerts_by_id(incident.name)
        incident_alerts = []

        for alert in incident.properties.alerts:
            MicrosoftAzureSentinelCommon.raise_if_timeout(connector_starting_time, python_process_timeout)
            if len(incident_alerts) >= incidents_alerts_limit_to_ingest:
                self.logger.info(f"Incident's {incident.name} Alerts Limit to Ingest was reached,"
                                 f" no more alerts will be processed.")
                break

            if not use_same_approach and alert.properties.product_component_name in ALERT_TYPES_WITH_EVENTS:
                MicrosoftAzureSentinelCommon.raise_if_timeout(connector_starting_time, python_process_timeout)
                alerts_with_old_api = self._get_alerts_by_id(alert.properties.system_alert_id,
                                                             incident_number=incident.properties.incident_number)

                if alerts_with_old_api:
                    incident_alerts.extend(alerts_with_old_api)

                    for scheduled_alert in alerts_with_old_api:
                        MicrosoftAzureSentinelCommon.raise_if_timeout(connector_starting_time,
                                                                      python_process_timeout)
                        try:
                            scheduled_alert['Events'] = self._get_alert_events(scheduled_alert,
                                                                               scheduled_alerts_events_limit)
                        except Exception:
                            scheduled_alert['Events'] = []
                            self.logger.error(
                                f"Failed to process Azure Sentinel Scheduled Alert with id {incident.name} and "
                                f"incident number {incident.properties.incident_number}! Query field of the "
                                f"affected alert: \"{json.loads(scheduled_alert.get('ExtendedProperties')).get('Query')}\"")
                    continue
                else:
                    self.logger.error(f"Failed to fetch incident {incident.properties.incident_number} scheduled "
                                      f"or NRT alerts. Will send it to or leave it in backlog.")
            else:
                MicrosoftAzureSentinelCommon.raise_if_timeout(connector_starting_time, python_process_timeout)

                if len(incident.properties.alerts) == 1:
                    alert.entities = self.get_incident_entities(alert.properties.system_alert_id,
                                                                incident.properties.incident_number,
                                                                incident.name,
                                                                backlog_ids)
                else:
                    alert.entities = self.get_alert_entities(alert.properties.system_alert_id,
                                                             incident.properties.incident_number,
                                                             incident.name,
                                                             backlog_ids)
                incident_alerts.append(alert)

        return incident_alerts

    def get_incident_alerts_by_id(self, incident_id):
        """
        Get Azure Sentinel alerts related to  specific incident.
        :param incident_id: {str} ID of the incident
        :return: {list} List of Alert objects
        """
        url = '{}{}'.format(self.base_url, API_ENDPOINTS['GET_INCIDENT_ALERTS']['URL'].format(incident_name=incident_id))
        api_parameters = self._build_api_parameters(api_version=API_ENDPOINTS['GET_INCIDENT_ALERTS']['VERSION'])

        response = self.session.post(url, params=api_parameters)
        self.validate_response(response)
        alerts_data = response.json().get('value', [])
        return [self.sentinel_parser.build_siemplify_incident_alert_obj(alert_data) for alert_data in alerts_data] \
            if alerts_data else []

    def get_alert_entities(self, alert_id, incident_number, incident_id, backlog_ids):
        """
        Get Azure Sentinel  entities related to  specific alert from the incident.
        :param alert_id: {str} Id of the alert
        :param incident_number: {int} The number of the incident
        :param incident_id: {str} ID of the incident
        :param backlog_ids: {dict} Backlog ids dict
        :return: {list} List of Entity objects
        """
        url = '{}{}'.format(self.base_url, API_ENDPOINTS['GET_ALERT_ENTITIES']['URL'].format(alert_id=alert_id))
        params = {
            'api-version': API_ENDPOINTS['GET_ALERT_ENTITIES']['VERSION']
        }
        payload = {
            'expansionId': API_ENDPOINTS['GET_ALERT_ENTITIES']['DEFAULT_EXPANSION_ID']
        }

        response = self.session.post(url, json=payload, params=params)

        try:
            self.validate_response(response)
        except Exception as e:
            if isinstance(e, MicrosoftAzureSentinelTimeoutError):
                raise 
            if incident_number not in backlog_ids:
                self.logger.error("Failed to fetch alert {} entities. Will send it to or leave it in backlog. Incident {}".
                                  format(alert_id, incident_id))
            return None

        response_data = response.json().get('value', {})
        edges_data = response_data.get('edges', [])
        return [self.sentinel_parser.build_siemplify_alert_entity_obj(
            entity_data, next((edge.get('additionalData', {}) for edge in edges_data if edge.get('targetEntityId')
                               == entity_data.get('id')), None)) for entity_data in response_data.get('entities', [])]

    def get_incident_by_number(self, incident_number, connector_starting_time, python_process_timeout,
                               incidents_alerts_limit_to_ingest, use_same_approach=False,
                               scheduled_alerts_events_limit=None, backlog_ids=None,):
        """
        Get incident by its number
        :param incident_number: {int} The number of the incident
        :param connector_starting_time: {int} Connector start time
        :param python_process_timeout: {int} The python process timeout
        :param scheduled_alerts_events_limit: {int} Limit for scheduled alerts events
        :param incidents_alerts_limit_to_ingest: {int} Limit for alerts per single Azure Sentinel incident
        :param use_same_approach: {bool} Whether to use the same approach with event creation for all alert types
        :param scheduled_alerts_events_limit: {int} Limit for scheduled alerts events
        :param backlog_ids: (dict} Backlog IDs dict
        :return: Incident
        """
        params = {
            'api-version': self._get_endpoint_version('incidents'),
            QueryFilterKeyEnum.FILTER.value: 'properties/incidentNumber eq {}'.format(incident_number)
        }
        response = self.session.get(self._get_full_url('incidents'), params=params)
        self.validate_response(response)
        incident_data = response.json().get('value')

        if not incident_data:
            raise MicrosoftAzureSentinelManagerError('Incident with number {} was not found'.format(incident_number))

        incident = self.sentinel_parser.build_siemplify_incident_obj(incident_data[0])
        incident.properties.alerts = self.adjust_incidents_alerts_data(
                incident=incident,
                connector_starting_time=connector_starting_time,
                python_process_timeout=python_process_timeout,
                incidents_alerts_limit_to_ingest=incidents_alerts_limit_to_ingest,
                use_same_approach=use_same_approach,
                scheduled_alerts_events_limit=scheduled_alerts_events_limit,
                backlog_ids=backlog_ids
            )
        return incident

    def get_incident_statistics(self, time_frame=None):
        # type: (int) -> object
        """
        Get Incident statistic
        @param time_frame: Time frame for which to show the statistics
        @return: IncidentStatistic instance
        """
        params = {'api-version': self._get_endpoint_version('incident_aggregation')}

        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_frame)

        params[QueryFilterKeyEnum.START_TIME.value] = start_time.strftime(TIME_FORMAT)

        params[QueryFilterKeyEnum.END_TIME.value] = end_time.strftime(TIME_FORMAT)

        response = self.session.get(self._get_full_url('incident_aggregation'), params=params)
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_incident_statistic_obj(response.json())

    def get_incident_by_incident_number(self, incident_number):
        return self._get_incident_by_incident_number(incident_number=incident_number)

    def add_comment_to_incident(self, incident_name, comment):
        """
        Add Comment to the incident
        @param incident_name: {str} Incident number
        @param comment: {str} comment to add to Incident
        @return: {Incident} updated incident details
        """
        params = {'api-version': self._get_endpoint_version('incident_comment')}
        json_payload = {
            'properties': {
                'message': comment
            }
        }

        response = self.session.put(
            self._get_full_url('incident_comment', incident_number=incident_name, incident_comment_id=uuid.uuid4()),
            params=params,
            json=json_payload
        )
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_incident_obj(raw_json=response.json())

    def _get_incident_by_incident_number(self, incident_number):
        """
        Update existing Incident
        @param incident_number: {str} Incident number
        @return: {Incident} instance
        """
        filter_query = QueryBuilder([
            Condition(field='properties/incidentNumber', operator='eq', value=incident_number)
        ])
        params = {
            'api-version': self._get_endpoint_version('incidents'),
            QueryFilterKeyEnum.FILTER.value: str(filter_query)
        }

        response = self.session.get(self._get_full_url('incidents'), params=params)
        self.validate_response(response)

        incident = self.sentinel_parser.build_results(response.json(), 'build_siemplify_incident_obj')

        if incident:
            return incident[0]

    def update_incident_labels(self, incident_number, labels=None):
        """
        Update existing Incident
        @param incident_number: {str} Incident by number to update
        @param labels: {list} Incident labels
        @return: Updated Incident
        """
        incident = self._get_incident_by_incident_number(incident_number)

        url = self._get_full_url('incident', incident_name=incident.name)
        params = {
            'api-version': self._get_endpoint_version('incident'),
        }
        json_payload, updated_labels, not_updated_labels = incident.update_labels(labels)

        response = self.session.put(url, params=params, json=json_payload)
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_incident_obj(response.json()), updated_labels, not_updated_labels

    def update_incident(self, incident_number, title=None, status=None, severity=None, description=None,
                        assigned_to=None, close_reason=None, closing_comment=None):
        # type: (int, str, str, str, str, str, str, list) -> object
        """
        Update existing Incident
        @param incident_number: Number of Incident to be updated
        @param title: Incident title
        @param status: Incident status
        @param severity: Incident severity
        @param description: Incident description
        @param assigned_to: Incident assignee
        @param close_reason: Incident close reason
        @param closing_comment: Closing comment
        @return: Updated Incident
        """
        incident = self._get_incident_by_incident_number(incident_number)
        params = {
            'api-version': self._get_endpoint_version('incident')
        }
        json_payload = self.update_incident_payload(incident.get_original_data(), title, status, severity, description,
                                                    assigned_to, close_reason, closing_comment)
        response = self.session.put(
            self._get_full_url('incident', incident_name=incident.name),
            params=params,
            json=json_payload
        )
        self.validate_response(response)

        return self.sentinel_parser.build_siemplify_incident_obj(response.json())

    def update_incident_payload(self, data, title=None, status=None, severity=None, description=None, assigned_to=None,
                                close_reason=None, closing_comment=None):
        """
        Update existing Incident
        @param data: Incident data
        @param title: Incident title
        @param status: Incident status
        @param severity: Incident severity
        @param description: Incident description
        @param assigned_to: Incident assignee
        @param close_reason: Incident close reason
        @param closing_comment: Closing comment
        @return: {dict} Updated Incident data
        """
        if title:
            data['properties']['title'] = title

        if status and status not in ADDITIONAL_DEFAULT_FOR_VALIDATION:
            data['properties']['status'] = status
            # In case of when changing from close status to other
            if status != CLOSED:
                data['properties']['classification'] = ''
                data['properties']['classificationReason'] = ''
                data['properties']['classificationComment'] = ''

        if severity and severity not in ADDITIONAL_DEFAULT_FOR_VALIDATION:
            data['properties']['severity'] = severity

        if description:
            data['properties']['description'] = description

        if assigned_to:
            data['properties']['owner']['assignedTo'] = assigned_to

        if close_reason and close_reason not in ADDITIONAL_DEFAULT_FOR_VALIDATION:
            classification, classification_reason = self.modify_classification(close_reason)
            data['properties']['classification'] = classification
            data['properties']['classificationReason'] = classification_reason
            data['properties']['classificationComment'] = closing_comment or ''

        return data

    def modify_classification(self, reason):
        """
        Update incident reason
        @param reason: {str} Incident closing reason
        :return classification: {str} updated closing reason
        """
        classifications_list = reason.split(CLOSE_REASON_DELIMITER)
        reason = classifications_list[-1].replace(' ', '').capitalize() if len(classifications_list) > 1 else ''

        return classifications_list[0].replace(' ', ''), reason

    def _get_alerts_by_id(self, *ids, incident_number=None):
        # type: (str) -> list
        """
        Get all alerts by provided ids
        @param ids: IDs of the alerts
        @param incident_number: Number of the incident
        @return: Alerts
        """
        query = 'SecurityAlert | summarize arg_max(TimeGenerated, *) by SystemAlertId | where SystemAlertId in({})' \
            .format(', '.join([f'\"{x}\"' for x in ids]))

        try:
            return self.run_kql_query(query=query).to_json()
        except MicrosoftAzureSentinelBadRequestError:
            if incident_number:
                self.logger.error(
                    f"Incident {incident_number} was skipped because it didn't had SystemAlertID value present on the "
                    'time of ingestion')
                return []
            raise

    def _get_alert_events(self, alert, limit=None):
        # type: (dict) -> list
        """
        Get event list for alert
        @param alert: Alert
        @param limit {int}: Limit for results
        @return: List of Events
        """
        extended_properties = json.loads(alert.get('ExtendedProperties'))
        start_time = convert_string_to_datetime(extended_properties.get('Query Start Time UTC'), "UTC")\
            .strftime(TIME_FORMAT)
        end_time = convert_string_to_datetime(extended_properties.get('Query End Time UTC'), "UTC")\
            .strftime(TIME_FORMAT)

        query = extended_properties.get('Query')
        timespan = '{}/{}'.format(start_time, end_time)

        return self.run_kql_query(query=query, timespan=timespan, limit=limit).to_json()

    @staticmethod
    def _build_api_parameters(api_version=DEFAULT_API_VERSION, statuses=None, time_frame=None, severities=None,
                              case_number=None, start_time=None, end_time=None, limit=None, asc=False, timespan=None,
                              creation_time=None):
        # type: (str, list, int, list, int, str, str, int, bool, str, datetime) -> object
        """
        Method to build api parameters in URL
        @param api_version: API VERSION
        @param statuses: Statuses
        @param time_frame: Time Frame
        @param severities: Severities
        @param case_number: Case Number
        @param start_time: Start Time
        @param end_time: End Time
        @param limit: Limit
        @param asc: Asc
        @param timespan: Time Span
        @param creation_time: Search for incidents with createdTimeUtc greater than given datetime
        @return: API parameters
        """
        params = {'api-version': api_version}
        filter_params = []

        if case_number:
            filter_params.append('properties/caseNumber eq {}'.format(case_number))

        if creation_time:
            filter_params.append('properties/createdTimeUtc ge {}'.format(creation_time.strftime(TIME_FORMAT)))

        elif time_frame:
            time = datetime.utcnow() - timedelta(hours=time_frame)
            filter_params.append('properties/createdTimeUtc ge {}'.format(time.strftime(TIME_FORMAT)))

        if statuses:
            statuses_filter_group = " or ".join(["properties/status eq '{}'".format(x) for x in statuses])
            filter_params.append("({})".format(statuses_filter_group))

        if severities:
            severities_filter_group = " or ".join(["properties/severity eq '{}'".format(x) for x in severities])
            filter_params.append("({})".format(severities_filter_group))

        # Apply filtering in oData format

        if filter_params:
            params['$filter'] = " and ".join(filter_params)

        if asc:
            params['$orderBy'] = 'properties/createdTimeUtc asc'

        if limit:
            params['$top'] = limit

        if start_time:
            params['startTime'] = start_time

        if end_time:
            params['endTime'] = end_time

        if timespan:
            params['timespan'] = timespan

        return params

    @staticmethod
    def _filter_alert_rules(alert_rules, severities=None, types=None, tactics=None, only_enabled_rules=False, limit=None):
        # type: (list, list, list, list, bool, int) -> [object]
        """
        Client-Side alert rules filtering
        @param alert_rules: Alert Rules before filtration
        @param severities: Severities to filter
        @param types: Types to filter
        @param tactics: Tactics to filter
        @param only_enabled_rules: Filter only enabled Alert Rules
        @param limit: Alert Rules to return
        @return: Filtered Alert Rules
        """
        filtered_alert_rules = []

        for alert_rule in alert_rules:
            conditions = []

            if severities:
                conditions += [
                    alert_rule.properties and
                    alert_rule.properties.severity and
                    alert_rule.properties.severity in severities
                ]

            if types:
                conditions += [
                    alert_rule.kind and
                    alert_rule.kind in types
                ]

            if tactics:
                conditions += [
                    alert_rule.properties and
                    alert_rule.properties.tactics and
                    any([tactic in tactics for tactic in alert_rule.properties.tactics])
                ]

            if only_enabled_rules:
                conditions += [
                    alert_rule.properties and
                    alert_rule.properties.enabled
                ]

            if all(conditions):
                filtered_alert_rules.append(alert_rule)

        return filtered_alert_rules[:limit]

    @staticmethod
    def _filter_custom_hunting_rules(custom_hunting_rules, names=None, tactics=None):
        # type: (list, list, list) -> [object]
        """
        Client-Side Custom Hunting Rules filtering
        @param custom_hunting_rules: Custom Hunting Rules before filtration
        @param names: Names to filter
        @param tactics: Tactics to filter
        @return: Filtered Custom Hunting Rule
        """
        filtered_custom_hunting_rules = []

        for custom_hunting_rule in custom_hunting_rules:
            conditions = []

            if names:
                conditions += [
                    custom_hunting_rule.properties and
                    custom_hunting_rule.properties.display_name and
                    custom_hunting_rule.properties.display_name in names
                ]

            if tactics:
                conditions += [
                    custom_hunting_rule.properties and
                    custom_hunting_rule.properties.tactics and
                    any([tactic in tactics for tactic in custom_hunting_rule.properties.tactics])
                ]

            if all(conditions):
                filtered_custom_hunting_rules.append(custom_hunting_rule)

        return filtered_custom_hunting_rules

    @staticmethod
    def validate_login_response(response, error_msg="An error occurred"):
        # type: (requests.Response, str) -> None
        """
        Login Response Validation
        @param response: API Response
        @param error_msg: Error message to change raised one
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise MicrosoftAzureSentinelManagerError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.json().get("error_description", response.content)
                )
            )

    @staticmethod
    def validate_iso8601_duration(duration):
        # type: (str) -> None or MicrosoftAzureSentinelValidationError
        """
        Validate iso8601 duration
        @param duration: Duration in ISO8601 format
        """
        if not duration:
            return

        try:
            isodate.parse_duration(duration)
        except isodate.ISO8601Error:
            raise MicrosoftAzureSentinelValidationError(f'Time duration format \"{duration}\" is invalid')

    @classmethod
    def validate_duration(cls, duration):
        try:
            if not duration:
                return

            duration = isodate.parse_duration(duration)

            # In case we are using more than month duration, isodate.parse_duration returns Duration type
            if not isinstance(duration, timedelta):
                # Start time to use totimedelta function to calculate days in month to properly get total_seconds
                duration = duration.totimedelta(datetime.utcnow())

            if not MIN_PT_DURATION.total_seconds() <= duration.total_seconds() <= MAX_PT_DURATION.total_seconds():
                raise MicrosoftAzureSentinelValidationError(
                    f'Duration can be only between {MIN_PT_DURATION} and {MAX_PT_DURATION}\n')
        except isodate.ISO8601Error:
            raise MicrosoftAzureSentinelValidationError('Time duration format \"{}\" is invalid'.format(duration))

    @classmethod
    def validate_sequence(cls, items, default, sec_name):
        # type: (list, list, str) -> None or MicrosoftAzureSentinelValidationError
        """
        Validate if statuses are a possible values
        @param items: items ti validate
        @param default: acceptable items
        @param sec_name: acceptable items
        """
        if not items:
            return

        items = set(items)
        default_statuses = set(default)
        wrong_statuses = items ^ default_statuses & items
        if wrong_statuses:
            raise MicrosoftAzureSentinelValidationError(
                f'Wrong {sec_name} {convert_list_to_comma_separated_string(wrong_statuses)}.\nPossible values '
                f'are {convert_list_to_comma_separated_string(default_statuses)}')

    @classmethod
    def validate_statuses(cls, statuses, additional_defaults=None):
        cls.validate_sequence(statuses, DEFAULT_STATUSES + (additional_defaults or []), 'statuses')

    @classmethod
    def validate_incident_statuses(cls, statuses, additional_defaults=None):
        cls.validate_sequence(statuses, DEFAULT_UPDATE_INCIDENT_STATUSES + (additional_defaults or []), 'statuses')

    @classmethod
    def validate_severities(cls, severities, additional_defaults=None):
        cls.validate_sequence(severities, DEFAULT_SEVERITIES + (additional_defaults or []), 'severities')

    @classmethod
    def validate_alert_rule_severities(cls, severities, additional_defaults=None):
        cls.validate_sequence(severities, DEFAULT_ALERT_RULE_SEVERITIES + (additional_defaults or []), 'severities')

    @classmethod
    def validate_tactics(cls, tactics, additional_defaults=None):
        cls.validate_sequence(tactics, DEFAULT_TACTICS + (additional_defaults or []), 'tactics')

    @classmethod
    def validate_trigger_operators(cls, trigger_operators, additional_defaults=None):
        cls.validate_sequence(trigger_operators, DEFAULT_TRIGGER_OPERATORS + (additional_defaults or []), 'trigger')

    @classmethod
    def validate_close_reasons(cls, close_reasons, additional_defaults=None):
        cls.validate_sequence(close_reasons, DEFAULT_CLOSE_REASONS + (additional_defaults or []), 'close_reasons')

    # @TODO remove after refactor
    @staticmethod
    def convert_comma_separated_to_list(comma_separated):
        # type: (str) -> list
        """
        Convert comma-separated string to list
        @param comma_separated: String with comma-separated values
        @return: List of values
        """
        return [item.strip() for item in comma_separated.split(',')] if comma_separated else []

    @staticmethod
    def join_validation_errors(validation_errors):
        # type: (list) -> str
        """
        Join validation errors list to one string
        @param validation_errors: Validation error messages list
        """
        return '\n'.join(validation_errors)

    @staticmethod
    def convert_list_to_comma_separated_string(iterable):
        # type: (list or set) -> str
        """
        Convert list to comma separated string
        @param iterable: List or Set to covert
        """
        return ', '.join(iterable)

    def get_incident_entities(self, alert_id, incident_number, incident_id, backlog_ids):
        """
        Get Azure Sentinel entities related to specific incident.
        :param alert_id: {str} Id of the alert
        :param incident_number: {int} The number of the incident
        :param incident_id: {str} ID of the incident
        :param backlog_ids: {dict} Backlog ids dict
        :return: {list} List of Entity objects
        """
        url = '{}{}'.format(self.base_url, API_ENDPOINTS['GET_INCIDENT_ENTITIES']['URL'].format(incident_id=incident_id))

        params = {
            'api-version': API_ENDPOINTS['GET_INCIDENT_ENTITIES']['VERSION']
        }

        response = self.session.post(url, params=params)

        try:
            self.validate_response(response)
        except Exception as e:
            if isinstance(e, MicrosoftAzureSentinelTimeoutError):
                raise
            if incident_number not in backlog_ids:
                self.logger.error("Failed to fetch alert {} entities. Will send it to or leave it in backlog. Incident {}".
                                  format(alert_id, incident_id))
            return None

        response_data = response.json()
        edges_data = response_data.get('edges', [])

        return [self.sentinel_parser.build_siemplify_alert_entity_obj(
                    entity_data,
                    next((edge.get('additionalData', {}) for edge in edges_data
                         if edge.get('targetEntityId') == entity_data.get('id')), None)
                ) for entity_data in response_data.get('entities', [])]
