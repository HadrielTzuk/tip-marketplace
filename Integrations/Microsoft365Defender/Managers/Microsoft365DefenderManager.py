import datetime
from urllib.parse import urljoin
from typing import Dict, List, Any, Set, Optional
import requests
from TIPCommon import filter_old_alerts, utc_now, is_approaching_timeout
from SiemplifyUtils import convert_string_to_datetime
from UtilsManager import validate_response
from datamodels import Incident
from Microsoft365DefenderParser import Microsoft365DefenderParser
from Microsoft365DefenderExceptions import (
    NotFoundItemException,
    Microsoft365DefenderException,
    APIPermissionError,
    TooManyRequestsError
)
from constants import (
    ENDPOINTS,
    TOKEN_PAYLOAD,
    FILTER_TIME_FORMAT,
    ACCESS_TOKEN_URL,
    DEFAULT_RESULTS_LIMIT,
    AND_OPERATOR,
    INCIDENTS_LIMIT_PER_REQUEST,
    ALERTS_LIMIT_PER_REQUEST,
    ALERT_ID_KEY,
    GRAPH_API_SCOPE,
    FETCHING_TIMEOUT_TRESHOLD
)


class Microsoft365DefenderManager:
    def __init__(self, api_root, tenant_id, client_id, client_secret, verify_ssl,
                 microsoft_graph_url="https://graph.microsoft.com", siemplify=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} API root of the Microsoft 365 Defender instance.
        :param tenant_id: {str} Microsoft 365 Defender account tenant ID.
        :param client_id: {str} Microsoft 365 Defender account client ID.
        :param client_secret: {str} Microsoft 365 Defender account client secret.
        :param verify_ssl: {bool} If enabled, verify the SSL certificate for the connection to the server is valid.
        :param microsoft_graph_url: {str} Microsoft Graph API Root
        :param siemplify: Siemplify Connector Executor.
        """
        self.api_root = api_root
        self.microsoft_graph_url = microsoft_graph_url
        self.siemplify = siemplify
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.parser = Microsoft365DefenderParser()
        self.access_token = self._generate_token(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            verify=verify_ssl
        )
        self.graph_api_token = self._generate_token(
            client_id=client_id,
            client_secret=client_secret,
            tenant_id=tenant_id,
            verify=verify_ssl,
            scope=GRAPH_API_SCOPE
        )
        self._update_headers()
        self.use_graph_api_for_alerts = True
        self.too_many_request_last_occurrence = None


    def _update_headers(self, use_graph_api: bool = False):
        token = self.access_token
        if use_graph_api:
            token = self.graph_api_token

        self.session.headers.update({
            "Authorization": "Bearer {}".format(token),
            "Content-Type": "application/json"
        })

    @staticmethod
    def _generate_token(client_id, client_secret, tenant_id, verify=True, scope=None):
        """
        Request access token (Valid for 60 min)
        :param client_id: {str} Microsoft 365 Defender account client ID.
        :param client_secret: {str} Microsoft 365 Defender account client secret.
        :param tenant_id: {str} Microsoft 365 Defender Tenant ID.
        :param verify: {bool} Whether to verify SSL certificates
        :param scope: {str} Scope for auth token
        :return: Access token
        """
        TOKEN_PAYLOAD["client_id"] = client_id
        TOKEN_PAYLOAD["client_secret"] = client_secret
        if scope is not None:
            TOKEN_PAYLOAD["scope"] = scope
        request_url = ACCESS_TOKEN_URL.format(tenant_id=tenant_id)
        response = requests.post(request_url, data=TOKEN_PAYLOAD, verify=verify)
        validate_response(response, 'Unable to generate access token for Microsoft 365 Defender')

        return response.json().get('access_token')

    def _get_full_url(self, url_id, use_graph=False, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root if not use_graph else self.microsoft_graph_url, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        """
        request_url = self._get_full_url("list_incidents")
        params = self._build_api_params(
            start_time=utc_now(),
            limit=1
        )
        response = self.session.get(request_url, params=params)
        validate_response(response)

    def update_incident(self, incident_id, status: Optional[str] = None, classification: Optional[str] = None,
                        determination: Optional[str] = None, assign_to: Optional[str] = None,
                        comment: Optional[str] = None):
        """
        Update incident in Microsoft 365 Defender
        :param incident_id: {int} The id of the incident to update
        :param status: {str} Status to set for the incident
        :param classification: {str} Classification to set for the incident
        :param determination: {str} Determination to set for the incident
        :param assign_to: {str} To whom to assign the incident
        :param comment: {str} Comment to add to incident
        """
        request_url = self._get_full_url("update_incident", incident_id=incident_id)
        payload = {}
        if status:
            payload["status"] = status
        if classification:
            payload["classification"] = classification
        if determination:
            payload["determination"] = determination
        if assign_to:
            payload["assignedTo"] = assign_to
        if comment:
            payload["comment"] = comment

        response = self.session.patch(request_url, json=payload)

        if response.status_code == 404:
            raise NotFoundItemException(f"incident \"{incident_id}\" wasn't found in Microsoft 365 Defender")

        validate_response(response)

    def get_incidents(self, existing_incidents: Dict[str, Any], limit: int, start_time: datetime.datetime,
                      end_time: datetime.datetime, statuses: List[str], detection_source: List[str],
                      service_source: List[str], connector_starting_time: int, python_process_timeout: int):
        """
        Get incidents
        :param existing_incidents: {dict} Dict with existing incident / alerts data
        :param limit: {int} The limit for results
        :param start_time: {datetime} The start datetime from where to fetch
        :param end_time: {datetime} The end datetime to fetch incidents up to
        :param statuses: {List[str]} List of statuses of incidents to fetch
        :param detection_source: {List[str]} List of detection sources to fetch when using graph api
        :param service_source: {List[str]} List of service sources to fetch when using graph api
        :param connector_starting_time: {int} Connector starting time in UNIX
        :param python_process_timeout: {int} Python process timeout in secs
        :return: {list} The list of filtered Incident objects
        """

        if self.siemplify is None:
            raise Microsoft365DefenderException("Please initialize manager with siemplify parameter filled")

        request_url = self._get_full_url("list_incidents")
        params = self._build_api_params(
            start_time=start_time,
            end_time=end_time,
            additional_filters={"status": statuses}
        )

        incidents_data = self._paginate_results(
            method='GET',
            url=request_url,
            params=params
        )
        filtered_incidents = []

        incident_data_sorted = sorted(incidents_data, key=lambda incident: incident['lastUpdateTime'])

        for incident_data in incident_data_sorted:
            if len(filtered_incidents) >= limit:
                break

            if is_approaching_timeout(connector_starting_time=connector_starting_time,
                                      python_process_timeout=python_process_timeout,
                                      timeout_threshold=FETCHING_TIMEOUT_TRESHOLD):
                self.siemplify.LOGGER.info("Timeout is approaching. Connector will gracefully exit")
                break

            incident = self.parser.build_incident_object(raw_data=incident_data)

            existing_alerts = set(existing_incidents.get(str(incident.incident_id), []))

            try:
                self.siemplify.LOGGER.info(f"Fetching alerts for incident - {incident.incident_id}")
                incident.alerts = self.get_incident_alerts(
                    incident=incident,
                    incidents_start_time=start_time,
                    existing_alerts=existing_alerts,
                    detection_source=detection_source,
                    service_source=service_source
                )
            except TooManyRequestsError as err:
                self.siemplify.LOGGER.error('Too many queries were executed to Graph alerts API. Rate limit is reached. '
                                            'The connector will stop fetching new alerts and process only fully fetched incidents.')
                self.too_many_request_last_occurrence = err.encountered_at
                break

            if incident.alerts or (incident.alerts is None and str(incident.incident_id) not in existing_incidents):
                filtered_incidents.append(incident)

        return filtered_incidents

    def get_incident_alerts(self, incident: Incident, incidents_start_time: datetime.datetime,
                            existing_alerts: Set[str], detection_source: List[str], service_source: List[str]):
        """
        Get alerts from incidents either from its data or from new Graph API
        :param incident: {Incident} Parsed incident data
        :param incidents_start_time: {datetime} The start datetime from where to fetch
        :param existing_alerts: {Set[str]} Existing alerts ids set to filter our already fetched
        :param detection_source: {List[str]} List of detection sources to fetch alerts when using graph api
        :param service_source: {List[str]} List of service sources to fetch alerts when using graph api
        :return: {list} The list of filtered Incident objects
        """

        alerts = [
            self.parser.build_alert_object(raw_data=raw_json)
            for raw_json in incident.raw_data.get('alerts', [])
        ]
        alerts_start_time = incidents_start_time

        if not alerts:
            return None

        if self.use_graph_api_for_alerts:
            self._update_headers(use_graph_api=True)

            try:

                incident_last_update_time_shifted = (
                    convert_string_to_datetime(incident.last_update_time)
                    - datetime.timedelta(hours=1)
                )
                alerts_start_time = (
                    incidents_start_time
                    if incidents_start_time < incident_last_update_time_shifted
                    else incident_last_update_time_shifted
                )

                request_uri = self._get_full_url("get_alerts", use_graph=True)
                additional_filters = {
                    "incidentId": incident.incident_id,
                    "detectionSource": detection_source,
                    "serviceSource": service_source
                }
                params = self._build_api_params(
                    created_time=alerts_start_time,
                    additional_filters=additional_filters
                )

                alerts_data = self._paginate_results(
                    method='GET',
                    url=request_uri,
                    params=params,
                    limit_per_request=ALERTS_LIMIT_PER_REQUEST
                )
                alerts = [
                    self.parser.build_alert_with_evidence_object(raw_data=raw_json)
                    for raw_json in alerts_data
                ]

            except APIPermissionError:
                self.siemplify.LOGGER.error(
                    "Application that is used for the connector doesn't have all of the necessary permissions. "
                    "Please check the documentation for more information. "
                    "The incidents will be processed based on only Defender 365 data."
                )
                self.use_graph_api_for_alerts = False
            finally:
                self._update_headers()

        alerts = filter_old_alerts(
            siemplify=self.siemplify,
            alerts=alerts,
            id_key=ALERT_ID_KEY,
            existing_ids=existing_alerts
        )
        self.siemplify.LOGGER.info(f"Fetching {len(alerts) if alerts is not None else 0} new alerts since {alerts_start_time}")

        return alerts

    def search_for_devices(self, table_names=None, start_time=None, end_time=None, user_query=None, fields=None,
                           sort_field=None, sort_order=None, limit=None, custom_query=None):
        """
        Search for devices

        Args:
            table_names (list): List of table names
            start_time (str): Start time for results
            end_time (str): End time for results
            user_query (str): User provided query to execute
            fields (str): Fields to return in results
            sort_field (str): Field to use for sorting
            sort_order (str): Order of sorting
            limit (int): Number of results to return
            custom_query (str): Query that is entirely provided by the user

        Returns:
            Tuple[list, str]: List of Device objects, final query string
        """
        request_url = self._get_full_url("execute_query")
        if custom_query:
            query = custom_query + f"| limit {limit}"
        else:
            query = self._build_request_query(
                table_names=table_names,
                start_time=start_time,
                end_time=end_time,
                user_query=user_query,
                fields=fields,
                sort_field=sort_field,
                sort_order=sort_order,
                limit=limit
            )
        payload = {
            "Query": query
        }
        response = self.session.post(request_url, json=payload)

        if response.status_code == 400:
            raise Microsoft365DefenderException(
                f"{response.json().get('error', {}).get('message') or response.content}"
            )

        validate_response(response)
        return self.parser.build_device_objects(response.json()), query

    def build_query_string(self, ip_key, hostname_key, hash_key, user_key, url_key, email_key, cross_entity_operator,
                           ip_entities, hostname_entities, hash_entities, user_entities, url_entities, email_entities):
        """
        Prepare the query string based on entities
        :param ip_key: {str} Key to use with IP entities
        :param hostname_key: {str} Key to use with Hostname entities
        :param hash_key: {str} Key to use with File Hash entities
        :param user_key: {str} Key to use with User entities
        :param url_key: {str} Key to use with URL entities
        :param email_key: {str} Key to use with Email Address entities
        :param cross_entity_operator: {str} Operator to use between entity types. Possible values: OR, AND.
        :param ip_entities: {list} List of IP entities to use in the query
        :param hostname_entities: {list} List of Hostname entities to use in the query
        :param hash_entities: {list} List of File Hash entities to use in the query
        :param user_entities: {list} List of User entities to use in the query
        :param url_entities: {list} List of URL entities to use in the query
        :param email_entities: {list} List of Email Address entities to use in the query
        :return: {str} The query string
        """
        queries = []

        if ip_key and ip_entities:
            queries.append(" or ".join([f"{ip_key} == \'{ip}\'" for ip in ip_entities]))

        if hostname_key and hostname_entities:
            queries.append(" or ".join([f"{hostname_key} == \'{hostname}\'" for hostname in hostname_entities]))

        if hash_key and hash_entities:
            queries.append(" or ".join([f"{hash_key} == \'{hash}\'" for hash in hash_entities]))

        if user_key and user_entities:
            queries.append(" or ".join([f"{user_key} == \'{user}\'" for user in user_entities]))

        if url_key and url_entities:
            queries.append(" or ".join([f"{url_key} == \'{url}\'" for url in url_entities]))

        if email_key and email_entities:
            queries.append(" or ".join([f"{email_key} == \'{email}\'" for email in email_entities]))

        query_string = ' | where '.join(queries) if cross_entity_operator == AND_OPERATOR else ' or '.join(queries)

        return f"| where {query_string}" if query_string else ""

    def _build_request_query(self, table_names, start_time, end_time, user_query, fields, sort_field, sort_order,
                             limit=DEFAULT_RESULTS_LIMIT):
        """
        Prepare the query string
        :param table_names: {list} List of table names
        :param start_time: {str} Start time for results
        :param end_time: {str} End time for results
        :param user_query: {str} User provided query to execute
        :param fields: {str} Fields to return in results
        :param sort_field: {str} Field to use for sorting
        :param sort_order: {str} Order of sorting
        :param limit: {int} Number of results to return
        """
        query = "union " if len(table_names) > 1 else ""
        query += f"{', '.join(table_names)}"
        query += f"| where Timestamp between(datetime({start_time}) .. datetime({end_time}))"

        if user_query:
            query += user_query

        if fields:
            query += f"| project {', '.join(fields)}"

        if sort_field:
            query += f"| top {limit} by {sort_field} {sort_order}"

        return query

    def _build_api_params(self, start_time=None, end_time=None, created_time=None, additional_filters=None, limit=None):
        """
        Create filtration dict
        :param start_time: Start time to fetch incidents from
        :param end_time: End time to fetch incidents to
        :param created_time: Start time to fetch alerts from
        :param additional_filters: Additional filters listed in dict
        :param limit: How much should be fetched
        :return: Dict of filters
        """
        if additional_filters is None:
            additional_filters = {}

        filter_params = []

        if start_time:
            filter_params.append('lastUpdateTime ge {}'.format(start_time.strftime(FILTER_TIME_FORMAT)))

        if end_time:
            filter_params.append('lastUpdateTime le {}'.format(end_time.strftime(FILTER_TIME_FORMAT)))

        if created_time:
            filter_params.append('createdDateTime ge {}'.format(created_time.strftime(FILTER_TIME_FORMAT)))

        for key, value in additional_filters.items():
            if not value:
                continue

            if isinstance(value, list):
                filter_value = " or ".join(f"{key} eq '{val}'" for val in value)
            else:
                filter_value = f"{key} eq '{value}'"
            filter_params.append(filter_value)

        params = {
            '$filter': " and ".join(filter_params) if filter_params else None,
            '$top': limit,
            '$skip': 0
        }

        return params

    def _paginate_results(self, method, url, params=None, body=None, start_offset=0, limit=None,
                          limit_per_request = INCIDENTS_LIMIT_PER_REQUEST, err_msg="Unable to get results"):
        """
        Paginate the results of a request
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param start_offset: {int} The start offset of the results to fetch
        :param limit: {int} The limit of the results to fetch
        :param limit_per_request: {int} The limit of the results to fetch on each page
        :param err_msg: {str} The message to display on error
        :return: {list} List of results
        """
        if params is None:
            params = {}

        params.update({
            "$skip": start_offset,
            "$top": limit_per_request
        })

        response = self.session.request(method, url, params=params, json=body)

        validate_response(response, err_msg)
        results = response.json().get("value", [])
        results_per_request = len(response.json().get("value", []))

        while True:
            if results_per_request < limit_per_request:
                break

            params.update({
                "skip": start_offset + len(results)
            })

            response = self.session.request(method, url, params=params, json=body)

            validate_response(response, err_msg)
            results_per_request = len(response.json().get("value", []))
            results.extend(response.json().get("value", []))

        return results
