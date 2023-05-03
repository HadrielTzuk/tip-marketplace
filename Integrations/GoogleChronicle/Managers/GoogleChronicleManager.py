# ============================================================================#
# title           :GoogleChronicleManager.py
# description     :This Module contain all Google Chronicle operations functionality
# author          :avital@siemplify.co
# date            :30-09-2020
# python_version  :3.7
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #
import copy
import json
import time
import requests
import datetime
from urllib.parse import urljoin
from random import randint
from time import sleep
from typing import List, Optional
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession

from GoogleChronicleParser import GoogleChronicleParser
import consts
import exceptions
import datamodels
import utils


# ============================= CLASSES ===================================== #


class GoogleChronicleManager(object):
    """
    Google Chronicle Manager
    """

    def __init__(self, type: str, project_id: str, private_key_id: str, private_key: str, client_email: str,
                 client_id: str, auth_uri: str, token_uri: str, auth_provider_x509_cert_url: str,
                 client_x509_cert_url: str, api_root: str = consts.API_URL, verify_ssl: bool = False,
                 siemplify_logger=None):
        self.api_root = api_root
        self.creds = {
            "type": type,
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": private_key,
            "client_email": client_email,
            "client_id": client_id,
            "auth_uri": auth_uri,
            "token_uri": token_uri,
            "auth_provider_x509_cert_url": auth_provider_x509_cert_url,
            "client_x509_cert_url": client_x509_cert_url
        }

        credentials = service_account.Credentials.from_service_account_info(info=self.creds, scopes=consts.SCOPES)
        self.session = AuthorizedSession(credentials)
        self.session.verify = verify_ssl
        self.parser = GoogleChronicleParser()
        self.siemplify_logger = siemplify_logger

    def test_connectivity(self) -> bool:
        """
        Test connectivity
        """
        try:
            self.list_iocs(start_time=utils.datetime_to_rfc3339(datetime.datetime.utcnow()), limit=1)
            return True
        except exceptions.GoogleChronicleManagerError as e:
            raise exceptions.GoogleChronicleManagerError(
                f"Unable to connect to Google Chronicle, please validate your credentials: {e}")

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        Args:
            url_id (str): The id of url
            kwargs (dict): Variables passed for string formatting
        Returns:
            (str): The full url
        """
        return urljoin(self.api_root, consts.ENDPOINTS[url_id].format(**kwargs))

    def list_iocs(self, start_time: str, limit: Optional[int] = consts.LIMIT, fallback_severity=None) \
            -> (bool, List[datamodels.IOC]):
        """
        List all of the IoCs discovered within your enterprise within the specified time range.
        If you receive the maximum number of IoCs you specified using the limit parameter (or 10,000, the default),
        there might still be more IoCs discovered in your Chronicle account.
        You might want to narrow the time range and issue the call again to ensure you have visibility on all possible
        IoCs.
        :param start_time: {str} Start time for your request. Enter time using the time standard defined in RFC 3339.
            Time is represented by the span of UTC time since Unix epoch 1970-01-01T00:00:00Z.
        :param limit: {int} Specify the maximum number of IoCs to return. You can specify between 1 and 10,000.
        :param fallback_severity: {str} fallback severity for alerts
        :return: {(bool, [datamodels.IOC])} Tuple of a flag whether there are more results, and a list of found IOCs
            within the time range.
        """
        request_url = f"{self.api_root}/v1/ioc/listiocs"
        response = self.session.get(request_url, params={
            "start_time": start_time,
            "page_size": limit
        })
        self.validate_response(response, "Unable to list IOCs")
        return response.json().get('response', {}).get('moreDataAvailable', False), [
            self.parser.build_siemplify_ioc_obj(ioc, fallback_severity) for ioc in
            response.json().get('response', {}).get('matches', [])]

    def list_assets(self, start_time: str, end_time: str, ip: Optional[str] = None,
                    domain: Optional[str] = None, file_hash: Optional[str] = None,
                    limit: Optional[int] = consts.LIMIT):  

        """
        For your enterprise, given the specified artifact, list all of the assets that accessed it within the specified
        time period, including the first and last time those assets accessed the artifact. This call returns a maximum
        of 100 assets per request. You can specify a narrower time period to reduce the number of assets returned.
        :param start_time: {str} Start time for your request. Enter time using the time standard defined in RFC 3339.
            Time is represented by the span of UTC time since Unix epoch 1970-01-01T00:00:00Z.
        :param end_time: {str} End time for your request. Enter time using the time standard defined in RFC 3339.
            Time is represented by the span of UTC time since Unix epoch 1970-01-01T00:00:00Z.
        :param ip: {str} Specify the ip indicator associated with the assets to filter by.
        :param domain: {str} Specify the domain indicator associated with the assets to filter by.
        :param ip: {str} Specify the file hash indicator associated with the assets to filter by.
        :param limit: {int} Specify the maximum number of assets to return. You can specify between 1 and 10,000.
        :return: {[datamodels.Asset]} List of found assets
            within the time range.
        """
        request_url = f"{self.api_root}/v1/artifact/listassets"
        params = {
            "start_time": start_time,
            "end_time": end_time,
            "page_size": limit
        }

        if sum([ip is not None, domain is not None, file_hash is not None]) > 1:
            # More than 1 artifacts was passed - invalid.
            raise exceptions.GoogleChronicleValidationError(
                "You can only specify a single artifact. "
                "The artifact indicator may either be a domain name, a destination IP address, or a file hash "
                "(one of MD5, SHA1, SHA256)."
            )
        elif ip:
            params["artifact.destination_ip_address"] = ip

        elif domain:
            params["artifact.domain_name"] = domain

        elif file_hash:
            params[utils.get_hash_type(file_hash)] = file_hash

        else:
            raise exceptions.GoogleChronicleValidationError(
                "You must specify at least one artifact. "
                "The artifact indicator may either be a domain name, a destination IP address, or a file hash "
                "(one of MD5, SHA1, SHA256)."
            )

        response = self.session.get(request_url, params=params)
        self.validate_response(response, "Unable to list assets")
        response_json = response.json()
        return response_json.get("uri", []), \
               [self.parser.build_siemplify_asset_obj(asset) for asset in response_json.get('assets', [])]

    def list_events(self, start_time: str, end_time: str, reference_time: str, ip: Optional[str] = None,
                    hostname: Optional[str] = None, mac: Optional[str] = None, limit: Optional[int] = consts.LIMIT,
                    event_types: Optional[str] = None):  

        """
        List all of the events discovered within your enterprise on a particular device within the specified time range.
        If you receive the maximum number of events you specified using the page_size parameter (or 10,000, the
        default), there might still be more events within your Chronicle account. You can narrow the time range and
        issue the call again to ensure you have visibility into all possible events.
        :param start_time: {str} Start time for your request. Enter time using the time standard defined in RFC 3339.
            Time is represented by the span of UTC time since Unix epoch 1970-01-01T00:00:00Z.
        :param end_time: {str} End time for your request. Enter time using the time standard defined in RFC 3339.
            Time is represented by the span of UTC time since Unix epoch 1970-01-01T00:00:00Z.
        :param reference_time: {str} Specify the reference time for the asset you are investigating.
            Enter time using the time standard defined in RFC 3339. Time is represented by the span of UTC time since
            Unix epoch 1970-01-01T00:00:00Z.
        :param ip: {str} Specify the ip indicator for the asset you are investigating.
        :param hostname: {str} Specify the hostname indicator for the asset you are investigating.
        :param mac: {str} Specify the mac indicator for the asset you are investigating.
        :param limit: {int} Specify the maximum number of events to return. You can specify between 1 and 10,000.
        :param event_types: {list} List of event types to return.
        :return: {[datamodels.Event]} List of found events
            within the time range.
        """
        request_url = f"{self.api_root}/v1/asset/listevents"
        params = {
            "start_time": start_time,
            "end_time": end_time,
            "reference_time": reference_time or end_time,
            "page_size": limit
        }

        if sum([ip is not None, hostname is not None, mac is not None]) > 1:
            # More than 1 artifacts was passed - invalid.
            raise exceptions.GoogleChronicleValidationError(
                "You can only specify a single indicator. "
                "The asset indicator may either be a hostname, an IP address or a MAC address."
            )
        elif ip:
            params["asset.asset_ip_address"] = ip

        elif hostname:
            params["asset.hostname"] = hostname

        elif mac:
            params["asset.mac"] = mac

        else:
            raise exceptions.GoogleChronicleValidationError(
                "You must specify at least one indicator. "
                "The asset indicator may either be a hostname, an IP address or a MAC address."
            )

        response = self.session.get(request_url, params=params)
        self.validate_response(response, "Unable to list events")
        response_json = response.json()
        events = [self.parser.build_siemplify_event_obj(event) for event in response_json.get('events', [])]
        filtered_events = [event for event in events if event.event_type.lower() in [t.lower() for t in event_types]] \
            if event_types else events
        return response_json.get("uri", []), filtered_events

    def list_alerts(self, start_time: str, end_time: Optional[str] = None, limit: Optional[int] = consts.LIMIT,
                    fetch_user_alerts: Optional[bool] = False, fallback_severity: Optional[str] = None):  

        """
        List all of the events discovered within your enterprise on a particular device within the specified time range.
        If you receive the maximum number of events you specified using the page_size parameter (or 10,000, the
        default), there might still be more events within your Chronicle account. You can narrow the time range and
        issue the call again to ensure you have visibility into all possible events.
        :param start_time: {str} Start time for the time range in which the Alerts were discovered in RFC 3339.
        :param end_time: {str} End time for the time range in which the Alerts were discovered in RFC 3339.
        :param limit: {int} Specify the maximum number of alerts to return. You can specify between 1 and 100,000.
        :param fetch_user_alerts: {bool} Specifies if user alerts needs to be fetched
        :param fallback_severity: {str} fallback severity for alerts
        :return: {[datamodels.Alert]} List of found alerts
            within the time range.
        """
        request_url = f"{self.api_root}/v1/alert/listalerts"
        params = {
            "start_time": start_time,
            "end_time": end_time or utils.datetime_to_rfc3339(datetime.datetime.utcnow()),
            "page_size": limit
        }
        response, elapsed_time = self.retry_request(method="GET",
                                                    request_url=request_url,
                                                    params=params)
        self.validate_response(response, "Unable to list alerts")

        if fetch_user_alerts:
            return [self.parser.build_siemplify_alert_obj(alert, consts.EXTERNAL_ALERT_ASSET_TYPE, fallback_severity)
                    for alert in response.json().get('alerts', [])]\
                   + [self.parser.build_siemplify_alert_obj(alert, consts.EXTERNAL_ALERT_USER_TYPE, fallback_severity)
                      for alert in response.json().get('userAlerts', [])], elapsed_time

        return [self.parser.build_siemplify_alert_obj(alert) for alert in response.json().get('alerts', [])], \
            elapsed_time

    def get_ioc_details(self, ip: Optional[str] = None, domain: Optional[str] = None) -> datamodels.IOCDetail:  

        """
        Submit an artifact indicator and return any threat intelligence associated with that artifact.
        The threat intelligence information is drawn from your enterprise security systems and from Google's
        IoC partners (for example, the DHS threat feed). You can only specify a single artifact. The artifact indicator
        may either be a domain name or an IP address.
        :param ip: {str} Specify the ip indicator associated with the assets.
        :param domain: {str} Specify the domain indicator associated with the assets.
        :return: {datamodels.IOCDetails} The found IOC detail for the given artifact.
        """
        if domain and ip:
            raise exceptions.GoogleChronicleValidationError(
                "You can only specify a single artifact. "
                "The artifact indicator may either be a domain name or an IP address."
            )

        elif ip:
            params = {"artifact.destination_ip_address": ip}

        elif domain:
            params = {"artifact.domain_name": domain}

        else:
            raise exceptions.GoogleChronicleValidationError(
                "You must specify at least one artifact. "
                "The artifact indicator may either be a domain name or an IP address."
            )

        request_url = f"{self.api_root}/v1/artifact/listiocdetails"
        response = self.session.get(request_url, params=params)
        self.validate_response(response, f"Unable to get IOC details for {ip}")
        return self.parser.build_siemplify_ioc_detail_obj(response.json())

    def get_rule_alerts(self, rule_id: str, start_time: str, end_time: str):  

        """
        Get all of the rule alerts discovered within your enterprise within the specified time range.
        :param rule_id: {str} Id of the rule.
        :param start_time: {str} Start time for your request. Enter time using the time standard defined in RFC 3339.
            Time is represented by the span of UTC time since Unix epoch 1970-01-01T00:00:00Z.
        :param end_time: {str} End time for your request. Enter time using the time standard defined in RFC 3339.
            Time is represented by the span of UTC time since Unix epoch 1970-01-01T00:00:00Z.
        :return: {[datamodels.Detection]} List of found detections.
        """
        request_url = f"{self.api_root}/v2/detect/rules/{rule_id}/detections"
        limit = 10000
        params = {
            "start_time": start_time,
            "pageSize": limit,
            "end_time": end_time or utils.datetime_to_rfc3339(datetime.datetime.utcnow())
        }
        response, elapsed_time = self.retry_request(method="GET",
                                                    request_url=request_url,
                                                    params=params)
        self.validate_response(response, "Unable to get rule alerts")

        results = response.json().get("detections", [])
        next_page_token = response.json().get("nextPageToken", "")

        while next_page_token:
            if len(results) >= limit:
                break

            params.update({
                "pageToken": next_page_token
            })
            response, total_seconds = self.retry_request(method="GET",
                                                         request_url=request_url,
                                                         params=params)
            self.validate_response(response, "Unable to get rule alerts")
            elapsed_time += total_seconds
            next_page_token = response.json().get("nextPageToken", "")
            results.extend(response.json().get("detections", []))

        return [self.parser.build_detection(detection) for detection in results], elapsed_time

    def retry_request(self, method, request_url, params=None, body=None):  

        """
        If received API limitation error, will retry the request given times
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param request_url: {str} The request url
        :param params: {dict} Parameters to use in the request
        :param body: {dict} The json payload of the request
        :return: {Response}
        """
        response = self.session.request(method, request_url, params=params, json=body)
        elapsed_time = response.elapsed.total_seconds()
        if response.status_code == consts.API_LIMIT_ERROR:
            for i in range(consts.MAX_RETRIES):
                sleep(randint(1, 3))
                response = self.session.request(method, request_url, params=params, json=body)
                elapsed_time += response.elapsed.total_seconds()
                if response.status_code == consts.API_LIMIT_ERROR:
                    continue
                break
        return response, elapsed_time

    def get_events_by_query(self, query: str, start_time: str, end_time: Optional[str] = None,
                            limit: Optional[int] = consts.LIMIT):  

        """
        List all of the events discovered within your enterprise with the specified query.
        :param query: {str} Query that needs to be executed.
        :param start_time: {str} Start time for the time range in which the Events were discovered in RFC 3339.
        :param end_time: {str} End time for the time range in which the Events were discovered in RFC 3339.
        :param limit: {int} Specify the maximum number of events to return. You can specify between 1 and 100,000.
        :return: {list} List of found events within the time range.
        """
        request_url = f"{self.api_root}/v1/events/liststructuredqueryevents"
        params = {
            "start_time": start_time,
            "end_time": end_time or utils.datetime_to_rfc3339(datetime.datetime.utcnow()),
            "raw_query": query.replace("'", "\'").replace('"', '\"'),
            "page_size": limit
        }
        response = self.session.get(request_url, params=params)
        if response.status_code == 400:
            raise exceptions.GoogleChronicleBadRequestError()

        self.validate_response(response, "Unable to fetch events")
        events = [self.parser.build_siemplify_event_obj(event.get("event", {})) for event
                  in response.json().get("results", [])]
        return events, response.elapsed.total_seconds()

    def build_api_query(self, activities, types, entity_identifier):  

        queries = []
        activity_query = " or ".join([f"metadata.event_type = \"{activity}\"" for activity in activities])
        if activity_query:
            if len(activities) > 1:
                queries.append(f"({activity_query})")
            else:
                queries.append(f"{activity_query}")

        entity_query = " or ".join([f"{type} = \"{entity_identifier}\"" for type in types])
        if entity_query:
            if len(types) > 1:
                queries.append(f"({entity_query})")
            else:
                queries.append(f"{entity_query}")

        return " and ".join(queries)

    def get_events_by_udm_query(self, query, start_time, end_time, limit):
        """
        Get events by udm query
        Args:
            query (str): query to run
            start_time (str): start time
            end_time (str): end time
            limit (int): limit for results
        Returns:
            ([UdmQueryEvent]) list of UdmQueryEvent objects
        """
        url = self._get_full_url("udm_search")
        params = {
            "time_range.start_time": start_time,
            "time_range.end_time": end_time,
            "query": query,
            "limit": limit
        }
        response = self.session.get(url, params=params)
        self.validate_response(response)
        return self.parser.build_udm_query_event_objects(response.json())

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):  

        """
        Validate a response
        :param response: {requests.Response} The response
        :param error_msg: {str} The error message to display on failure
        """
        try:
            if response.status_code == consts.API_LIMIT_ERROR:
                raise exceptions.GoogleChronicleAPILimitError("Reached API request limitation")

            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                response.json()

                if response.status_code == 400:
                    raise exceptions.GoogleChronicleManagerError(
                        response.json().get("error", {}).get("message", "")
                    )

                raise exceptions.GoogleChronicleManagerError(
                    f"{error_msg}: {error} {response.json().get('error', {}).get('message', response.content)}"
                )
            except exceptions.GoogleChronicleManagerError:
                raise

            except:
                raise exceptions.GoogleChronicleManagerError(
                    f"{error_msg}: {error} {response.content}"
                )

    def stream_detection_alerts_in_retry_loop(self, start_time, limit, python_process_timeout, connector_starting_time,
                                              timeout_threshold, fallback_severity=None):  

        continuation_time = start_time
        max_consecutive_failures = 7
        consecutive_failures = 0
        processed_detections = []

        while True:
            if utils.is_approaching_timeout(python_process_timeout, connector_starting_time, timeout_threshold):
                self.siemplify_logger.info('Timeout is approaching. Connector will gracefully exit.')
                break

            if consecutive_failures > max_consecutive_failures:
                raise RuntimeError("exiting retry loop. consecutively failed " +
                                   f"{consecutive_failures} times without success")

            if consecutive_failures:
                sleep_duration = 2 ** consecutive_failures
                self.siemplify_logger.info("sleeping {} seconds before retrying".format(sleep_duration))
                time.sleep(sleep_duration)

            req_data = {} if not continuation_time else {
                "continuationTime": continuation_time
            }
            response_code, disconnection_reason, most_recent_continuation_time, processed_detections = \
                self.stream_detection_alerts(req_data, processed_detections, limit, python_process_timeout,
                                             connector_starting_time, timeout_threshold, fallback_severity)
            if most_recent_continuation_time:
                consecutive_failures = 0
                continuation_time = most_recent_continuation_time
            else:
                self.siemplify_logger.info(disconnection_reason
                                           if disconnection_reason else "connection unexpectedly closed")

                # Do not retry if the disconnection was due to invalid arguments.
                # We assume a disconnection was due to invalid arguments if the connection
                # was refused with HTTP status code 400.
                if response_code == 400:
                    raise RuntimeError("exiting retry loop. connection refused " +
                                       f"due to invalid arguments {req_data}")

                consecutive_failures += 1
            break

        return processed_detections

    def stream_detection_alerts(self, req_data, processed_detections, limit, python_process_timeout,
                                connector_starting_time, timeout_threshold, fallback_severity=None):  

        url = f"{self.api_root}/v2/detect/rules:streamDetectionAlerts"

        response_code = 0
        disconnection_reason = ""
        continuation_time = ""

        with self.session.post(url, stream=True, data=req_data, timeout=60) as response:
            self.siemplify_logger.info(f"Initiated connection to detection alerts stream with request: {req_data}")
            response_code = response.status_code

            if response.status_code != 200:
                disconnection_reason = (
                        "connection refused with " +
                        f"status={response.status_code}, error={response.text}")
            else:
                for batch in self.parse_stream(response):
                    if utils.is_approaching_timeout(python_process_timeout, connector_starting_time, timeout_threshold):
                        self.siemplify_logger.info('Timeout is approaching. Connector will gracefully exit.')
                        break
                    if "error" in batch:
                        error_dump = json.dumps(batch["error"], indent="\t")
                        disconnection_reason = f"connection closed with error: {error_dump}"
                        break

                    if "heartbeat" in batch:
                        self.siemplify_logger.info("Got empty heartbeat (confirms connection/keepalive)")
                        continue

                    continuation_time = batch["continuationTime"]

                    if "detections" not in batch:
                        self.siemplify_logger.info("Got a new continuationTime={}, no detections".format(
                            continuation_time))
                        continue
                    else:
                        self.siemplify_logger.info("Got detection batch with continuationTime={}".format(
                            continuation_time))

                    processed_detections.extend(
                        [self.parser.build_detection(detection, fallback_severity)
                         for detection in batch.get('detections', [])]
                    )

                    if len(processed_detections) > limit or not processed_detections:
                        break

        return response_code, disconnection_reason, continuation_time, processed_detections

    @staticmethod
    def parse_stream(response):  

        try:
            if response.encoding is None:
                response.encoding = "utf-8"

            for line in response.iter_lines(decode_unicode=True, delimiter="\r\n"):
                if not line:
                    continue

                json_string = "{" + line.split("{", 1)[1].rsplit("}", 1)[0] + "}"
                yield json.loads(json_string)
        except Exception as e:
            yield {
                "error": {
                    "code": 500,
                    "status": "UNAVAILBLE",
                    "message": "exception caught while reading stream response (your "
                               "streaming client should retry connection): {}".format(repr(e)),
                }
            }

    def get_updated_cases_metadata(self, siemplify, start_timestamp_unix_ms, count, allowed_environments,
                                   vendor):  

        results = siemplify.get_updated_sync_cases_metadata(
            start_timestamp_unix_ms=start_timestamp_unix_ms,
            count=count,
            allowed_environments=allowed_environments,
            vendor=vendor
        )

        return [self.parser.build_case_metadata_obj(item.__dict__) for item in results]

    def get_updated_alerts_metadata(self, siemplify, start_timestamp_unix_ms, count, allowed_environments,
                                    vendor):  

        results = siemplify.get_updated_sync_alerts_metadata(
            start_timestamp_unix_ms=start_timestamp_unix_ms,
            count=count,
            allowed_environments=allowed_environments,
            vendor=vendor
        )

        return [self.parser.build_alert_metadata_obj(item.__dict__) for item in results]

    def convert_siemplify_cases_to_chronicle(self, cases_with_details):  

        return [self.parser.build_chronicle_case_obj(json.loads(json.dumps(case_data.__dict__))) for case_data in
                cases_with_details]

    def convert_siemplify_alerts_to_chronicle(self, alerts_with_details, sync_cases):  

        case_id_mappings = {case.case_id: case.external_case_id for case in sync_cases}
        self.siemplify_logger.info(f'case id mapping: {case_id_mappings}')
        for alert in alerts_with_details:
            setattr(alert, 'case_id', case_id_mappings[alert.case_id])

        return [self.parser.build_chronicle_alert_obj(json.loads(json.dumps(alert_data.__dict__))) for alert_data in
                alerts_with_details]

    def batch_update_cases_in_chronicle(self, cases_to_update):
        updated_cases = copy.deepcopy(cases_to_update)
        url = self._get_full_url("batch_update")
        boundary = '===============7330845974216740156=='
        data = self.build_cases_batch_request_data(cases_to_update, boundary)
        response = self.session.post(url, data=data, headers={"content-type": f'multipart/mixed; boundary={boundary}'})
        self.validate_response(response, "Unable to update cases")
        parsed_response_list = self.parser.parse_multipart_response(response)
        for case, resp in zip(updated_cases, parsed_response_list):
            try:
                if resp.status_code >= 400:
                    raise requests.HTTPError()
                case.external_id = resp.json().get('name')
            except requests.HTTPError:
                case.has_failed = True
                err = resp.json().get("error").get("message")
                self.siemplify_logger.error(f'Failed to update case {case.id}. Reason: {err}')

        return updated_cases

    def batch_update_alerts_in_chronicle(self, alerts_to_update):
        updated_alerts = copy.deepcopy(alerts_to_update)
        url = self._get_full_url("batch_update")
        boundary = '===============7330845974216740156=='
        data = self.build_alerts_batch_request_data(alerts_to_update, boundary)
        response = self.session.post(url, data=data, headers={"content-type": f'multipart/mixed; boundary={boundary}'})
        self.validate_response(response, "Unable to update alerts")
        parsed_response_list = self.parser.parse_multipart_response(response)
        for alert, resp in zip(updated_alerts, parsed_response_list):
            try:
                if resp.status_code >= 400:
                    raise requests.HTTPError()
            except requests.HTTPError:
                alert.has_failed = True
                err = resp.json().get("error").get("message")
                self.siemplify_logger.error(f'Failed to update alert {alert.id}. Reason: {err}')

        return updated_alerts

    @staticmethod
    def build_cases_batch_request_data(data_list, boundary):
        data_str = '''
'''
        for item in data_list:
            payload = {
                "display_name": item.display_name,
                "responsePlatformInfo": {"responsePlatformType": "RESPONSE_PLATFORM_TYPE_SIEMPLIFY",
                                         "caseId": str(item.id)},
                "stage": item.stage,
                "priority": consts.PRIORITY_SIEMPLIFY_TO_CHRONICLE.get(item.priority, 0),
                "status": consts.STATUS_SIEMPLIFY_TO_CHRONICLE.get(item.status, 0)}
            if item.external_id in ["None", None, ""]:
                payload["name"] = item.external_id

            data_str += f'''--{boundary}
Content-Type: application/http
Content-Transfer-Encoding: binary

POST /v1/cases HTTP/1.1
Content-Type: application/json
accept: application/json

{json.dumps(payload)}
'''
        final_boundary = f'''--{boundary}--
'''
        return data_str + final_boundary

    @staticmethod
    def build_alerts_batch_request_data(data_list, boundary):
        data_str = '''
'''
        for item in data_list:
            feedback = {"idp_user_id": consts.CHRONICLE_USER,
                        "priority": consts.PRIORITY_SIEMPLIFY_TO_CHRONICLE.get(item.priority, 0),
                        "status": consts.STATUS_SIEMPLIFY_TO_CHRONICLE.get(item.status, 0),
                        "comment": item.comment,
                        "reason": consts.REASON_SIEMPLIFY_TO_CHRONICLE.get(item.reason, 0),
                        "root_cause": item.root_cause,
                        "verdict": consts.SIEMPLIFY_REASON_TO_CHRONICLE_VERDICT.get(item.reason, 0),
                        "reputation": consts.SIEMPLIFY_USEFULNESS_TO_CHRONICLE_REPUTATION.get(item.usefulness, 0)}
            feedback = {k: v for k, v in feedback.items() if v is not None}
            payload = {"id": item.ticket_id,
                       "responsePlatformInfo": {"responsePlatformType": "RESPONSE_PLATFORM_TYPE_SIEMPLIFY",
                                                "alertId": item.id},
                       "feedback": feedback,
                       "caseName": item.case_id}
            data_str += f'''--{boundary}
Content-Type: application/http
Content-Transfer-Encoding: binary

PATCH /v1/alert/updatealert HTTP/1.1
Content-Type: application/json
accept: application/json

{json.dumps(payload)}
'''
        final_boundary = f'''--{boundary}--
'''

        return data_str + final_boundary
