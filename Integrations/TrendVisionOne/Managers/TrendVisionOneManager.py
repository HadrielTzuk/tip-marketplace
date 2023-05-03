import requests
from urllib.parse import urljoin
from UtilsManager import validate_response
from constants import ENDPOINTS, POSSIBLE_SEVERITIES, DATETIME_FORMAT, DEFAULT_MAX_LIMIT
from datetime import datetime
from TrendVisionOneParser import TrendVisionOneParser
import datamodels


class TrendVisionOneManager:
    def __init__(self, api_root, api_token, verify_ssl, siemplify=None):
        """
        The method is used to init an object of Manager class
        Args:
            api_root (str): API root of the TrendVisionOne instance
            api_token (str): API key of the TrendVisionOne account
            verify_ssl (bool): Specifies if certificate that is configured on the api root should be validated
            siemplify: Siemplify connector or action execution instance
        """
        self.api_root = api_root
        self.verify_ssl = verify_ssl
        self.siemplify = siemplify
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({"Authorization": f"Bearer {api_token}"})
        self.parser = TrendVisionOneParser()

    def _get_full_url(self, url_id, **kwargs) -> str:
        """
        Get full url from url identifier.
        Args:
            url_id (str): The id of url
            **kwargs: Variables passed for string formatting

        Returns:
            (str) The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        Args:

        Returns:
            () None
        """
        response = self.session.get(self._get_full_url("healthcheck"))
        validate_response(response)

    def get_alerts(self, start_timestamp, lowest_severity_filter, limit):
        """
        Get Alerts
        Args:
            start_timestamp (int): Start time to fetch alerts from
            lowest_severity_filter (str): Lowest severity value to use for filtering
            limit (int): Limit for results
        Returns:
            ([Alert]): List of Alert objects
        """
        params = {
            "orderBy": "createdDateTime asc",
            "startDateTime": self._build_datetime_filter(start_timestamp)
        }

        self.session.headers.update({
            "TMV1-Filter": f"({self._build_severity_filter(lowest_severity_filter)}) "
                           f"and (investigationStatus eq 'New' or investigationStatus eq 'In Progress')"
        })

        return self._paginate_results(method="GET",
                                      url=self._get_full_url("get_alerts"),
                                      parser_method="build_alert_object",
                                      params=params,
                                      limit=max(limit, DEFAULT_MAX_LIMIT))


    def _paginate_results(self, method, url, parser_method, params=None, limit=None):
        """
        Paginate results
        Args:
            method (str): Method for request
            url (str): Url for request
            parser_method (str): Parser for request
            params (dict): Params for request
            limit (int): Limit for request
        Returns:
            (List): [Alert]
        """
        response = None
        results = []

        while not response or response.json().get("nextLink"):
            if response and response.json().get("nextLink"):
                if limit and len(results) >= limit:
                    break

                response = self.session.request(method, response.json().get("nextLink", ""))
            else:
                response = self.session.request(method, url, params=params)

            validate_response(response)
            current_items = self.parser.build_results(response.json(), parser_method)
            results.extend(current_items)

        return results[:limit] if limit else results

    @staticmethod
    def _build_severity_filter(lowest_severity_filter):
        """
        Build severity filter
        Args:
            lowest_severity_filter (str): Lowest severity value to build filter
        Returns:
            (str): Severity filter
        """
        severities = POSSIBLE_SEVERITIES[POSSIBLE_SEVERITIES.index(lowest_severity_filter):] if \
            lowest_severity_filter in POSSIBLE_SEVERITIES else POSSIBLE_SEVERITIES

        return " or ".join([f"severity eq '{severity}'" for severity in severities])

    @staticmethod
    def _build_datetime_filter(start_timestamp):
        """
        Build datetime filter
        Args:
            start_timestamp (int): Start time to build filter
        Returns:
            (str): Datetime filter
        """
        return datetime.utcfromtimestamp(start_timestamp / 1000).strftime(DATETIME_FORMAT)

    def search_endpoint(self, ip=None, hostname=None) -> datamodels.Endpoint:
        """
        Get endpoint by entity
        Args:
            ip (str): IP address
            hostname (str): Hostname

        Returns:
            (datamodels.Endpoint)
        """
        url = self._get_full_url("search_endpoint")
        entity_filter = f"ip eq \'{ip}\'" if ip else f"endpointName eq \'{hostname}\'"
        self.session.headers.update({"TMV1-Query": entity_filter})
        response = self.session.get(url)
        validate_response(response)
        items = response.json().get("items", [])
        if items:
            return self.parser.build_endpoint_obj(raw_json=items[0])

    def isolate_endpoint(self, description, guid) -> str:
        """
        Isolate endpoint
        Args:
            description (str): Description for isolation
            guid (str): Endpoint guid

        Returns:
            Task url
        """
        url = self._get_full_url("isolate_endpoint")
        payload = [
            {
                "agentGuid": guid,
                "description": description
            }
        ]
        response = self.session.post(url, json=payload)
        validate_response(response)
        response_headers = response.json()[0].get("headers", [])
        return next(
            (
                res_head.get("value") for res_head in response_headers if res_head.get("name") == "Operation-Location"
            ), None
        )

    def unisolate_endpoint(self, description, guid) -> str:
        """
        Unisolate endpoint
        Args:
            description (str): Description for unisolation
            guid (str): Endpoint guid

        Returns:
            Task url
        """
        url = self._get_full_url("unisolate_endpoint")
        payload = [
            {
                "agentGuid": guid,
                "description": description
            }
        ]
        response = self.session.post(url, json=payload)
        validate_response(response)
        response_headers = response.json()[0].get("headers", [])
        return next(
            (
                res_head.get("value") for res_head in response_headers if res_head.get("name") == "Operation-Location"
            ), None
        )

    def get_task(self, task_url) -> datamodels.Task:
        """
        Get task details
        Args:
            task_url: URL of the task

        Returns:
            (datamodels.Task)
        """
        response = self.session.get(task_url)
        validate_response(response)

        return self.parser.build_task_obj(response.json())

    def get_alert_by_id(self, alert_id: str):
        """
        Get Alert data
        Args:
            alert_id (str): ID of alert to retrieve data for.
        Returns:
            (Alert): Alert object
        Raises:
            TrendVisionOneExceptions
        """

        uri = self._get_full_url("alert_details", alert_id=alert_id)
        response = self.session.get(uri)
        validate_response(response)

        return self.parser.build_alert_object(response.json())


    def update_alert(self, alert_id: str, status: str):
        """
        Update alert
        Args:
            alert_id (str): ID of alert to update.
            status (str): Status to update alert with.
        Returns:
            (bool): True if alert was successfully updated
        Raises:
            TrendVisionOneExceptions
        """

        payload = {
            "investigationStatus": status
        }
        uri = self._get_full_url("alert_details", alert_id=alert_id)
        response = self.session.patch(uri, json=payload)
        validate_response(response)

        return True

    def get_script_by_name(self, script_name: str) -> datamodels.Script:
        """
        Get script by name
        Args:
            script_name: Full script name

        Returns:
            (datamodels.Script)
        """

        url = self._get_full_url("get_scripts")
        response = self.session.get(
            url,
            params={"filter": f"fileName eq '{script_name}'"}
        )
        validate_response(response)

        scripts = self.parser.build_script_objects(response.json())
        if scripts:
            return scripts[0]

    def run_script(self, script_name: str, script_parameters: str, guid: str):
        """
        Run Script
        Args:
            script_name (str): Full script name
            script_parameters (str): Script parameters
            guid (str): Endpoint guid

        Returns:
            Task url
        """
        url = self._get_full_url("run_script")
        payload = [
            {
                "agentGuid": guid,
                "fileName": script_name,
                "parameter": script_parameters
            }
        ]
        response = self.session.post(url, json=payload)
        validate_response(response)
        response_headers = response.json()[0].get("headers", [])
        response_error = response.json()[0].get("body", {}).get("error", {})

        if response_error:
            self.siemplify.LOGGER.info(f"New script wasn't created due to the following error: {response_error['code']} - {response_error['message']}")

        return next(
            (
                res_head.get("value") for res_head in response_headers if res_head.get("name") == "Operation-Location"
            ), None
        )
