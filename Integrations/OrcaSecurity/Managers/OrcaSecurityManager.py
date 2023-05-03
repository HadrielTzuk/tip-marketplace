from typing import List, Any
from urllib.parse import urljoin
import requests
from UtilsManager import validate_response
from OrcaSecurityParser import OrcaSecurityParser
from constants import ENDPOINTS, POSSIBLE_SEVERITIES, DEFAULT_MAX_LIMIT, WHITELIST_FILTER, BLACKLIST_FILTER
from SiemplifyUtils import unix_now


class OrcaSecurityManager:
    def __init__(self, api_root, api_key, api_token, verify_ssl, ui_root="", siemplify_logger=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} OrcaSecurity API root
        :param api_key: {str} OrcaSecurity API key
        :param api_token: {str} OrcaSecurity API token
        :param verify_ssl: {bool} Specifies if certificate that is configured on the api root should be validated
        :param ui_root: {str} OrcaSecurity UI root
        :param siemplify_logger: Siemplify logger
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.api_key = api_key
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.ui_root = ui_root
        self.siemplify_logger = siemplify_logger
        self.parser = OrcaSecurityParser()
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if self.api_token:
            self.session.headers = {"Authorization": f"Token {self.api_token}"}
        elif self.api_key:
            self.set_auth_cookies()
        else:
            raise Exception('Either \"API Key\" or \"API Token\" needs to be provided for authentication.')

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def set_auth_cookies(self):
        """
        Set authorization cookies
        :return: {void}
        """
        url = self._get_full_url("login")
        params = {
            "security_token": self.api_key
        }

        response = self.session.get(url, params=params, allow_redirects=False)
        validate_response(response)

        for cookie in response.cookies:
            if cookie.name == 'csrftoken':
                self.session.cookies.update({"csrftoken": cookie.value})
            if cookie.name == 'sessionid':
                self.session.cookies.update({"sessionid": cookie.value})

    def test_connectivity(self):
        """
        Test connectivity
        :return: {void}
        """
        payload = {"limit": 1}
        url = self._get_full_url("vulnerability_details")
        response = self.session.post(url, json=payload)
        validate_response(response)

    def get_alerts(self, start_timestamp, limit, lowest_severity=None, categories=None, title_filter=None,
                   title_filter_type=WHITELIST_FILTER, alert_types=None):
        """
        Get alerts
        :param start_timestamp: {int} timestamp for oldest alert to fetch
        :param limit: {int} limit for results
        :param lowest_severity: {str} lowest severity to use for fetching
        :param categories: {list} list of category filters to use for fetching
        :param title_filter: {list} list of title filters to use for fetching
        :param title_filter_type: {int} specifies if includes or excludes should be used for title filter
        :param alert_types: {list} list of alert type filters to use for fetching
        :return: {list} list of Alert objects
        """
        url = self._get_full_url("get_alerts")

        payload = {
            "dsl_filter": {
                "filter": [
                    {
                        "field": "state.created_at",
                        "range": {
                            "gte": start_timestamp,
                            "lte": unix_now()
                        }
                    },
                    {
                        "field": "state.status",
                        "includes": [
                            "open",
                            "in_progress"
                        ]
                    }
                ],
                "sort": [
                    {
                        "field": "state.created_at",
                        "order": "asc"
                    }
                ]
            },
            "limit": max(limit, DEFAULT_MAX_LIMIT),
            "start_at_index": 0,
            "resolved_alerts": False,
            "grouping": True,
            "show_all_statuses_alerts": True
        }

        if lowest_severity:
            payload.get("dsl_filter").get("filter").append({
                "field": "state.severity",
                "includes": POSSIBLE_SEVERITIES[:POSSIBLE_SEVERITIES.index(lowest_severity) + 1]
            })

        if categories:
            payload.get("dsl_filter").get("filter").append({
                "field": "category",
                "includes": categories
            })

        if title_filter:
            payload.get("dsl_filter").get("filter").append({
                "field": "data.title",
                "excludes" if title_filter_type == BLACKLIST_FILTER else "includes": title_filter
            })

        if alert_types:
            payload.get("dsl_filter").get("filter").append({
                "field": "type",
                "includes": alert_types
            })

        response = self.session.post(url, json=payload)
        validate_response(response)
        return self.parser.build_alert_objects(response.json())

    def verify_alert(self, alert_id):
        """
        Verify Alert
        :param alert_id: {str} alert id
        :return: {void}
        """
        url = self._get_full_url("verify_alert", alert_id=alert_id)
        response = self.session.put(url)
        validate_response(response)

    def snooze_alert(self, alert_id, snooze_days):
        """
        Snooze alert
        :param alert_id: {str} alert id
        :param snooze_days: {int} specifies how many days alert needs to be snoozed
        :return: {void}
        """
        url = self._get_full_url("snooze_alert", alert_id=alert_id)
        payload = {
            "days": snooze_days
        }

        response = self.session.put(url, json=payload)
        validate_response(response)

    def update_alert_status(self, alert_id, status):
        """
        Update alert status
        :param alert_id: {str} alert id
        :param status: {int} specifies what status to set for alert
        :return: {void}
        """
        url = self._get_full_url("update_alert_status", alert_id=alert_id, status=status)
        response = self.session.put(url)
        validate_response(response)

    def get_alert_data(self, alert_id):
        """
        Get alert data
        :param alert_id: {str} alert id
        :return: {Alert} Alert object
        """
        url = self._get_full_url("get_alert_data", alert_id=alert_id)
        response = self.session.get(url)
        validate_response(response)
        return self.parser.build_alert_object(response.json())

    def add_alert_comment(self, alert_id, comment):
        """
        Add comment to alert
        :param alert_id: {str} alert id
        :param comment: {str} comment to add
        :return: {AlertComment} AlertComment object
        """
        url = self._get_full_url("add_alert_comment", alert_id=alert_id)
        payload = {
            "comment": comment
        }

        response = self.session.put(url, json=payload)
        validate_response(response)
        return self.parser.build_alert_comment_object(response.json())

    def get_frameworks(self, framework_names, limit):
        """
        Get frameworks
        :param framework_names: {list} list of framework names to retrieve
        :param limit: {int} limit for results
        :return: {([Framework], [str])} list of Framework objects, list of not found framework names
        """
        url = self._get_full_url("get_frameworks")
        response = self.session.post(url)
        validate_response(response)
        return self.filter_frameworks(self.parser.build_framework_objects(response.json()), framework_names, limit)

    @staticmethod
    def filter_frameworks(frameworks, framework_names, limit):
        """
        Filter frameworks by names
        :param frameworks: {list} list of Framework objects to filter
        :param framework_names: {list} list of framework names to use for filtering
        :param limit: {int} limit for results
        :return: {([Framework], [str])} list of filtered Framework objects, list of not found framework names
        """
        if framework_names:
            filtered_frameworks = [framework for framework in frameworks if framework.display_name in framework_names]
            not_found_frameworks = list(
                set(framework_names) - set([framework.display_name for framework in filtered_frameworks])
            )
        else:
            filtered_frameworks = frameworks
            not_found_frameworks = []

        return filtered_frameworks[:limit] if limit else filtered_frameworks, not_found_frameworks

    def start_scan(self, asset_id):
        """
        Start scan for asset by id
        :param asset_id: {str} asset id
        :return: {ScanStatus} ScanStatus object
        """
        url = self._get_full_url("start_scan", asset_id=asset_id)
        response = self.session.post(url)
        validate_response(response)
        return self.parser.build_scan_status_object(response.json())

    def get_scan_status(self, scan_id):
        """
        Get scan status by id
        :param scan_id: {str} scan id
        :return: {ScanStatus} ScanStatus object
        """
        url = self._get_full_url("get_scan_status", scan_id=scan_id)
        response = self.session.get(url)
        validate_response(response)
        return self.parser.build_scan_status_object(response.json())

    def get_vulnerability_results(self, cve_id, limit=None, create_insight=False) -> List[Any]:
        payload = {
            "dsl_filter": {
                "filter": [
                    {
                        "field": "cve_id",
                        "includes": [cve_id]
                    }
                ],
                "sort": [
                    {
                        "field": "severity",
                        "order": "desc"
                    }
                ]
            }
        }

        results = self._paginate_results(method='POST', url=self._get_full_url("vulnerability_details"),
                                         body=payload, limit=limit)
        enrichment_data = self.parser.build_results(raw_json=results[:limit], pure_data=True, method='build_cve_object')
        return_list = [enrichment_data, None]
        if create_insight:
            # for insight generation whole data is required
            insight_data = self.parser.build_results(raw_json=results, pure_data=True, method='build_cve_object')
            return_list[1] = insight_data
        return return_list

    def get_asset_details(self, asset_id):
        """
        Get asset details
        :param asset_id: {str} asset unique id
        :return: {Asset} object of Asset datamodel
        """
        response = self.session.get(self._get_full_url("asset_details", asset_id=asset_id))
        validate_response(response)

        return self.parser.build_asset_object(response.json())

    def get_vulnerability_details(self, asset_id, severity, limit=None):
        """
        Get vulnerability details by severity value
        :param asset_id: {str} asset unique id
        :param severity: {str} lowest severity value
        :param limit: {int} limit of returning data
        :return: {list} list of vulnerabilities
        """
        payload = {
            "dsl_filter": {
                "filter": [
                    {
                        "field": "asset_unique_id",
                        "includes": [asset_id]
                    }
                ],
                "sort": [
                    {
                        "field": "score",
                        "order": "desc"
                    }
                ]
            },
            "limit": limit,
            "start_at_index": 0,
            "grouping": True
        }

        if severity:
            payload.get("dsl_filter").get("filter").append({
                "field": "severity",
                "includes": POSSIBLE_SEVERITIES[:POSSIBLE_SEVERITIES.index(severity.lower()) + 1]
            })

        response = self.session.post(self._get_full_url("vulnerability_details"), json=payload)
        validate_response(response)

        return self.parser.build_results(raw_json=response.json(), method='build_cve_object')

    def _paginate_results(
            self, method, url, params=None, body=None, limit=None, err_msg="Unable to get results", **kwargs
    ):
        """
        Paginate the results of a request
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param limit: {int} The limit of the results to fetch
        :param err_msg: {str} The message to display on error
        :return: {list} List of results
        """
        if body is None:
            body = {}

        body.update({
            "limit": 1000
        })

        response = self.session.request(method, url, params=params, json=body)

        validate_response(response, err_msg)
        json_response = response.json()
        results = json_response.get("data", [])
        next_page_token = json_response.get("next_page_token", "")

        while next_page_token:
            body.update({
                "next_page_token": next_page_token
            })

            response = self.session.request(method, url, params=params, json=body)
            validate_response(response, err_msg)
            json_response = response.json()
            next_page_token = json_response.get("next_page_token", "")
            results.extend(json_response.get("data", []))
        return results
