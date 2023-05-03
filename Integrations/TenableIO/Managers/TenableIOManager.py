from urllib.parse import urljoin
import requests
from constants import ENDPOINTS, FINISHED_STATUS, CANCELLED_STATUS, ERROR_STATUS
from UtilsManager import validate_response, filter_old_alerts, write_pending_export
from TenableIOParser import TenableIOParser
from TenableIOExceptions import ExportNotFinishedException, TenableIOException


class TenableIOManager:
    def __init__(self, api_root, secret_key, access_key, verify_ssl=False, siemplify_logger=None):
        """
        The method is used to init an object of Manager class
        :param api_root: {str} API root of the Tenable.io instance.
        :param secret_key: {str} Secret Key of the SpyCloud instance.
        :param access_key: {str} Access Key of the Tenable.io instance
        :param verify_ssl: {bool} If enabled, verify the SSL certificate for the connection to the Tenable.io server is valid.
        :param siemplify_logger: Siemplify logger
        """
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.secret_key = secret_key
        self.access_key = access_key
        self.logger = siemplify_logger
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.parser = TenableIOParser()
        self.session.headers.update({
            "x-apikeys": f"accessKey={self.access_key};secretKey={self.secret_key}"
        })
        self.session.headers.update({
            "User-Agent": "Integration/1.0 (Siemplify; TenableIO_Integration; Build/5.6"
        })        

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        """
        request_url = self._get_full_url("ping")
        response = self.session.get(request_url)
        validate_response(response)

    def list_assets(self):
        """
        List all assets
        :return: {list} List of Asset objects
        """
        request_url = self._get_full_url("assets")
        response = self.session.get(request_url)
        validate_response(response)
        return self.parser.build_asset_objects(response.json())

    def get_asset(self, id):
        """
        Get asset details by id
        :param id: {str} Asset id
        :return: {Asset} Asset object
        """
        request_url = self._get_full_url("asset", id=id)
        response = self.session.get(request_url)
        validate_response(response)
        return self.parser.build_asset_object(response.json())

    def list_plugin_families(self):
        """
        List all plugin families
        :return: {list} List of PluginFamily objects
        """
        request_url = self._get_full_url("list_plugin_families")
        response = self.session.get(request_url)
        validate_response(response, 'Unable to list plugin families')

        return self.parser.build_plugin_families_list(response.json())

    def list_policies(self):
        """
        List all policies
        :return: {list} List of Policy objects
        """
        request_url = self._get_full_url("list_policies")
        response = self.session.get(request_url)
        validate_response(response, 'Unable to list policies')

        return self.parser.build_policies_list(response.json())

    def list_scanners(self):
        """
        List all scanners
        :return: {list} List of Scanner objects
        """
        request_url = self._get_full_url("list_scanners")
        response = self.session.get(request_url)
        validate_response(response, 'Unable to list scanners')

        return self.parser.build_scanners_list(response.json())

    def initiate_export(self, statuses, severities, start_timestamp, plugin_families):
        """
        Initiate Export
        :param statuses: {list} List of statuses to apply to the filter
        :param severities: {list} List of severities to apply to the filter
        :param start_timestamp: {int} The timestamp from where to fetch
        :param plugin_families: {list} List of plugin families tp apply to the filter
        :return: {str} The uuid of Export
        """
        request_url = self._get_full_url('initiate_export')
        payload = {
            "filters": {
                "severity": severities,
                "plugin_family": plugin_families,
                "since": int(str(start_timestamp)[:-3]),
                "state": statuses
            }
        }

        response = self.session.post(request_url, json=payload)
        validate_response(response, 'Unable to initiate export')

        return response.json().get("export_uuid")

    def get_export_status(self, siemplify, export_uuid):
        """
        Get Export status
        :param siemplify: {Siemplify} Siemplify object.
        :param export_uuid: {str} The id of Export
        :return: Export object
        """
        request_url = self._get_full_url('get_export_status', export_id=export_uuid)
        response = self.session.get(request_url)
        validate_response(response, 'Unable to check export status')

        export_data = response.json()
        export_status = export_data.get("status")

        if export_status == FINISHED_STATUS:
            return export_data
        elif export_status in [CANCELLED_STATUS, ERROR_STATUS]:
            raise ExportNotFinishedException(f"Export {export_uuid} status is {export_status}. "
                                             f"Connector will stop the iteration and skip the export.")
        else:
            write_pending_export(siemplify, export_data)
            raise ExportNotFinishedException(f"Export {export_uuid} status is {export_status}. "
                                             f"Connector will stop the iteration and save the export data.")

    def get_export_chunk_data(self, existing_ids, export_uuid, chunk_id):
        """
        Get chunk data with export id
        :param existing_ids: {list} The list of existing ids
        :param export_uuid: {str} The id of Export
        :param chunk_id: {int} The id of the chunk
        :return: {list} List of Vulnerability objects
        """
        request_url = self._get_full_url('export_chunk_data', export_id=export_uuid, chunk_id=chunk_id)
        response = self.session.get(request_url)
        validate_response(response, 'Unable to get vulnerabilities')

        vulnerabilities = self.parser.build_vulnerabilities_list(raw_data=response.json())
        filtered_alerts = filter_old_alerts(logger=self.logger, alerts=vulnerabilities, existing_ids=existing_ids)
        return sorted(filtered_alerts, key=lambda vulnerability: vulnerability.last_found)

    def get_vulnerability_details(self, plugin_id):
        """
        Get Vulnerability details
        :param plugin_id: {str} Plugin id
        :return: {VulnerabilityDetails} VulnerabilityDetails object
        """
        request_url = self._get_full_url("get_vulnerabilities_details", plugin_id=plugin_id)
        response = self.session.get(request_url)
        validate_response(response)
        return self.parser.build_vulnerability_details_object(response.json(), plugin_id)

    def get_endpoint_vulnerabilities(self, asset_id, severities, limit):
        """
        List vulnerabilities
        :param asset_id: {str} Asset id
        :param severities: {list} Severities to apply to the filter
        :param limit: {int} Max vulnerabilties to return
        :return: {list} List of EndpointVulnerability objects
        """
        severity_filter = self.build_severity_filter(severities)
        request_url = self._get_full_url("list_vulnerabilities", asset_id=asset_id, query_string=severity_filter)
        response = self.session.get(request_url)
        try:
            validate_response(response)
        except Exception as e:
            if 500 < response.status_code < 600:
                raise Exception(e)
            raise TenableIOException(e)

        return self.parser.build_endpoint_vulnerabilities_list(response.json())[:limit]

    def build_severity_filter(self, severities):
        """
        Create severity filter string
        :param severities: {list} Severities to apply to the filter
        :return: {str} Filter string
        """
        filters = []
        for i, value in enumerate(severities):
            filters.append(f"filter.{i}.filter=severity&filter.{i}.quality=eq&filter.{i}.value={value.lower()}")

        return "&filter.search_type=or&".join(filters)

    def create_scan(self, policy_uuid, scan_name, ip_address, emails, scanner_id):
        """
        Create scan
        :param policy_uuid: {str} The uuid of policy
        :param scan_name: {str} The name of the scan
        :param ip_address: {str} The target ip address
        :param emails: {str} CSV of emails to send report to
        :param scanner_id: {int} Id of the scanner to use
        :return: {int} The created scan id
        """
        request_url = self._get_full_url("create_scan")
        payload = {
            "uuid": policy_uuid,
            "settings": {
                "name": scan_name,
                "enabled": True,
                "text_targets": ip_address,
                "launch": "ON_DEMAND",
                "emails": emails or ""
            }
        }

        if scanner_id:
            payload["settings"]["scanner_id"] = scanner_id

        response = self.session.post(request_url, json=payload)
        validate_response(response)

        return response.json().get("scan", {}).get("id")

    def launch_scan(self, scan_id):
        """
        Launch scan
        :param scan_id: {int} Id of the scan to launch
        """
        request_url = self._get_full_url("launch_scan", scan_id=scan_id)
        response = self.session.post(request_url)
        validate_response(response)

    def check_scan_status(self, scan_id):
        """
        Check the scan status
        :param scan_id: {int} Id of the scan to check
        :return: {str} The scan status
        """
        request_url = self._get_full_url("check_scan_status", scan_id=scan_id)
        response = self.session.get(request_url)
        validate_response(response)

        return response.json().get("status", "")

    def get_scan_results(self, scan_id):
        """
        Get results for completed scan
        :param scan_id: {int} Id of the scan
        :return: {Scan} The Scan object
        """
        request_url = self._get_full_url("get_scan_results", scan_id=scan_id)
        response = self.session.get(request_url)
        validate_response(response)

        return self.parser.build_scan_object(response.json())
