import requests
import json
import traceback
import time
import urlparse
from constants import ENDPOINTS
from TenableParser import TenableParser
from TenableExceptions import AssetNotFoundException


# Overcome bad handshake SSL Errors.
# See https://stackoverflow.com/questions/40741361/python-requests-gives-me-bad-handshake-error
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':ADH-AES128-SHA256'

HEADERS = {'Content-Type': 'application/json'}
OFFSET = 50


class TenableSecurityCenterException(Exception):
    pass


class TenableSecurityCenterManager(object):
    def __init__(self, server_address, username, password, use_ssl=False):
        self.server_address = server_address
        self.session = requests.Session()
        self.session.headers = HEADERS
        self.session.headers.update({
            "User-Agent": "Integration/1.0 (Siemplify; TenableSecurityCenter_Integration; Build/5.6"
        })
        self.session.verify = use_ssl
        self.token = self.obtain_token(username, password)

        self.session.headers.update({'X-SecurityCenter': str(self.token)})
        self.parser = TenableParser()

    def obtain_token(self, username, password):
        """
        Obtain token
        :param username: {str} Tenable username
        :param password: {str} Tenable password
        :return: {str} The obtained token
        """
        url = "{}/rest/token".format(self.server_address)
        res = self.session.post(url, json={
            "username": username,
            "password": password,
            "releaseSession": "true"
        })

        self.validate_response(res, "Unable to obtain token")
        return res.json()['response']['token']

    def release_token(self):
        """
        Release token
        :return: {bool} True if successful, exception otherwise
        """
        url = '{}/rest/token'.format(self.server_address)
        res = self.session.post(url)
        self.validate_response(res, "Unable to release token")

        return True

    def get_ip_info(self, ip, repo_name):
        """
        Gets IP Info for the Repository associated with {id}.
        :param ip: {str} The ip
        :param repo_name: {str} The repository name
        :return: {json} The Ip info
        """
        repo_id = self.get_repository_id_by_name(repo_name)
        url = '{}/rest/repository/{}/ipInfo'.format(self.server_address, repo_id)
        res = self.session.get(url, params={"ip": ip})
        self.validate_response(res,
                               "Unable to get information for {}".format(ip))

        return res.json()['response']

    def get_ip_related_assets(self, ip, repo_name):
        """
        Gets the ip intersections of an Asset.
        :param ip: {str} The ip
        :param repo_name: {str} The repository name
        :return: {json} The found assets
        """
        repo_id = self.get_repository_id_by_name(repo_name)
        url = '{}/rest/repository/{}/assetIntersections'.format(self.server_address, repo_id)
        res = self.session.get(url, params={"ip": ip})
        self.validate_response(res, "Unable to get related assets of {}".format(ip))

        return res.json()['response']['assets']

    def get_vulnerabilities_for_ip(self, ip):
        """
        Get vulnerabilities for an ip.
        :param ip: {str} The ip address
        :return: {JSON} The found vulnerabilities.
        """
        data = {
            "query": {
                "type": "vuln",
                "tool": "listvuln",
                "sourceType": "cumulative",
                "startOffset": 0,
                "endOffset": OFFSET,
                "filters": [
                    {
                        "id": "ip",
                        "filterName": "ip",
                        "operator": "=",
                        "type": "vuln",
                        "isPredefined": True,
                        "value": ip
                    }
                ],
            },
            "sourceType": "cumulative",
            "type": "vuln"
        }

        url = "{}/rest/analysis".format(self.server_address)
        res = self.session.post(url, json=data)
        self.validate_response(res, "Unable to get valnerabilities for {}".format(ip))

        vulnerabilities = res.json()['response']['results']
        total = int(res.json()['response']['totalRecords'])

        vulnerabilities = self.paginate_vulnerabilities(vulnerabilities, url,
                                                        data, total,
                                                        "Unable to get valnerabilities for {}".format(ip))

        # Vulnerability's family, severity and repository come as a dict.
        # As only the name interests us, extract it and overwrite the vulnerability.
        for vulnerability in vulnerabilities:
            vulnerability['family'] = vulnerability['family']['name']
            vulnerability['severity'] = vulnerability['severity']['name']
            vulnerability['repository'] = vulnerability['repository']['name']

        return vulnerabilities

    def get_scan_list(self):
        """
        Gets the list of Scans.
        :return: {json} The list of Scans.
        """
        url = "{}/rest/scan".format(self.server_address)

        res = self.session.get(url)
        self.validate_response(res, "Unable to get the list of scans")

        return res.json()['response']

    def get_policy_list(self):
        """
        Gets the list of Scan Policies.
        :return: {json} The list of policies
        """
        url = "{}/rest/policy".format(self.server_address)

        res = self.session.get(url)
        self.validate_response(res, "Unable to get policies")

        return res.json()['response']

    def get_repository_list(self):
        """
        Gets the list of Repositories.
        :return: {json} The list of Repositories.
        """
        url = "{}/rest/repository".format(self.server_address)

        res = self.session.get(url)
        self.validate_response(res, "Unable to get the list of repositories")

        return res.json()['response']

    def get_repository_id_by_name(self, name):
        """
        Get repository id by repository name
        :param name: {str} The repository name
        :return: {int} The matching repository id
        """
        repository_list = self.get_repository_list()
        for repository in repository_list:
            if repository['name'] == name:
                return repository['id']

        raise TenableSecurityCenterException(
            "Repository {} not found".format(name))

    def copy_scan_by_id(self, scan_id, target_user_id, new_scan_name):
        """
        Copies the Scan associated with {id}, depending on access and permissions.
        :param scan_id: {str} The scan id
        :param target_user_id: {str} The target user id
        :param new_scan_name: {str} The name of the copied scan
        :return: {json} The copied scan
        """
        chosen_scan = None

        for scan in self.get_scan_list()['usable']:
            if scan['id'] == scan_id:
                chosen_scan = scan
                break

        if chosen_scan:
            url = '{}/rest/scan/{}/copy'.format(self.server_address, scan_id)
            res = self.session.post(url, json={
                "name": new_scan_name,
                "targetUser": {
                    "id": target_user_id
                }
            })
            self.validate_response(res, "Unable to copy scan {}".format(scan_id))

            return res.json()['response']

        raise TenableSecurityCenterException("Scan {} not found.".format(scan_id))

    def launch_scan(self, scan_id):
        """
        Launches the Scan associated with {id}.
        :param scan_id: {str} The scan id
        :return: {json} Scan details
        """
        url = '{}/rest/scan/{}/launch'.format(self.server_address, scan_id)
        res = self.session.post(url)
        self.validate_response(res, "Unable to launch scan {}".format(scan_id))

        return res.json()['response']

    def create_new_scan(self, name, policy_id, description='',
                        repository_id='1',
                        dhcp_tracking=True,
                        scanning_virtual_hosts=False, assets=[],
                        ip_list=[], max_scan_time='unlimited', reports=[],
                        credentials=[]):
        """
        :param name: Name of the scan
        :param description: Descriptino of the scan
        :param repository_id: {str} The id of the repository to create the scan in.
        :param dhcp_tracking: {bool} Whether to enable DHCP tracking.
        :param scanning_virtual_hosts: {bool} Whether to scan virtualhosts
        :param assets: {list} List of assets
        :param ip_list: {list}  A comma separated string with a list of available IPs
        :param max_scan_time: {str} Max scan duration time (number or unlimited)
        :param reports: {list} List of reports
        :param credentials: {list} List of credentials
        :return: a json object with the complete result. field ['response']['id'] contains the ID of the scan to be used for launch (and potentially for reports)
        """
        data = {
            "name": name,
            "type": "policy",
            "description": description,
            "repository": {
                "id": repository_id
            },
            "policy": {
                "id": policy_id
            },
            "dhcpTracking": dhcp_tracking,
            "classifyMitigatedAge": 0,
            "schedule": {
                "type": "template",
            },
            "reports": reports,
            "assets": assets,
            "credentials": credentials,
            "emailOnLaunch": False,
            "emailOnFinish": False,
            "timeoutAction": "rollover",
            "scanningVirtualHosts": scanning_virtual_hosts,
            "rolloverType": "template",
            "ipList": ",".join(ip_list),
            "maxScanTime": max_scan_time
        }
        url = '{}/rest/scan'.format(self.server_address)

        res = self.session.post(url, json=data)
        self.validate_response(res, "Unable to create new scan")

        return res.json()['response']

    def get_scan_result(self, scan_result_id):
        """
        Get scan results by id (the vulnerability summary)
        :param scan_result_id: {str} The scan results id
        :return: {json} The scan results
        """
        data = {
            "scanID": scan_result_id,
            "query": {
                "scanID": scan_result_id,
                "tool": "sumid",
                "view": "all",
                "type": "vuln"
            },
            "sourceType": "individual",
            "type": "vuln",
            "sortField": "severity",
            "sortDir": "desc",
        }

        url = '{}/rest/analysis'.format(self.server_address)

        res = self.session.post(url, json=data)
        self.validate_response(res, "Unable to get scan results")

        results = res.json()['response']['results']

        # Result's family, severity and severity come as a dict.
        # As only the name interests us, extract it and overwrite the result.
        for result in results:
            result['family'] = result['family']['name']
            result['severity'] = result['severity']['name']

        return results

    def get_scan_status(self, scan_result_id):
        """
        Get status of a scan
        :param scan_result_id: {str} The scan id
        :return: {json} The results of the scan
        """
        url = '{}/rest/scanResult/{}'.format(self.server_address, scan_result_id)

        res = self.session.get(url)
        self.validate_response(res, "Unable to get scan status for id {}".format(scan_result_id))

        return res.json()['response']

    def get_severity_summary(self, scan_result_id):
        """
        Get severity summary of a scan result
        :param scan_result_id: {int} The is of the scan result
        :return: {json} The severity summary
        """
        data = {
            "query":
                {
                    "type": "vuln",
                    "tool": "sumseverity",
                    "sourceType": "individual",
                    "startOffset": 0,
                    "endOffset": OFFSET,
                    "vulnTool": "sumseverity",
                    "scanID": scan_result_id,
                    "view": "all"
                },
            "sourceType": "individual",
            "scanID": scan_result_id,
            "sortField": "severity",
            "sortDir": "desc",
            "type": "vuln"
        }

        url = "{}/rest/analysis".format(self.server_address)

        res = self.session.post(url, json=data)
        self.validate_response(res, "Unable to get severity summary")

        return res.json()['response']['results']

    def is_scan_complete(self, scan_result_id):
        """
        Checks whether a scan is complet
        :param scan_result_id: {int} The scan result id
        :return: {bool} True if complete, otherwise False.
        """
        return self.get_scan_status(scan_result_id)['running'] == "false"

    def get_policy_id_by_name(self, name):
        """
        Get policy id by policy name
        :param name: {str} The policy name
        :return: {int} The matching policy id
        """
        policy_list = self.get_policy_list()
        for policy in policy_list['usable']:
            if policy['name'] == name:
                return policy['id']

        raise TenableSecurityCenterException("Policy {} not found".format(name))

    def create_and_launch_scan_by_policy_name(self, scan_name, policy_name, ip_list=[], wait_for_results=False):
        """
        Create a scan, launch it and get results
        :param scan_name: {str} The name of the scan to create
        :param policy_name: {str} The name of the policy
        :param ip_list: {str} The ips to scan
        :param wait_for_results: {bool} Whether to wait for the scan to complete
        :return: {json/int} The scan results if wait_for_results=True, otherwise the scan results id
        """
        scan = self.create_new_scan(scan_name,
                                   self.get_policy_id_by_name(policy_name),
                                   ip_list=ip_list)

        scan_id = scan['id']
        scan_details = self.launch_scan(scan_id)
        scan_result_id = scan_details['scanResult']['id']

        if wait_for_results:
            return self.wait_for_scan_results(scan_result_id)

        return scan_result_id

    def create_ip_list_asset(self, name, description, tags, ips):
        """
        Create an IP list asset in Tenable.sc
        :param name: {str} Name of the asset
        :param description: {str} Description of the asset
        :param tags: {str} Tags of the asset
        :param ips: {list} List of IPs
        :return: {IPListAsset}
        """
        request_url = self._get_full_url(u"get_assets")
        payload = {
            u"tags": tags,
            u"name": name,
            u"description": description,
            u"type": "static",
            u"definedIPs": ips
        }
        response = self.session.post(request_url, json=payload)
        self.validate_response(response)
        return self.parser.build_ip_list_asset(response.json())

    def wait_for_scan_results(self, scan_result_id):
        """
        Wait for scan ot complete and return the results
        :param scan_result_id: {str} The scan result id
        :return: {json} The scan results
        """
        while not self.is_scan_complete(scan_result_id):
            time.sleep(2)

        return self.get_scan_result(scan_result_id)

    def paginate_vulnerabilities(self, vulnerabilities, url, data, total, error_message):
        """
        Handle pagination for vulnerabilities
        :param vulnerabilities: {list} List of the vulnerabilities in first page
        :param url: {str} The url
        :param data: {dict} The payload data
        :param total: {int} The total excpected result count.
        :param error_message: {str} The error message to display if an error occurres.
        :return: {list} List of all the vulnerabilities.
        """
        while len(vulnerabilities) < total:
            data["query"]["startOffset"] = data["query"]["startOffset"] + OFFSET
            data["query"]["endOffset"] = data["query"]["endOffset"] + OFFSET

            res = self.session.post(url, json=data)
            self.validate_response(res, error_message)

            vulnerabilities.extend(res.json()['response']['results'])

        return vulnerabilities

    def get_vulnerabilities(self, days_ago=1, start_offset=0, limit=10):
        """
        Get vulnerabilities for the last {days_ago} days
        :param days_ago: {int} The number of days ago to search in
        :param start_offset: Specifies the start offset for fetching data.
        :param limit: The limit for results
        :return: {json} The found vulnerabilities
        """
        data = {"query": {
            "type": "vuln",
            "tool": "sumid",
            "sourceType": "cumulative",
            "startOffset": start_offset,
            "endOffset": start_offset + limit,
            "filters": [
                {"id": "firstSeen",
                 "filterName": "firstSeen",
                 "operator": "=",
                 "type": "vuln",
                 "isPredefined": True,
                 "value": "{}:{}".format((days_ago - 1) if days_ago >= 1 else 0, days_ago if days_ago >= 0 else 0)}
            ],
        },
            "sourceType": "cumulative",
            "sortField": "firstSeen",
            "sortDir": "asc",
            "type": "vuln"
        }

        url = '{}/rest/analysis'.format(self.server_address)
        res = self.session.post(url, json=data)
        self.validate_response(res, "Unable to get vulnerabilities")
        return res.json().get('response', {}).get('results', [])

    def get_plugin_info(self, plugin_id):
        """
        Get plugin info
        :param plugin_id: {str} The plugin id
        :return: {json} The plugin info
        """
        url = '{}/rest/plugin/{}'.format(self.server_address, plugin_id)

        res = self.session.get(url)
        self.validate_response(res, "Unable to get plugin info")

        return res.json()['response']

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            if response.json()['error_code'] != 0:
                raise TenableSecurityCenterException(response.json()['error_msg'])

            raise TenableSecurityCenterException(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

    @staticmethod
    def construct_csv(results):
        """
        Constructs a csv from results
        :param results: The results to add to the csv (results are list of flat dicts)
        :return: {list} csv formatted list
        """
        csv_output = []
        headers = reduce(set.union, map(set, map(dict.keys, results)))

        csv_output.append(",".join(map(str, headers)))

        for result in results:
            csv_output.append(
                ",".join([s.replace(',', ' ') for s in
                          map(str,
                              [unicode(result.get(h, None)).encode('utf-8') for
                               h in headers])]))

        return csv_output

    def get_report_by_id(self, report_id):
        """
        Get report by ID.
        :param report_id: {string} Report ID.
        :return: {dict} Report.
        """
        url = '{}/rest/report'.format(self.server_address)
        response = self.session.get(url, params={"id": report_id})
        self.validate_response(response)
        try:
            report = response.json().get('response')
        except Exception as err:
            raise Exception("Failed fetching report JSON, Response Content: {0}, Error: {1}".format(
                response.content,
                err.message
            ))

        if report:
            return report
        raise Exception('Failed fetching report, content: {0}, status code: {1}'.format(response.content,
                                                                                       response.status_code))

    def get_report_by_name(self, report_name):
        """
        Get report by name.
        :param report_name: {string} Report name.
        :return: {dict} Report.
        """
        url = '{}/rest/report'.format(self.server_address)
        response = self.session.get(url, params={"name": report_name})
        self.validate_response(response)
        try:
            report = response.json().get('response')
        except Exception as err:
            raise Exception("Failed fetching report JSON, Response Content: {0}, Error: {1}".format(
                response.content,
                err.message
            ))

        if report:
            return report
        raise Exception('Failed fetching report, content: {0}, status code: {1}'.format(response.content,
                                                                                       response.status_code))

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {unicode} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {unicode} The full url
        """
        return urlparse.urljoin(self.server_address, ENDPOINTS[url_id].format(**kwargs))

    def get_asset_details(self, asset_id, only_type_fields):
        """
        Get asset details.
        :param asset_id: {str} Id of the asset
        :param only_type_fields: {bool} If true, will fetch only type fields
        :return: {IPListAsset}
        """
        request_url = self._get_full_url(u'asset_details', asset_id=asset_id)
        params = {u"fields": u"typeFields"} if only_type_fields else {}
        response = self.session.get(request_url, params=params)
        self.validate_response(response)
        return self.parser.build_ip_list_asset(response.json())

    def update_ip_list_asset(self, asset_id, ips):
        """
        Update ips in asset.
        :param asset_id: {str} Id of the asset
        :param ips: {list} List of IPs
        :return: {IPListAsset}
        """
        request_url = self._get_full_url(u'asset_details', asset_id=asset_id)
        params = {
            u"fields": u"typeFields"
        }
        payload = {
            u"definedIPs": ips
        }
        response = self.session.patch(request_url, params=params, json=payload)
        self.validate_response(response)
        return self.parser.build_ip_list_asset(response.json())

    def get_scan_results(self, scan_name, asset_name, policy_id, repository_id, description):
        """
        Execute asset scan
        :param scan_name: {str} The name for the scan
        :param asset_name: {str} The name of the asset that should be scanned
        :param policy_id: {int} The id of the policy that should be used in the scan
        :param repository_id: {int} The id of the repository that should be used in the scan
        :param description: {str} The description for the scan.
        :return: {Scan} The Scan object
        """
        asset_id = self.get_asset_id_by_asset_name(asset_name)
        if not asset_id:
            raise AssetNotFoundException

        return self.execute_scan(scan_name, asset_id, policy_id, repository_id, description)

    def get_asset_id_by_asset_name(self, asset_name):
        """
        Get the id of asset by asset name
        :param asset_name: The name of the asset which should be found
        :return: {int} The asset id
        """
        url = self._get_full_url("get_assets")
        params = {
            u"fields": u"name",
            u"filter": u"usable"
        }

        response = self.session.get(url, params=params)
        self.validate_response(response)
        return self.parser.get_asset_id(response.json(), asset_name)

    def execute_scan(self, scan_name, asset_id, policy_id, repository_id, description):
        """
        Execute Scan
        :param scan_name: {str} The name for the scan
        :param asset_id: {int} The id of the asset that should be scanned
        :param policy_id: {int} The id of the policy that should be used in the scan
        :param repository_id: {int} The id of the repository that should be used in the scan
        :param description: {str} The description for the scan.
        :return: {Scan} The Scan object
        """
        url = self._get_full_url(u"scan")
        payload = {
            u"name": scan_name,
            u"description": description,
            u"repository": {
                u"id": repository_id
            },
            u"type": u"policy",
            u"policy": {
                u"id": policy_id
            },
            u"assets": [
                {
                    u"id": asset_id
                }
            ],
            u"schedule": {
                u"type": u"now",
                u"enabled": u"true"
            }
        }

        response = self.session.post(url, json=payload)
        self.validate_response(response)
        return self.parser.build_scan_object(response.json())

