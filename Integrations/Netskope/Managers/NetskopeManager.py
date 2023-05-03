# ============================================================================#
# title           :NetskopeManager.py
# description     :This Module contain all Netskope operations functionality
# author          :avital@siemplify.co
# date            :02-12-2018
# python_version  :2.7
# libreries       :requests
# requirments     :
# ============================================================================#

# ============================= IMPORTS ===================================== #

import requests
from NetskopeTransformationalLayer import NetskopeTransformationalLayer

# ============================== CONSTS ===================================== #


MAX_LIMIT = 5000
ERROR_STATUS = "error"
TYPES = ["page", "application", "audit", "infrastructure"]

# ============================= CLASSES ===================================== #
class NetskopeManagerError(Exception):
    pass


class NetskopeManager(object):
    def __init__(self, api_root, api_token, verify_ssl=False):
        """
        :param api_root: {string} Netskope api root URL.
        :param token: {string} Authorization token.
        """
        self.api_root = api_root if api_root[-1:] == '/' else api_root + '/'
        self.api_token = api_token
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.parser = NetskopeTransformationalLayer()

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

            if response.json().get("status") == ERROR_STATUS:
                raise NetskopeManagerError(
                    "{error_msg}: {error} {text}".format(
                        error_msg=error_msg,
                        error=response.json()['errorCode'],
                        text=",".join(response.json().get('errors', [])))
                )

        except requests.HTTPError as error:
            raise NetskopeManagerError(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

    def test_connectivity(self):
        """
        Test connectivity to Netskope
        :return: {bool} True if succeed.
        """
        self.get_clients()
        return True

    def get_events(self, query=None, alert_type=None, timeperiod=None, start_time=None,
                   end_time=None, limit=None):
        """
        Get events
        :param query: {str} This acts as a filter for all the cloud app events in the events database.
        :param alert_type: {str} page | application | audit | infrastructure.
            Selects page events, application events,
            audit events, or infrastructure events. Application events are
            triggered for user actions inside the cloud app. Page events are
            triggered for the http/https connection. Audit and infrastructure
            events are logged for administrator activity in the Netskope UI.
        :param timeperiod: {int} 3600 | 86400 | 604800 | 2592000
        :param start_time: {int} Restrict events to those that have timestamps greater than this. Needed only if timeperiod is not passed. Unixtime.
        :param end_time: {int} Restrict events to those that have timestamps less than or equal to this. Needed only if timeperiod is not passed. Unixtime.
        :param limit: {int} Limit the number of events returned
        :return: {list} The found events
        """
        url = "{}/api/v1/events".format(self.api_root)
        params = {
            'token': self.api_token,
            'query': query,
            'type': alert_type,
            'timeperiod': timeperiod,
            'starttime': start_time,
            'endtime': end_time,
            'limit': min(limit, MAX_LIMIT) if limit else MAX_LIMIT,
            'skip': 0
        }

        params = {k:v for k,v in list(params.items()) if v is not None}
        return self._paginate_results(url, params, limit, "Unable to get events")

    def get_all_events(self, query=None, timeperiod=None, start_time=None,
                   end_time=None, limit=None):
        """
        Get all events (regardless of their type)
        :param query: {str} This acts as a filter for all the cloud app events in the events database.
        :param timeperiod: {int} 3600 | 86400 | 604800 | 2592000
        :param start_time: {int} Restrict events to those that have timestamps greater than this. Needed only if timeperiod is not passed. Unixtime.
        :param end_time: {int} Restrict events to those that have timestamps less than or equal to this. Needed only if timeperiod is not passed. Unixtime.
        :param limit: {int} Limit the number of events returned
        :return: {list} The found events
        """
        events = []
        for alert_type in TYPES:
            if len(events) < limit:
                limit = limit - len(events)
                events.extend(
                    self.get_events(query, alert_type, timeperiod, start_time,
                                    end_time, limit=limit
                                    )
                )

        return events

    def get_alerts(self, query=None, alert_type=None, acked=None, timeperiod=None, start_time=None,
                   end_time=None, limit=None):
        """
        Get alerts
        :param query: {str} This acts as a filter for all the cloud app events in the events database.
        :param alert_type: {str} anomaly | 'Compromised Credential' | policy |
            'Legal Hold' | malsite | Malware | DLP | watchlist |
            quarantine | Remediation
            Selects Policy, DLP, Quarantine or Watchlist alerts.
            If nothing is passed then it gets alerts of all types.
        :param acked: {bool} Selects the type of alerts. If nothing is passed, then it gets alerts of all types.
        :param timeperiod: {int} 3600 | 86400 | 604800 | 2592000
        :param start_time: {int} Restrict alerts to those that have timestamps greater than this. Needed only if timeperiod is not passed. Unixtime.
        :param end_time: {int} Restrict alerts to those that have timestamps less than or equal to this. Needed only if timeperiod is not passed. Unixtime.
        :param limit: {int} Limit the number of alerts returned
        :return: {list} The found alerts
        """
        url = "{}/api/v1/alerts".format(self.api_root)
        params = {
            'token': self.api_token,
            'query': query,
            'type': alert_type,
            'acked': acked,
            'timeperiod': timeperiod,
            'starttime': start_time,
            'endtime': end_time,
            'limit': min(limit, MAX_LIMIT) if limit else MAX_LIMIT,
            'skip': 0
        }

        params = {k:v for k,v in list(params.items()) if v is not None}
        return self._paginate_results(url, params, limit, "Unable to get alerts")

    def get_clients(self, query=None, limit=None):
        """
        Get clients info
        :param query: {str} This acts as a filter on all the entries in the database.
        :param limit: {int} Limit the number of clients returned
        :return: {list} The clients info
        """
        url = "{}/api/v1/clients".format(self.api_root)
        params = {
            'token': self.api_token,
            'query': query,
            'limit': min(limit, MAX_LIMIT) if limit else MAX_LIMIT,
            'skip': 0
        }

        params = {k:v for k,v in list(params.items()) if v is not None}
       # return [client.get("attributes") for client in self._paginate_results(url, params, limit, "Unable to get clients")]
        return [self.parser.build_siemplify_client(client) for client in self._paginate_results(url, params, limit, "Unable to get clients")]


    def get_quarantined_files(self, start_time=None, end_time=None):
        """
        Get all quarantined results
        :param start_time: {int} Get files last modified within a certain time period. Unixtime.
            If not provided starttime is assumed to be 0 and endtime is assumed to be the current time.
        :param end_time: {int} Get files last modified within a certain time period. Unixtime.
            If not provided starttime is assumed to be 0 and endtime is assumed to be the current time.
        :return: {list} The quarantined files
        """
        url = "{}/api/v1/quarantine".format(self.api_root)
        params = {
            'token': self.api_token,
            'op': "get-files",
            'starttime': start_time,
            'end_time': end_time
        }

        params = {k:v for k,v in list(params.items()) if v is not None}
        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to get quarantined files")

        quarantines = response.json().get("data", {}).get("quarantined", [])

        files = []
        for quarantine in quarantines:
            for quarantined_file in quarantine.get("files", []):
                quarantined_file.update({"quarantine_profile_id": quarantine.get("quarantine_profile_id")})
                quarantined_file.update({"quarantine_profile_name": quarantine.get("quarantine_profile_name")})
                files.append(quarantined_file)

        return files

    def block_file(self, file_id, quarantine_profile_id):
        """
        Block a file
        :param file_id: {str} The id of the file
        :param quarantine_profile_id: {str} The id of the quarantine profile that the file is part of
        :return: {bool} True if successful, exception otherwise.
        """
        url = "{}/api/v1/quarantine".format(self.api_root)
        params = {
            'token': self.api_token,
            'op': "take-action",
            'file_id': file_id,
            'quarantine_profile_id': quarantine_profile_id,
            'action': "block",
        }

        params = {k: v for k, v in list(params.items()) if v is not None}
        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to do action on quarantined file")

        return True

    def allow_file(self, file_id, quarantine_profile_id):
        """
        Allow a file
        :param file_id: {str} The id of the file
        :param quarantine_profile_id: {str} The id of the quarantine profile that the file is part of
        :return: {bool} True if successful, exception otherwise.
        """
        url = "{}/api/v1/quarantine".format(self.api_root)
        params = {
            'token': self.api_token,
            'op': "take-action",
            'file_id': file_id,
            'quarantine_profile_id': quarantine_profile_id,
            'action': "allow",
        }

        params = {k: v for k, v in list(params.items()) if v is not None}
        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to do action on quarantined file")

        return True

    def download_file(self, file_id, quarantine_profile_id):
        """
        Download a quarantined file
        :param file_id: {str} The id of the file
        :param quarantine_profile_id: {str} The id of the quarantine profile that the file is part of
        :return: {str} The content of the quarantined file
        """
        url = "{}/api/v1/quarantine".format(self.api_root)
        params = {
            'token': self.api_token,
            'op': "download-url",
            'file_id': file_id,
            'quarantine_profile_id': quarantine_profile_id,
        }

        params = {k: v for k, v in list(params.items()) if v is not None}
        response = self.session.get(url, params=params)

        if response.history:
            download_url = response.url
            download_response = self.session.get(download_url)
            download_response.raise_for_status()
            return download_response.content

        raise NetskopeManagerError("Unable to download a quarantined file")

    def get_security_assessment(self, platform, instance_name, profile_name=None,
                                region=None, service=None, rule_name=None,
                                severity=None, resource_id=None, limit=None):
        """
        Gt security assessment violations from the latest scan
        :param platform: {str} Specifies the Iaas platform provider. This is a required parameter.
        :param instance_name: {str} The Introspection instance name. This is a required parameter.
        :param profile_name: {str} The Security Assessment profile name. This is an optional parameter.
        :param region: {str} The location reference. This is an optional parameter.
            For Azure, only one value is currently available: all
            For AWS, possible values are:
                ap-south-1
                ap-northeast-2
                ap-southeast-1
                ap-southeast-2
                ap-northeast-1
                ca-central-1
                eu-central-1
                eu-west-1
                eu-west-2
                eu-west-3
                eu-west-3
                sa-east-1
                us-east-1
                us-east-2
                us-west-1
                us-west-2
                global
        :param service: {str} The resource category. This is an optional parameter.
        :param rule_name: {str} The Security Assessment rule name. This is an optional parameter.
        :param severity: {str} The Security Assessment rule severity. This is an optional parameter.
        :param resource_id: {str} The resource identifier created by the IaaS platform provider. This is an optional parameter.
        :param limit: {int} The number of results returned.
        :return: {list} The found security assessments.
        """
        url = "{}/api/v1/security_assessment".format(self.api_root)
        params = {
            'token': self.api_token,
            'platform': platform,
            'instance_name': instance_name,
            'profile_name': profile_name,
            'region': region,
            'service': service,
            'rule_name': rule_name,
            'severity': severity,
            'resource_id': resource_id,
            'limit': min(limit, MAX_LIMIT) if limit else MAX_LIMIT,
            'skip': 0
        }

        params = {k: v for k, v in list(params.items()) if v}
        return self._paginate_results(url, params, limit,
                                      "Unable to get security assessments")

    def _paginate_results(self, url, params, limit=None, error_msg="Unable to get results"):
        """
        Paginate results
        :param url: {str} The url to get the results from
        :param params: {dict} The params of the request
        :param limit: {int} The number of results returned
        :param error_msg: {str} The message to display on error
        :return: {list} The results
        """
        response = self.session.get(url, params=params)
        self.validate_response(response, error_msg)
        results = response.json().get('data')

        while response.json().get("data"):
            if limit and limit < MAX_LIMIT:
                if len(results) >= limit:
                    return results[:limit]
                return results

            params.update({
                'skip': params['skip'] + (min(MAX_LIMIT, limit - MAX_LIMIT) if limit else MAX_LIMIT)
            })
            response = self.session.get(url, params=params)

            self.validate_response(response, error_msg)
            results.extend(response.json().get('data', []))

        return results

