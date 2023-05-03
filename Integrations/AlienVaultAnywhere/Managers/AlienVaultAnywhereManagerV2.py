# ==============================================================================
# title           :AlienVaultAnywhereManagerv2.py
# description     :This Module contain all AlienVaultAnywhere API functionality (v2)
# python_version  :2.7
# api_version     :v2.0
# ==============================================================================

import requests
from SiemplifyParser import SiemplifyParser

LIMIT_PER_REQUEST = 100
SORT_PARAM = "timestamp_occured,asc"


class AlienVaultAnywhereManagerV2Exception(Exception):
    pass


class AlienVaultAnywhereManagerV2(object):
    def __init__(self, api_root, username, password, use_ssl=False,
            siemplify=None):
        self.api_root = api_root[:-1] if api_root.endswith("/") else api_root
        self.session = requests.Session()
        self.session.verify = use_ssl
        self.login(username, password)
        self.siemplify_parser = SiemplifyParser()
        self.siemplify = siemplify

    def login(self, username, password):
        """
        authenticate to AlienVault Anywhere.
        The AlienVault REST API v2.0 is secured by OAuth 2.0.
        The AlienVault REST API v2.0 only supports the client_credentials grant type.
        :return: {boolean} True if success
        """
        # Open the login page
        base_login_url = "{}/api/2.0/oauth/token".format(self.api_root)
        params = {'grant_type': 'client_credentials'}

        response = self.session.post(base_login_url, params=params, auth=(username, password))
        self.validate_response(response, "Unable to login")

        response_data_json = response.json()

        # update headers with OAuth Bearer token to use with all other resource requests.
        self.session.headers = {
            "Authorization": "{0} {1}".format(response_data_json.get("token_type"),
                                              response_data_json.get("access_token")),
            "Content-Type": "application/json"
        }

        return True

    def test_connectivity(self):
        """
        Test connectivity to AlienVault Anywhere
        :return: {bool} True if successful, exception otherwise.
        """
        return self.get_alarms(limit=1)

    def _paginate_results(self, url, limit=None, from_time=None, to_time=None, alarms_json_ids=[], priority=None,
                          show_suppressed=False, use_suppressed_filter=False, intent=None, strategy=None, method=None):
        """
        Paginate the results
        :param url: {str} The url to send request to
        :param limit: {int} The limit of the results to fetch
        :param from_time: {str} Fetch results that were created after the specified date. (unix timestamp)
        :param to_time: {str} Time to fetch alarms until (unix timestamp)
        :param alarms_json_ids: {list} old ids
        :param priority: {str}  The priority of the alarm. e.g. medium
        :param show_suppressed: {boolean} filter alarms by the suppressed flag.
        :param use_suppressed_filter: {boolean} indicator to use suppressed filter or not
        :param intent: {string} The intent of the rule that triggered the alarm. e.g. Environmental Awareness
        :param strategy: {string} The strategy of the rule that triggered the alarm. e.g. Network Access Control Modification
        :param method: {string} The method of the rule that triggered the alarm. e.g. AWS EC2 Security Group Modified
        :return: {list} List of results
        """
        current_page = 0
        params = {
            "sort": SORT_PARAM,
            'page': current_page,
            'size': str(LIMIT_PER_REQUEST),
            'timestamp_occured_gte': from_time,
            'timestamp_occured_lte': to_time,

        }

        #if show_suppressed and not use_suppressed_filter or not show_suppressed and not use_suppressed_filter => no filter is used and everything will be ingested
        if show_suppressed and use_suppressed_filter:
            params.update({"suppressed": "true"})
    
        if not show_suppressed and use_suppressed_filter:
            params.update({"suppressed": "false"})

        if priority:
            params.update({"priority_label": priority})
        if intent:
            params.update({"rule_intent": intent})
        if strategy:
            params.update({"rule_strategy": strategy})
        if method:
            params.update({"rule_method": method})

        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to get alarms")
        results = response.json().get("_embedded", {}).get("alarms", [])

        # filter old ids
        filtered_results = [alarm for alarm in results if alarm.get('uuid') not in alarms_json_ids]

        while len(results) < response.json()["page"]["totalElements"]:
            if limit and len(filtered_results) >= limit:
                return filtered_results[:limit]

            current_page += 1

            params.update({
                'page': current_page
            })

            response = self.session.get(url, params=params)

            self.validate_response(response, "Unable to get alarms")
            new_results = response.json().get("_embedded", {}).get("alarms", [])
            # filter old ids
            new_filtered_results = [alarm for alarm in new_results if alarm.get('uuid') not in alarms_json_ids]
            results.extend(new_results)
            filtered_results.extend(new_filtered_results)

        return filtered_results[:limit] if limit else filtered_results

    def get_alarm_by_id(self, alarm_id):
        """
        Get an alarm by ID
        :param alarm_id: {str} The ID of the alarm
        :return: {Alarm} The found alarm
        """
        url = "{}/api/2.0/alarms/{}".format(self.api_root, alarm_id)
        response = self.session.get(url)
        self.validate_response(response, "Unable to get alarm {}".format(alarm_id))
        return self.siemplify_parser.build_siemplify_alarm_object(response.json())

    def get_alarms(self, limit=None, from_time=None, to_time=None, alarms_json_ids=[], priorities=None,
                   show_suppressed=False, use_suppressed_filter=False, intent=None, strategy=None, method=None):
        """
        Get alarms
        :param limit: {int} Max amount of alarms to return
        :param from_time: {str} Time to fetch alarms from (unix timestamp)
        :param to_time: {str} Time to fetch alarms until (unix timestamp)
        :param limit: {int} Alarms count limit
        :param alarms_json_ids: {list} alarms ids that already fetched
        :param priorities: {list}  The priority of the alarm. e.g. medium
        :param show_suppressed: {boolean} filter alarms by the suppressed flag.
        :param use_suppressed_filter: {boolean} indicator to use suppressed filter or not
        :param intent: {string} The intent of the rule that triggered the alarm. e.g. Environmental Awareness
        :param strategy: {string} The strategy of the rule that triggered the alarm. e.g. Network Access Control Modification
        :param method: {string} The method of the rule that triggered the alarm. e.g. AWS EC2 Security Group Modified
        :return: {list} of {AlienVaultAlarmModel} The alarm info after parsing
        """
        alarms = []
        alarms_url = "{}/api/2.0/alarms".format(self.api_root)

        if priorities:
            # AlienVault V2 API is not supporting filtering by multiple priorities at the same time (even though
            # documentation says otherwise). So fetch alarms for each given priority in a separate request
            # and join them all together
            for priority in priorities:
                alarms.extend(
                    self._paginate_results(
                        url=alarms_url, limit=limit, from_time=from_time, to_time=to_time,
                        alarms_json_ids=alarms_json_ids, show_suppressed=show_suppressed,
                        intent=intent, use_suppressed_filter=use_suppressed_filter,
                        strategy=strategy, method=method, priority=priority)
                )

        else:
            alarms = self._paginate_results(
                url=alarms_url, limit=limit, from_time=from_time, to_time=to_time,
                alarms_json_ids=alarms_json_ids, show_suppressed=show_suppressed,
                intent=intent, use_suppressed_filter=use_suppressed_filter,
                strategy=strategy, method=method
            )

        # Convert raw data to Siemplify objects (datamodel objects)
        siemplify_alarm_objects = [self.siemplify_parser.build_siemplify_alarm_object(alarm) for alarm in alarms]

        # Sort the found alarms by timestamp
        siemplify_alarm_objects = sorted(siemplify_alarm_objects, key=lambda alarm: alarm.timestamp)

        # Return alarms up to the set limit
        return siemplify_alarm_objects[:limit] if limit else siemplify_alarm_objects

    def get_events(self, start_time=None, end_time=None, account_name=None, event_name=None, source_name=None, limit=None,
                      asc=False, suppressed=False):
        """
        List events
        :param start_time: {int} Filtered results will include events that occurred after this timestamp (milliseconds).
        :param end_time: {int} Filtered results will include events that occurred before this timestamp (milliseconds).
        :param account_name: {str} The account name.
        :param event_name: {str} The name of the event.
        :param source_name: {str} The source name
        :param limit: {int} Max number of events to return
        :param asc: {bool} Whether to return the results in ascending or descending order
        :param suppressed: {bool} A boolean to filter events by the suppressed flag.
        :return: {[Event]} The found events
        """
        events_url = "{}/api/2.0/events".format(self.api_root)

        params = {
            'page': 0,
            'size': min(LIMIT_PER_REQUEST, limit) if limit else LIMIT_PER_REQUEST,
            'sort': 'timestamp_occured,{}'.format('asc' if asc else 'desc'),
        }

        if account_name:
            params['account_name'] = account_name
        if event_name:
            params['event_name'] = event_name
        if source_name:
            params['source_name'] = source_name
        if start_time:
            params['timestamp_occured_gte'] = start_time
        if end_time:
            params['timestamp_occured_lte'] = end_time
        if suppressed:
            params['suppressed'] = suppressed

        response = self.session.get(events_url, params=params)
        self.validate_response(response, "Unable to get events")

        raw_events = response.json().get("_embedded", {}).get("eventResources", [])
        events = [self.siemplify_parser.build_siemplify_event_object(raw_event) for raw_event in raw_events]

        while len(events) < response.json().get("page", {}).get("totalElements", 0):
            if limit and len(events) >= limit:
                break

            params.update({
                'page': params['page'] + 1
            })

            response = self.session.get(events_url, params=params)
            self.validate_response(response, "Unable to get events")

            raw_events = response.json().get("_embedded", {}).get("eventResources", [])
            events.extend([self.siemplify_parser.build_siemplify_event_object(raw_event) for raw_event in raw_events])

        return events[:limit] if limit else events

    @staticmethod
    def validate_response(res, error_msg="An error occurred"):
        """
        Validate a response
        :param error_msg: {str} The error message to display
        :param res: {requests.Response} The response to validate
        """
        try:
            res.raise_for_status()

        except requests.HTTPError as error:
            raise Exception(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )



