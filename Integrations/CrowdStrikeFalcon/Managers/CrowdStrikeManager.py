import json
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urljoin
import requests
from datetime import datetime
from CrowdStrikeParser import CrowdStrikeParser
from exceptions import CrowdStrikeManagerError, CrowdStrikeSessionCreatedError, CrowdStrikeNotFoundError
from constants import (
    FILTER_STRATEGY_MAPPING,
    OPEN,
    REOPEN,
    API_ROOT_DEFAULT,
    FilterStrategy,
    IOC_DEFAULT_SEVERITY,
    SEVERITIES,
    ACTION_TYPE_MAPPING,
    UNASSIGN,
    DETECTION_STATUS_MAPPING,
    DATE_TIME_FORMAT
)


DATETIME_FORMAT = "YYYY-MM-DDTHH:MM:SSZ"
HEADERS = {
    "Content-Type": "application/json"
}

SHA256 = 'sha256'
MD5 = 'md5'
ADDRESS = 'ipv4'
DOMAIN = 'domain'
DEFAULT_EXPIRATION_DAYS = 30
PAGE_SIZE = 50
MAX_DETECTIONS_TO_FETCH = 100
MAX_PROCESSED_IDS_PER_REQUEST = 400

POLICY_DEFAULT_FOR_DETECT = 'detect'
STATUS = [OPEN, REOPEN]

API_ENDPOINTS = {
    'fetch_token': 'oauth2/token',
    'queries_devices': 'devices/queries/devices/v1',
    'entities_devices': 'devices/entities/devices/v2',
    'user_uuids': 'users/queries/user-uuids-by-email/v1',
    'detections': 'detects/entities/detects/v2',
    'discover_streams': 'sensors/entities/datafeed/v2',
    'ioc_endpoint': "indicators/entities/iocs/v1",
    'update_ioc': "iocs/entities/indicators/v1",
    'delete_ioc': "iocs/entities/indicators/v1",
    'get_ioc_id': "iocs/queries/indicators/v1",
    'get_alerts': "alerts/queries/alerts/v1",
    'get_alerts_details': 'alerts/entities/alerts/v1',
    'detections_connector': 'detects/queries/detects/v1',
    'detection_details': 'detects/entities/summaries/GET/v1',
    'ioc_queries': 'indicators/queries/devices/v1',
    'devices_actions': 'devices/entities/devices-actions/v2',
    'ioc_listing': 'indicators/queries/iocs/v1',
    'queries_processes': 'indicators/queries/processes/v1',
    'entities_processes': 'processes/entities/processes/v1',
    'vulnerability_ids': 'spotlight/queries/vulnerabilities/v1',
    'vulnerability_details': 'spotlight/entities/vulnerabilities/v2',
    'remediation_details': 'spotlight/entities/remediations/v2',
    'create_session': '/real-time-response/entities/sessions/v1',
    'start_session': 'real-time-response/combined/batch-init-session/v1',
    'responder_command': 'real-time-response/entities/active-responder-command/v1',
    'pull_file_from_host': 'real-time-response/combined/batch-get-command/v1',
    'retrieve_get_command_status': 'real-time-response/combined/batch-get-command/v1',
    'file_content': 'real-time-response/entities/extracted-file-contents/v1',
    'get_iocs': 'iocs/entities/indicators/v1',
    'upload_ioc': 'iocs/entities/indicators/v1',
    'get_host_groups': 'devices/combined/host-groups/v1',
    'get_devices_login_histories': '/devices/combined/devices/login-history/v1',
    'get_devices_online_states': '/devices/entities/online-state/v1',
    'update_alert': '/alerts/entities/alerts/v2'
}


class CrowdStrikeManager(object):
    """
    CrowdStrike Manager
    """

    def __init__(self, client_id, client_secret, use_ssl=False, api_root=API_ROOT_DEFAULT,
                 force_check_connectivity=False, logger=None):
        self.api_root = api_root
        self.session = requests.Session()

        self.session.verify = use_ssl
        self.session.headers = HEADERS
        self.session.headers.update({"Authorization": f"bearer {self.fetch_token(client_id, client_secret, use_ssl)}"})

        self.parser = CrowdStrikeParser()

        self.logger = logger

        if force_check_connectivity:
            self.test_connectivity()

    @staticmethod
    def get_query_filter(filter_dict):
        """
        Get Query filter string
        :param filter_dict: {dict} Filter key values dict
        :return: Return string of filter
        """
        return '+'.join([f"{k}: {v}" if isinstance(v, list) else f"{k}: '{v}'" for k, v in filter_dict.items()])

    @staticmethod
    def _get_valid_params(params):
        return {k: v for k, v in params.items() if v is not None}

    def fetch_token(self, client_id, client_secret, use_ssl=False):
        """
        Fetch authentication token for Devices payloads.
        :param client_id: {str} Client ID.
        :param client_secret: {str} Client Secret.
        :param use_ssl: {bool} Verify SSL.
        :return: {str} Access Token.
        """
        payload = {
            "client_id": client_id,
            "client_secret": client_secret
        }
        response = requests.post(
            self._get_full_url('fetch_token'),
            data=payload,
            verify=use_ssl
        )
        self.validate_response(response)

        access_token = response.json().get('access_token', '')

        if access_token:
            return access_token

        raise Exception("Failed fetching token, Response: {0}, status: {1}".format(response.content,
                                                                                   response.status_code))

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url for session.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, API_ENDPOINTS[url_id].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity to CrowdFalcon.
        :return:
        """
        self.search_devices_ids(limit=1)

        return True

    def search_devices_ids(self, device_id=None, external_ip=None, hostname=None,
                           last_seen=None, local_ip=None, mac_address=None, machine_domain=None,
                           platform_name=None, status=None, limit=None, for_hosts=False):
        """
        Search for hosts in your environment by platform, hostname, IP, and other criteria.
        :param device_id: {str} The ID of the device.
        :param external_ip: {str} External IP of the device, as seen by CrowdStrike.
        :param hostname: {str} The name of the machine. Supports prefix and suffix searching with * wildcard (abc* / *abc)
        :param last_seen: {str} Timestamp of devices most recent connection to Falcon. ex. YYYY-MM-DDTHH:MM:SSZ
        :param local_ip: {str} The device's local IP address. the IP address of this device at the last time it connected
        :param mac_address: {str} The MAC address of the device (2001:db8:ffff:ffff:ffff:ffff:ffff:ffff)
        :param machine_domain: {str} Active Directory domain name.
        :param platform_name: {str} Operating system platform. (Mac, etc)
        :param status: {str} Containment Status of the machine. (Normal, containment_pending, contained, lift_containment_pending)
        :param limit: {int} Max amount of devices to return
        :return: {list} of device details {dict}
        """
        filter_data = {
            'device_id': device_id,
            'external_ip': external_ip,
            'hostname': hostname,
            'last_seen': last_seen,
            'local_ip': local_ip,
            'mac_address': mac_address,
            'machine_domain': machine_domain,
            'platform_name': platform_name,
            'status': status
        }

        filter_data = {key: value for key, value in filter_data.items() if value}

        return self._paginate_results(
            self._get_full_url('queries_devices'),
            params={'filter': self.get_query_filter(filter_data)},
            limit=limit,
            error_msg='Unable to search for devices ids',
            for_hosts=for_hosts)

    def search_devices(self, **kwargs):
        """
        Search for hosts in your environment by platform, hostname, IP, and other criteria.
        :return: {list} of device details {dict}
        """
        starts_with_name = kwargs.get('starts_with_name')
        if starts_with_name:
            kwargs['hostname'] = kwargs.pop('starts_with_name')

        ids = self.search_devices_ids(**kwargs)

        if not ids:
            return []

        devices = self.get_devices(devices_ids=ids, limit=kwargs.get('limit'), for_hosts=kwargs.get('for_hosts'))

        if starts_with_name:
            filtered_devices = [device for device in devices
                                if self.match_device_host_name(device, starts_with_name)]
            return sorted(filtered_devices, key=lambda machine: machine.last_seen_unix) if filtered_devices else None

        return devices

    def search_device_ids(self, **kwargs):
        """
        Search device ids by hostname, IP, and other criteria.
        :return: {list} of device ids
        """
        starts_with_name = kwargs.get('starts_with_name')
        if starts_with_name:
            kwargs['hostname'] = kwargs.pop('starts_with_name')

        ids = self.search_devices_ids(**kwargs)

        return ids if ids else []

    def create_device_session(self, device_id):
        """
        Create session for provided device
        :param device_id: {str} device id
        :return: {str} session_id
        """
        body = {
            "device_id": device_id,
            "origin": "",
            "queue_offline": True
        }
        response = self.session.post(self._get_full_url('create_session'), json=body)
        self.validate_response(response, custom_response=True)

        return self.parser.get_resources(response.json(), builder_method='get_session_id')[0]

    def start_device_session(self, device_id):
        """
        Create session for provided device
        :param device_id: {str} device id
        :return: {str} session_id
        """
        body = {
            "host_ids": [device_id],
            "queue_offline": True
        }
        response = self.session.post(self._get_full_url('start_session'), json=body)
        self.validate_response(response, custom_response=True)

        return self.parser.build_batch_session_object(response.json(), device_id)

    def batch_get_command(self, batch_id, filename):
        """
        Create session for provided device
        :param batch_id: {str} batch id
        :param filename: {str} file name that should be uploaded
        :return: {str}
        """
        payload = {
            "batch_id": batch_id,
            "file_path": filename
        }

        response = self.session.post(self._get_full_url('pull_file_from_host'), json=payload)
        self.validate_response(response, custom_response=True)

        return self.parser.build_batch_get_obj(response.json())

    def get_status_of_batch_command(self, batch_request_id):
        """
        Create session for provided device
        :param batch_request_id: {str} batch_request_id
        :return: {str}
        """
        params = {"batch_get_cmd_req_id": batch_request_id}
        response = self.session.get(self._get_full_url('pull_file_from_host'), params=params)
        self.validate_response(response, custom_response=True)

        return self.parser.get_resources_dict(response.json(), 'build_batch_command_obj')

    def execute_responder_command(self, session_id, command, device_id):
        """
        Execute responder command
        :param session_id: {str} session_id
        :param command: {str} command
        :param device_id: {str} device id
        :return: {str} cloud_request_id
        """
        body = {
            "base_command": command.split()[0],
            "command_string": command,
            "device_id": device_id,
            "persist": True,
            "session_id": session_id
        }
        response = self.session.post(self._get_full_url('responder_command'), json=body)
        self.validate_response(response, custom_response=True)

        return self.parser.get_resources(response.json(), builder_method='get_cloud_request_id')[0]

    def get_status_of_responder_command(self, cloud_request_id):
        """
        Get status of session
        :param cloud_request_id: {str} session_id
        :return: {list} ov Session.obj
        """

        params = {
            'cloud_request_id': cloud_request_id,
            'sequence_id': 0
        }
        response = self.session.get(self._get_full_url('responder_command'), params=params)
        self.validate_response(response, custom_response=True)

        return self.parser.get_resources(response.json(), builder_method='build_command_object')

    def get_file_content(self, session_id, filehash):
        """
        Get file content
        :param session_id: {str} session id
        :param filehash: {str} file hash
        :return: {str} file content
        """
        params = {
            'session_id': session_id,
            'sha256': filehash
        }
        response = self.session.get(self._get_full_url('file_content'), params=params)
        response.raise_for_status()

        return response.content

    def get_devices(self, devices_ids=None, limit=None, for_hosts=False):
        """
        Get devices by its ids
        :param devices_ids {list} list of device ids
        :param limit {int} limit
        """
        devices = self._paginate_results(
            self._get_full_url('entities_devices'),
            params={'ids': devices_ids},
            limit=limit,
            error_msg='Unable to search for devices',
            for_hosts=for_hosts)

        return self.parser.build_results(devices, 'build_siemplify_device_obj', pure_data=True)

    def get_list_devices_by_filter(self, value, filter_strategy, limit=None):
        """
        Get list devices by provided filter field and value
        :param value {str} value to compare
        :param filter_strategy {str} value to search
        :param limit {int}
        :return: {list} List of devices
        """
        devices = self.search_devices(limit=limit,
                                      hostname=[value] if value and filter_strategy == FilterStrategy.Equal.value else None,
                                      for_hosts=True)

        if not (filter_strategy and value):
            return devices[:limit]

        return self.filter_devices(devices, filter_strategy, value, limit=limit)

    def filter_indicator_ids(self, indicator_ids, filter_logic, value, limit=None):
        """
        Filter devices by provided filter field and value
        :param indicator_ids {list} List of Indicators objects
        :param value {str} value to compare
        :param filter_logic {str} value to search
        :param limit {int}
        return {list} List of filtered devices
        """
        found_results = []

        for indicator in indicator_ids:
            indicator_value = indicator.split(':')[-1]
            if FILTER_STRATEGY_MAPPING[filter_logic](indicator_value, value):
                found_results.append(indicator)

            if limit and len(found_results) >= limit:
                break

        return found_results

    def filter_devices(self, devices, filter_strategy, value, limit=None):
        """
        Filter devices by provided filter field and value
        :param devices {list} List of Device objects
        :param value {str} value to compare
        :param filter_strategy {str} value to search
        :param limit {int}
        return {list} List of filtered devices
        """
        found_results = []

        for device in devices:
            if FILTER_STRATEGY_MAPPING[filter_strategy](device.hostname, value):
                found_results.append(device)

            if limit and len(found_results) >= limit:
                break

        return found_results

    def get_detection_status(self, detection_ids):
        """
        Get detection status with the given ID.
        :param detection_ids: {list or str} The unique identifier of the detection.
        :return: {str} Detection status.
        """
        detection_ids = detection_ids if isinstance(detection_ids, list) else [detection_ids]

        response = self.session.post(self._get_full_url('detection_details'), json={'ids': detection_ids})
        self.validate_response(response, f'Unable to get status of the detection with identifier '
                                         f'{", ".join(detection_ids)}')

        resource = self.parser.get_resources(response.json())

        if resource:
            return self.parser.get_detection_status(resource[0])

        raise CrowdStrikeManagerError(
            f'Unable to get status of the detection with identifier {", ".join(detection_ids)}')

    def add_comment_to_detection(self, comment, detection_ids, status):
        """
        Add a comment to the specified detection.
        :param comment: {str} The comment that will add information about the detection.
        :param detection_ids: {list or str} The unique identifier of the detection.
        :param status: {str} The status of the detection.
        :return: {bool} True if successful, raise exception otherwise.
        """
        detection_ids = detection_ids if isinstance(detection_ids, list) else [detection_ids]

        json_payload = {
            'ids': detection_ids,
            'comment': comment,
            'status': status
        }

        response = self.session.patch(self._get_full_url('detections'), json=json_payload)
        self.validate_response(response, f'Failed to add a comment to the detection with identifier '
                                         f'{", ".join(detection_ids)}')

        return True

    def get_user_uuid(self, email):
        """
        Get User UUID with given Email.
        :param email: {str} User Email.
        :return: {list} User UUID.
        """
        response = self.session.get(self._get_full_url('user_uuids'), params={"uid": email})
        self.validate_response(response, f'Unable to get UUID with email {email}')

        return self.parser.get_resources(response.json())

    def get_user_uuid_or_raise(self, email):
        """
        Get User UUID with given Email or raise.
        :param email: {str} User Email.
        :return: {list} List of uuids or raise.
        """
        uuids = self.get_user_uuid(email=email)

        if uuids:
            return uuids[0]

        raise CrowdStrikeManagerError(f'Unable to get UUID with email {email}')

    def update_detection(self, uuid, detection_ids, detection_status):
        """
        Update the status of a detection with the option to assign the detection to a Falcon user.
        :param uuid: {str} User UUID.
        :param detection_ids: {list} The unique identifiers of the detection.
        :param detection_status: {str} The status of the detection.
        :return: {bool} True if successful, raise exception otherwise.
        """
        data = {
            'ids': detection_ids,
            'status': detection_status,
            'assigned_to_uuid': uuid
        }

        response = self.session.patch(self._get_full_url('detections'), json=self._get_valid_params(data))
        self.validate_response(response, f'Failed to update detection {", ".join(map(str, detection_ids))}')

        return True

    def _discover_streams(self, app_name):
        """
        Discover stream link and token to fetch detections
        :param app_name: App name with which stream will be created
        :return: Stream with link and token
        """
        params = {
            'appId': app_name
        }

        response = self.session.get(self._get_full_url('discover_streams'), params=params)
        self.validate_response(response, 'Unable to discover streams')

        return self.parser.build_siemplify_stream(response.json())

    def get_stream_detections(self, app_name, offset, limit):
        """
        Yields a detection from stream
        :param app_name: App name with which stream will be created
        :param offset: Offset from which we will get detections
        :param limit: Limit of detections to fetch
        """
        stream = self._discover_streams(app_name=app_name)
        detections = pauses = 0
        max_pauses = 30

        payload = {'offset': offset} if offset else {}
        response = None

        try:
            response = self.session.get(
                stream.url,
                params=payload,
                stream=True,
                headers={'Authorization': f'Token {stream.token}', 'Accepts': 'application/json'},
                timeout=(5, 10))

            self._validate_stream_response(response)

            for stream_line in response.iter_lines():
                if detections == limit:
                    response.close()
                    break
                if stream_line.strip():
                    detections += 1
                    detection_data = json.loads(stream_line)
                    if not self.parser.get_event_data(detection_data):
                        if self.logger:
                            current_offset = self.parser.get_offset(detection_data)
                            self.logger.info(f'Skipping detection with offset {current_offset}. '
                                             f'Reason: "events" key is empty')
                        continue
                    yield self.parser.build_siemplify_detection_obj(json.loads(stream_line))
                elif pauses >= max_pauses:
                    response.close()
                    break
                pauses += 1

        except Exception as e:
            response.close()
            raise CrowdStrikeManagerError('Stream to fetch detections reaches timeout' if 'Read Timed out' in str(e)
                                          else str(e))

    @staticmethod
    def _validate_stream_response(response, message='Response is not 200'):
        """
        Validate stream response and close if status is not 200
        :param response: Response object
        :param message: Message to raise exception with
        """
        if response.status_code != 200:
            response.close()
            raise CrowdStrikeManagerError(
                '{} (Status code: {}): {}'.format(message, response.status_code, response.text))

    def upload_ioc(
            self, ioc_type, ioc_value, platforms, severity, host_group_ids, action, comment=None
    ):
        """
        Upload custom indicators that you want CrowdStrike to watch.
        :param ioc_type: {str} The type of the indicator. Valid types include:
                sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                sha1: A hex-encoded sha1 hash string. Length - min 40, max: 40.
                md5: A hex-encoded md5 hash string. Length - min 32, max: 32.
                domain: A domain name. Length - min: 1, max: 200.
                ipv4: An IPv4 address. Must be a valid IP address.
                ipv6: An IPv6 address. Must be a valid IP address.
        :param ioc_value: {str} The string representation of the indicator.
        :param platforms: {list} list of the platforms related to the IOC
        :param severity: {str} IOC severity
        :param host_group_ids: {list} list of host group ids
        :param action: {str} param identifies which action will be enabled for this IOC: detect/block
        :param comment: {bool} IOC comment
        :return: {void}
        """
        json_payload = {
            "comment": comment,
            "indicators": [
                {
                    "type": ioc_type,
                    "value": ioc_value,
                    "action": ACTION_TYPE_MAPPING[action],
                    "severity": severity,
                    "platforms": platforms,
                    "host_groups": host_group_ids
                }
            ]
        }
        if not host_group_ids:
            json_payload["indicators"][0].update({"applied_globally": True})

        response = self.session.post(self._get_full_url("upload_ioc"), json=self._get_valid_params(json_payload))
        self.validate_response(response, f"Unable to upload custom ioc {ioc_type}:{ioc_value}")

    def get_custom_indicators(self, ioc_types=None, value=None, filter_logic=None, limit=None):
        """
        Get custom indicators that CrowdStrike is watching.
        :param ioc_types: {list} The list of types for the indicator. Valid types include:
                sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
                sha1: A hex-encoded sha1 hash string. Length - min 40, max: 40.
                md5: A hex-encoded md5 hash string. Length - min 32, max: 32.
                domain: A domain name. Length - min: 1, max: 200.
                ipv4: An IPv4 address. Must be a valid IP address.
                ipv6: An IPv6 address. Must be a valid IP address.
        :param value: {str} The string representation of the indicator.
        :param filter_logic: {str} Filter logic. Can be equal or contains
        :param limit: {int} The max amount of indicators to return
        :return: {list} The indicators
        """
        params = {
            'types': ioc_types,
        }

        ids = self._paginate_results(
            self._get_full_url('ioc_listing'),
            params=self._get_valid_params(params),
            limit=limit,
            error_msg="Unable to get custom indicators ids"
        )

        if not ids:
            return []

        if filter_logic and value:
            ids = self.filter_indicator_ids(ids, filter_logic, value, limit=limit)

        # Get the details of the indicators by the received ids
        indicators = self._paginate_results(
            self._get_full_url('ioc_endpoint'),
            params={'ids': ids},
            limit=limit,
            error_msg="Unable to get custom indicators"
        )

        return self.parser.build_results(indicators, 'build_siemplify_indicator_obj', pure_data=True)

    def delete_ioc(self, ioc_id):
        """
        Delete ioc by ID
        :param ioc_id: {str} ioc ID
        :return: {void}
        """
        params = {
            "ids": ioc_id
        }
        
        response = self.session.delete(self._get_full_url('delete_ioc'), params=params)
        self.validate_response(response, f"Failed to delete the ioc with ID {ioc_id}.")

    def match_device_host_name(self, device, starts_with_name):
        """
        Check if hostname matches with device name
        :param device: {Device} instance
        :param starts_with_name: {str} The starting string of device name
        :return: [{Device}] if match results None otherwise
        """
        host_name = device.hostname.lower()
        starts_with = host_name.startswith(starts_with_name.lower())

        if not starts_with:
            return False

        if starts_with and len(host_name) == len(starts_with_name):
            return True

        return starts_with and host_name[len(starts_with_name)] == '.'

    def get_devices_ran_on(self, ioc_type, value, limit=None):
        """
        Find hosts that have observed a given custom IOC.
        :param ioc_type: {str} The type of indicator from the list of supported indicator types. Valid types include:
            sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
            sha1: A hex-encoded sha1 hash string. Length - min 40, max: 40.
            md5: A hex-encoded md5 hash string. Length - min 32, max: 32.
            domain: A domain name. Length - min: 1, max: 200.
        :param value: {str} The actual string representation of your indicator.
        :param limit: {int} Max amount of devices to return
        :return: {list} The devices' details
        """
        params = {
            'type': ioc_type,
            'value': value
        }
        # NOTICE! The API returns 404 code when no devices are found for the indicator! So ignore 404
        ids = self._paginate_results(
            self._get_full_url('ioc_queries'),
            params=params,
            limit=limit,
            error_msg="Unable to get devices ran on for {}:{}".format(ioc_type, value),
            builtin_pagination=True,
            ignore_404=True
        )

        if not ids:
            return []

        # NOTICE! The hosts can age out in the API, in such cases the request above will still return them, but the
        # request below will throw a 404 code! So ignore 404 codes in here
        devices = self._paginate_results(
            self._get_full_url('entities_devices'),
            params={'ids': ids},
            limit=limit,
            error_msg="Unable to search for devices",
            ignore_404=True
        )

        return self.parser.build_results(devices, 'build_siemplify_device_obj', pure_data=True)

    def get_detections(self, detection_id=None, status=None, date_updated=None,
                       md5=None, severity=None, filename=None, timestamp=None,
                       ioc_type=None, ioc_source=None, ioc_value=None, device_id=None,
                       device_hostname=None, device_external_ip=None, device_local_ip=None,
                       limit=None):
        """
        Get detections details
        :param detection_id: {int} The ID of the detection.
        :param status: {str} The current status of the detection. Values include new, in_progress, true_positive, false_positive, and ignored.
        :param date_updated: {str} The date of the most recent update to a detection. i.e: 2017-01-31T22:36:11Z.
        :param md5: {str} MD5 of the triggering process.
        :param severity: {int} Severity rating for the behavior. Value can be any integer between 1-100.
        :param filename: {str} File name of the triggering process.
        :param timestamp: {str} 	The time when the behavior detection occurred. i.e: 2017-01-12T06:51:42Z.
        :param ioc_type: {str} The type of the triggering IOC. Values include hash_sha256, hash_md5,domain,filename,registry_key,command_line, and behavior.
        :param ioc_source: {str} Source that triggered an IOC detection. Values include library_load, primary_module, file_read, and file_write.
        :param ioc_value: {str} IOC value.
        :param device_id: {str} Device ID as seen by CrowdStrike.
        :param device_hostname: {str} Device host name.
        :param device_external_ip: {str} Device's external IP.
        :param device_local_ip: {str} The device's local IP address, with optional wildcards (*).
            As a detections parameter, this is the IP address at the time the detection occurred.
            To use wildcards, prefix the IP address with an asterisk (*) and enclose the IP address in single quotes.
        :param limit: {int} Max amount of devices to return
        :return: {json} The found detection details (list of dicts)
        """

        filter_data = {
            'detection_id': detection_id,
            'status': status,
            'date_updated': date_updated,
            'behaviors.md5': md5,
            'behaviors.severity': severity,
            'behaviors.filename': filename,
            'behaviors.timestamp': timestamp,
            'behaviors.ioc_type': ioc_type,
            'behaviors.ioc_source': ioc_source,
            'behaviors.ioc_value': ioc_value,
            'device.device_id': device_id,
            'device.hostname': device_hostname,
            'device.external_ip': device_external_ip,
            'device.local_ip': device_local_ip
        }

        filter_data = self._get_valid_params(filter_data)

        # Filter query construction
        filter_query = "+".join(["{}:'{}'".format(key, value) for key, value in filter_data.items()])
        url = "{}/detects/queries/detects/v1".format(self.api_root)

        response = self.session.get(url)
        self.validate_response(response,
                               "Unable to get detections")

        ids = self._paginate_results(url, params={"filter": filter_query}, limit=limit,
                                     error_msg="Unable to get detections ids")

        if not ids:
            return []

        url = "{}/detects/entities/summaries/GET/v1".format(self.api_root)

        detections = self._paginate_results(url, method="POST", body={'ids': ids}, limit=limit,
                                            error_msg="Unable to get detections")
        return [self.parser.build_siemplify_detection_obj(detection) for detection in detections]

    def close_detection(self, detection_id, show_in_ui=False):
        """
        Close detection in Crowdstrike Falcon
        :param detection_id: {str} Crowdstrike Falcon detection id
        :param show_in_ui: {bool} if False, hides detection in Crowdstrike Falcon
        :return: {bool} True if successful, raise exception otherwise.
        """
        data = {
            "ids": [detection_id],
            "show_in_ui": show_in_ui,
            "status": "closed"
        }
        response = self.session.patch(self._get_full_url('detections'), json=data)
        self.validate_response(response, f"Failed to close detection {detection_id}")

        return True

    @staticmethod
    def validate_response(response, error_msg="An error occurred", ignore_404=False, custom_response=False,
                          handle_not_found=False):
        try:
            if ignore_404 and response.status_code == 404:
                return

            response.raise_for_status()

        except requests.HTTPError as error:
            if custom_response:
                if 'error' in response.json().keys():
                    if custom_response:
                        if 'Command not found' != response.json()['error']:
                            raise CrowdStrikeSessionCreatedError(response.json()['error'])

                elif response.json().get("errors"):
                    if custom_response:
                        if 'Command not found' not in [error_obj.get("message") for error_obj in response.json().get('errors')]:
                            raise CrowdStrikeSessionCreatedError(
                                ", ".join([error_obj.get("message") for error_obj in response.json().get('errors')]))

            if handle_not_found and response.status_code == 404:
                raise CrowdStrikeNotFoundError(
                    "{error_msg}: {error} {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=error.response.content)
                )

            raise CrowdStrikeManagerError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

        if 'error' in response.json().keys():
            if custom_response:
                if 'Command not found' == response.json()['error']:
                    raise CrowdStrikeManagerError(response.json()['error'])
            raise CrowdStrikeSessionCreatedError(response.json()['error'])

        elif response.json().get("errors"):
            if custom_response:
                if 'Command not found' in [error_obj.get("message") for error_obj in response.json().get('errors')]:
                    raise CrowdStrikeManagerError(
                        ", ".join([error_obj.get("message") for error_obj in response.json().get('errors')]))

            if handle_not_found:
                if 404 in [error_obj.get("code") for error_obj in response.json().get('errors')]:
                    raise CrowdStrikeNotFoundError(
                        ", ".join([error_obj.get("message") for error_obj in response.json().get('errors')]))

            raise CrowdStrikeSessionCreatedError(
                ", ".join([error_obj.get("message") for error_obj in response.json().get('errors')]))

    def update_ioc(self, ioc_id, expiration_date=None, detect_policy=True, source=None, description=None, severity=None):
        """
        Update ioc
        :param ioc_id: {str} ioc ID
        :param expiration_date: {str} The date until which the indicator should be valid for. This only applies to domain, ipv4, and ipv6 types.
        :param detect_policy: {bool} when the value is detected on a host enacted a detect policy, else none(This is equivalent to turning the indicator off)
        :param source: {str} The source where this indicator originated. This can be used for tracking where this indicator was defined. Limit 200 characters.
        :param description: {str} The friendly description of the indicator. Limit 200 characters.
        :param severity: {str} ioc severity
        :return: {void}
        """
        json_payload = {
            "indicators": [
                {
                    "id": ioc_id,
                    "source": source,
                    "action": POLICY_DEFAULT_FOR_DETECT if detect_policy else None,
                    "description": description,
                    "expiration": expiration_date,
                    "severity": IOC_DEFAULT_SEVERITY if detect_policy and not severity else severity
                }
            ]
        }
        
        json_payload["indicators"] = [self._get_valid_params(item) for item in json_payload.get("indicators")]
        response = self.session.patch(self._get_full_url('update_ioc'), json=json_payload)
        self.validate_response(response, f'Unable to update custom ioc with ID {ioc_id}')
        return self.parser.get_resources(response.json())

    def get_processes_ran_on(self, ioc_type, value, device_id, device_name=None, limit=None):
        """
        Search for processes associated with a custom IOC
        :param ioc_type: {str} The type of indicator from the list of supported indicator types. Valid types include:
            sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
            sha1: A hex-encoded sha1 hash string. Length - min 40, max: 40.
            md5: A hex-encoded md5 hash string. Length - min 32, max: 32.
            domain: A domain name. Length - min: 1, max: 200.
        :param value: {str} The actual string representation of your indicator.
        :param device_id: {str} The device ID you want to specifically check against.
        :param device_name: {str} The device name you want to specifically check against.
        :param limit: {int} The max amount of results to return
        :return: {json} The process' details
        """
        # NOTICE! The API returns 404 code when no processes are found for the indicator! So ignore 404
        params = {
            "type": ioc_type,
            "value": value,
            "device_id": device_id
        }
        ids = self._paginate_results(
            self._get_full_url('queries_processes'),
            params=params,
            limit=limit, error_msg=f'Unable to get processes ran on for {ioc_type}:{value}',
            builtin_pagination=True,
            ignore_404=True
        )
        if not ids:
            return []

        # NOTICE! The processes can age out in the API, in such cases the request above will still return them, but the
        # request below will throw a 404 code! So ignore 404 codes in here
        processes = self._paginate_results(
            self._get_full_url('entities_processes'),
            params={'ids': ids},
            error_msg="Unable to search for processes",
            ignore_404=True
        )

        return self.parser.build_results(raw_json=processes, method='build_siemplify_process', pure_data=True,
                                         hostname=device_name, indicator_value=value)

    def get_processes_by_device_name(self, device_name, ioc_type, ioc_value):
        """
        Get processes by device name
        :param device_name: {str} device name (e.g. LP-ZIV)
        :param ioc_type: {str} The type of indicator from the list of supported indicator types. Valid types include:
            sha256: A hex-encoded sha256 hash string. Length - min: 64, max: 64.
            sha1: A hex-encoded sha1 hash string. Length - min 40, max: 40.
            md5: A hex-encoded md5 hash string. Length - min 32, max: 32.
            domain: A domain name. Length - min: 1, max: 200.
            ipv4: An IPv4 address. Must be a valid IP address.
            ipv6: An IPv6 address. Must be a valid IP address.
        :param ioc_value: {str} The actual string representation of your indicator.
        :return: [{Process}] List of found processes model
        """
        results = []
        devices = self.search_devices(starts_with_name=device_name)

        if not devices:
            raise CrowdStrikeManagerError(f"Device {device_name} was not found")

        device_id = devices[0].device_id

        if device_id:
            results.extend(self.get_processes_ran_on(ioc_type=ioc_type, value=ioc_value, device_id=device_id,
                                                     device_name=device_name))

        return results

    def contain_host_by_device_id(self, device_ids):
        """
        Contain(Quarantine) host by device ID.
        :param device_ids: {str or list} the ID of the host device.
        :return: {bool} Is success.
        """
        device_ids = device_ids if isinstance(device_ids, list) else [device_ids]

        response = self.session.post(
            self._get_full_url('devices_actions'),
            json={'ids': device_ids},
            params={'action_name': 'contain'}
        )
        self.validate_response(response)

        return True

    def lift_containment_from_host_by_device_id(self, device_ids):
        """
        Lift containment from host by device ID.
        :param device_ids: {str or list} the ID of the host device.
        :return: {bool} Is success.
        """
        device_ids = device_ids if isinstance(device_ids, list) else [device_ids]

        response = self.session.post(
            self._get_full_url('devices_actions'),
            json={'ids': device_ids},
            params={'action_name': 'lift_containment'}
        )
        self.validate_response(response)

        return True

    def get_alerts(self, severity, start_timestamp, limit):
        """
        Get Alerts
        Args:
            severity: {int} filter by severity
            start_timestamp: {str} filter by start timestamp
            limit: {int} limit for results
        Returns:
            {[AlertDetails]} list of AlertDetails objects
        """

        params = {
            "filter": self.build_get_alerts_filters(severity=severity, start_timestamp=start_timestamp),
            "limit": limit,
            "sort": "created_timestamp.asc"
        }
        response = self.session.get(self._get_full_url('get_alerts'), params=params)
        self.validate_response(response)
        return self.get_alerts_details(self.parser.get_resources(response.json()))

    def get_alerts_details(self, ids):
        """
        Get alerts details
        Args:
            ids: {list} alerts' ids
        Returns:
            {[AlertDetails]} list of AlertDetails objects
        """
        if not ids:
            return []

        response = self.session.post(self._get_full_url('get_alerts_details'), json={'ids': ids})
        self.validate_response(response, handle_not_found=True)
        return self.parser.get_resources(response.json(), 'build_siemplify_alert_details')

    @staticmethod
    def build_get_alerts_filters(severity, start_timestamp):
        """
        Build get alerts filters
        Args:
            severity: {int} filter by severity
            start_timestamp: {str} filter by start timestamp
        Returns: {str} query filter
        """
        query_filter = f"severity:>='{severity}'"
        query_filter += "+product:'idp'+status:['new','in_progress']"
        query_filter += f"+created_timestamp:>=" \
                        f"'{datetime.fromtimestamp(start_timestamp / 1000).strftime(DATE_TIME_FORMAT)}'"

        return query_filter

    def get_detections_connector(self, first_behavior, severity=None, confidence=None, limit=MAX_DETECTIONS_TO_FETCH,
                                 filters=None, sort_by='first_behavior', sort_order='asc'):
        """
        Paginate the results of a job
        :param first_behavior: {str} Datetime for the first detection to fetch. Format:'2020-01-12T16:17:19Z'
        :param severity: {int} Severity rating for the behavior. Value can be any integer between 1-100.
        :param confidence: {int} Confidence rating for the behavior. Value can be any integer between 0-100.
        :param limit: {str} Maximum number of detections to fetch
        :param filters: {list} Filters for apply query
        :param sort_by: {str} The field name to sort data
        :param sort_order: {str} Sort direction
        :return: {list} List of Detections
        """
        payload = {
            "filter": self.prepare_filter(first_behavior, severity, confidence, filters),
            "sort": "{}.{}".format(sort_by, sort_order),
            "limit": max(limit, MAX_DETECTIONS_TO_FETCH),
        }
        payload_str = "&".join(f"{k}={v}" for k, v in payload.items())
        response = self.session.get(self._get_full_url('detections_connector'), params=payload_str)
        self.validate_response(response)

        resources = self.parser.get_resources(response.json())

        if self.logger:
            self.logger.info(f"Detections parameters {json.dumps(payload_str)}")
            self.logger.info(f"Received following detection IDs {json.dumps(resources)}")

        return sorted(
            self.get_detection_details(resources),
            key=lambda elem: resources.index(elem.detection_id)
        )

    def prepare_filter(self, first_behavior, severity, confidence, filters=None):
        """
        Create filter by given parameters
        :param first_behavior: {str} Datetime for the first detection to fetch. Format:'2020-01-12T16:17:19Z'
        :param severity: {int} Severity rating for the behavior. Value can be any integer between 1-100.
        :param confidence: {int} Confidence rating for the behavior. Value can be any integer between 0-100.
        :param filters: {int} Filters for apply query
        :return: {str} Filter string
        """
        query_filter = "status:'new'"

        if first_behavior:
            query_filter += "+first_behavior:>='{}'".format(first_behavior)
        if severity:
            try:
                severity = int(severity)
                query_filter += "+max_severity:>={}".format(severity)
            except:
                query_filter += "+max_severity_displayname:{}".format(SEVERITIES[SEVERITIES.index(severity.title()):])
        if confidence:
            query_filter += "+max_confidence:>={}".format(confidence)
        if filters:
            query_filter += "+{}".format("+".join(filters))

        return urllib.parse.quote(query_filter)

    def get_detection_details(self, ids):
        """
        Paginate the results of a job
        :param ids: {list} Ids of detections to load details
        :return: {list} List of DetectionDetails
        """
        if not ids:
            return []

        response = self.session.post(self._get_full_url('detection_details'), json={'ids': ids})
        self.validate_response(response)

        return self.parser.get_resources(response.json(), 'build_siemplify_detection_detail')

    def _paginate_results(self, url, params=None, body=None, method=None, limit=None, error_msg=None,
                          builtin_pagination=False, ignore_404=False, for_hosts=False):
        """
        Paginate the results of a job
        :param url: {str} The url to send request to
        :param method: {str} The method of the request
        :param params: {dict} The params of the request
        :param body: {json} The JSON body of the request
        :param limit: {int} The limit of the results to fetch
        :param error_msg: {str} The error message to display on error
        :return: {list} List of results
        """
        method = method or 'GET'
        error_msg = error_msg or 'Unable to get results'
        params = params or {}

        params.update({
            'offset': None if builtin_pagination else 0,
            'limit': 1000 if for_hosts else PAGE_SIZE
        })

        while True:
            response = json_response = None

            if not response:
                response = self.session.request(method, url, params=params, json=body)
                json_response = response.json()

                self.validate_response(response, error_msg, ignore_404=ignore_404)

            results = self.parser.get_resources(json_response)

            if builtin_pagination:
                if not self.parser.get_next_page_cursor(json_response):
                    break
            else:
                if len(results) >= self.parser.get_page_total(json_response):
                    break

            if (limit and len(results) >= limit) or for_hosts:
                return results[:limit]

            if builtin_pagination:
                params.update({'offset': self.parser.get_page_offset(json_response)})
            else:
                params.update({'offset': params['offset'] + PAGE_SIZE})

            response = self.session.request(method, url, params=params, json=body)
            self.validate_response(response, error_msg, ignore_404=ignore_404)

            json_response = response.json()

            results.extend(self.parser.get_resources(json_response))

        return results[:limit]

    def get_vulnerability_ids(self, aid=None, severity=None, limit=None):
        """
        Get vulnerability ids
        :param aid: {list} Ids of vulnerabilities
        :param severity: {list} Ids of severity filter for vulnerabilities
        :param limit: {int} Maximum number of ids to return
        :return: {Vulnerability}
        """
        filter_data = {
            'aid': aid,
            'cve.severity': severity or None,
            'status': STATUS
        }

        return self._paginate_vulnerability_results(
            self._get_full_url('vulnerability_ids'),
            params={'filter': self.get_query_filter(self._get_valid_params(filter_data))},
            limit=limit
        )

    def get_vulnerabilities_detailed_information(self, vulnerability_ids):
        """
        Get vulnerabilities detailed information by ids. Max ids = 400
        :param vulnerability_ids: {list} Ids for vulnerabilities
        :return: {list} List of Vulnerabilities
        """
        params = {
            'ids': vulnerability_ids
        }
        response = self.session.get(self._get_full_url('vulnerability_details'), params=params)
        self.validate_response(response)
        return self.parser.build_results(raw_json=response.json(), method='build_vulnerability_detail_obj')

    def get_vulnerabilities(self, vulnerability_ids):
        """
        Get vulnerability details
        :param vulnerability_ids: {list} Ids for vulnerabilities
        :return: {list} List of VulnerabilityDetail
        """
        vulnerability_details = []
        for vulnerability_ids_chunk in [vulnerability_ids[x:x + MAX_PROCESSED_IDS_PER_REQUEST] for x in
                                        range(0, len(vulnerability_ids), MAX_PROCESSED_IDS_PER_REQUEST)]:
            vulnerability_details.extend(self.get_vulnerabilities_detailed_information(
                vulnerability_ids=vulnerability_ids_chunk))

        return vulnerability_details

    def get_remediation_details(self, ids):
        """
        Get remediation details
        :param ids: {list} Ids of remediation
        :return: {list} List of RemediationDetails
        """
        params = {
            'ids': ids
        }
        response = self.session.get(self._get_full_url('remediation_details'), params=params)
        self.validate_response(response)
        return self.parser.build_results(raw_json=response.json(),
                                         method='build_remediation_detail_obj')

    def _paginate_vulnerability_results(self, url, params=None, method=None, limit=None):
        """
        Paginate the results of a job
        :param url: {str} The url to send request to
        :param method: {str} The method of the request
        :param params: {dict} The params of the request
        :param limit: {int} The limit of the results to fetch
        :return: {list} , {int} List of results and total from endpoint
        """
        method = method or 'GET'
        params = params or {}

        params.update({
            'limit': min(limit or MAX_PROCESSED_IDS_PER_REQUEST, MAX_PROCESSED_IDS_PER_REQUEST)
        })

        response = json_response = None
        vulnerability_ids = []

        while True:
            if limit and len(vulnerability_ids) >= limit:
                break
            if response and json_response:
                after_page = self.parser.get_after_page(json_response)
                if not after_page:
                    break
                params.update({'after': after_page})

            response = self.session.request(method, url, params=params)
            self.validate_response(response)

            json_response = response.json()

            vulnerability_ids.extend(self.parser.get_resources(json_response))
        total = self.parser.get_page_total(json_response) if json_response else 0
        return vulnerability_ids[:limit], total

    def get_ioc_id(self, ioc_value):
        """
        Get ioc ID by value
        :param ioc_value: {str} ioc value
        :return: {list} List of ioc IDs
        """
        params = {
            "filter": f"value:'{ioc_value}'"
        }

        response = self.session.get(self._get_full_url('get_ioc_id'), params=params)
        self.validate_response(response)
        return self.parser.get_resources(response.json())

    @staticmethod
    def build_ioc_filters(types, filter_value=None, filter_logic=None):
        """
        Build ioc filters
        :param types: {list} list of ioc types
        :param filter_value: {str} ioc value
        :param filter_logic: {str} filter logic that needs to be applied
        :return: {str} ioc filters
        """
        filters_string = ",".join([f'type:"{type}"' for type in types])

        if filter_value and filter_logic == FilterStrategy.Equal.value:
            filters_string += f'+ value:"{filter_value}"'

        return filters_string

    def get_ioc_ids(self, types, filter_value=None, filter_logic=None, limit=None):
        """
        Get ioc ids based on filters
        :param types: {list} list of ioc types
        :param filter_value: {str} ioc value for filtering
        :param filter_logic: {str} filter logic that needs to be applied
        :param limit: {int} limit for the results
        :return: {list} list of ioc ids
        """
        params = {
            "filter": self.build_ioc_filters(types, filter_value, filter_logic)
        }

        return self._paginate_results(
            self._get_full_url('get_ioc_id'),
            params=self._get_valid_params(params),
            limit=limit,
            error_msg="Failed to get IOC ids"
        )

    def get_iocs(self, ids, filter_value=None, filter_logic=None):
        """
        Get IOCs by provided ids
        :param ids: {list} list of ids
        :param filter_value: {str} ioc value for filtering
        :param filter_logic: {str} filter logic that needs to be applied
        :return: {list} list of CustomIndicator objects
        """
        params = {
            "ids": ids
        }

        iocs = self._paginate_results(
            self._get_full_url('get_iocs'),
            params=params,
            error_msg="Failed to get IOCs"
        )

        iocs_objects = self.parser.build_results(iocs, 'build_siemplify_indicator_obj', pure_data=True)

        if filter_value and filter_logic == FilterStrategy.Contains.value:
            iocs_objects = [ioc for ioc in iocs_objects if FILTER_STRATEGY_MAPPING[filter_logic](ioc.value, filter_value)]

        return iocs_objects

    def get_host_group_by_name(self, name):
        """
        Get host group by name
        :param name: {str} host group name
        :return: {HostGroup} HostGroup object
        """
        host_groups = self._paginate_results(
            self._get_full_url('get_host_groups'),
            error_msg="Failed to get host groups"
        )

        host_group_objects = self.parser.build_results(host_groups, 'build_host_group_object', pure_data=True)
        return next((host_group_object for host_group_object in host_group_objects if host_group_object.name == name), None)

    def get_devices_login_histories(self, ids):
        """
        Get login histories for devices
        :param ids: {[str]} list of device ids
        :return: {[LoginHistory]} list of LoginHistory objects
        """
        payload = {
            "ids": ids
        }

        response = self.session.post(self._get_full_url("get_devices_login_histories"), json=payload)
        self.validate_response(response)
        return self.parser.build_results(response.json(), "build_login_history_object")

    def get_devices_online_states(self, ids):
        """
        Get online states for devices
        :param ids: {[str]} list of device ids
        :return: {[OnlineState]} list of OnlineState objects
        """
        params = {
            "ids": ids
        }

        response = self.session.get(self._get_full_url("get_devices_online_states"), params=params)
        self.validate_response(response)
        return self.parser.build_results(response.json(), "build_online_state_object")

    def update_alert(self, alert_id, status, assign_to):
        """
        Update alert
        Args:
            :param alert_id: {str} alert id
            :param status: {str} status to assign
            :param assign_to: {str} name to assign
        Returns:
            {Void}
        """
        data = {
            "ids": [alert_id],
            "action_parameters": []
        }

        if assign_to == UNASSIGN:
            data.get("action_parameters").append({"name": "unassign", "value": ""})
        elif assign_to:
            data.get("action_parameters").append({"name": "assign_to_name", "value": assign_to})

        if DETECTION_STATUS_MAPPING.get(status):
            data.get("action_parameters").append(
                {"name": "update_status", "value": DETECTION_STATUS_MAPPING.get(status)}
            )

        response = self.session.patch(self._get_full_url("update_alert"), json=data)
        self.validate_response(response)
