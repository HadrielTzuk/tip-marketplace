# ==============================================================================
# title           :PortNoxManager.py
# description     :This Module contain all portnox operations functionality
# author          :avital@siemplify.co
# date            :19-07-18
# python_version  :2.7
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import requests
import datetime
import arrow

# =====================================
#             CONSTANTS               #
# =====================================
PORTNOX_AUTH_URL_SUFFIX = "auth/user"
# {0} for file hash
PORTNOX_REVALIDATE_URL_SUFFIX = "devices/actions/revalidation"
PORTNOX_DEVICE_INFO_URL_SUFFIX = "devices/{deviceId"
REVALIDATE_IN_PROGRESS_STATUS = "DuringAuthentication"
REVALIDATE_DONE_STATUS = "AuthorizationPassed"

# =====================================
#              CLASSES                #
# =====================================
class PortnoxManagerError(Exception):
    """
    General Exception for Portnox manager
    """
    pass


class PortnoxManager(object):
    """
    Responsible for all Portnox operations functionality
    """
    def __init__(self, api_root, username, password, verify_ssl=False):
        self.api_root = self.validate_api_root(api_root)
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "username": username,
            "password": password,
            "Content-Type": "application/json"
        })

    @staticmethod
    def validate_api_root(api_root):
        """
        Validate that api root is not endind with '/'
        :param api_root: api root url {string}
        :return: valid api root {string}
        """
        if api_root.endswith('/'):
            return api_root[:-1]
        return api_root

    def test_conectivity(self):
        """
        Test connection to sever
        :return: {bool} True if connection is successful, exception otherwise
        """
        response = self.session.get("{}/auth/user".format(self.api_root))
        self.validate_response(response, "Unable to connect")
        return True

    def revalidate_device(self, device_id):
        """
        Revalidate auth policy on a specific device connected to NAC
        :param device_id: {string} The device to revalidate
        :return: {bool} True if connection is successful, exception otherwise
        """
        url = "{}/devices/actions/revalidation".format(self.api_root)
        data = {'deviceIds': [device_id]}
        response = self.session.post(url, data=data)
        self.validate_response(response, "Unable to validate device {}".format(device_id))
        return True

    def get_device_info(self, device_id):
        """
        Retrieve all NAC info on specific device
        :param device_id: {string} The device id
        :return: {dict} Device details
        """
        url = "{}/devices/{}".format(self.api_root, device_id)
        response = self.session.get(url)
        self.validate_response(response, "Unable to get info for device {}".format(
            device_id))
        return response.json()

    def get_device_user_history(self, device_id):
        """
        Get authentication history of a given device.
        :param device_id: {string} The device id
        :return: {list} User history
        """
        url = "{}/devices/{}/details/userHistory".format(self.api_root, device_id)
        response = self.session.get(url)
        self.validate_response(response, "Unable to get user history for device {}".format(
            device_id))
        return response.json()

    def get_device_history(self, device_id,
                           from_timestamp=arrow.utcnow().isoformat(),
                           to_timestamp=arrow.utcnow().isoformat()):
        """
        Get device history of a given device.
        :param device_id: {string} The device
        :param from_timestamp: {str} Timestamp to fetch history from (ISO format)
        :param to_timestamp: {str} Timestamp to fetch history until (ISO format)
        :return: {list} Device history
        """
        url = "{}/devices/{}/details/deviceHistory".format(self.api_root, device_id)
        response = self.session.get(url, params={
            'from': from_timestamp,
            'to': to_timestamp
        })
        self.validate_response(response, "Unable to get device history for device {}".format(
            device_id))
        return response.json()

    def get_device_installed_applications(self, device_id):
        """
        Get the installed applications of a given device.
        :param device_id: {string} The device id
        :return: {list} The installed applications
        """
        url = "{}/devices/{}/details/applications".format(self.api_root, device_id)
        response = self.session.get(url)
        self.validate_response(response, "Unable to get installed applications for device {}".format(
            device_id))
        return response.json()

    def get_device_services(self, device_id):
        """
        Get the services of a given device.
        :param device_id: {string} The device id
        :return: {list} The services
        """
        url = "{}/devices/{}/details/services".format(self.api_root, device_id)
        response = self.session.get(url)
        self.validate_response(response, "Unable to get services for device {}".format(
            device_id))
        return response.json()

    def get_device_locations(self, device_id):
        """
        Get the locations of a given device.
        :param device_id: {string} The device id
        :return: {list} The locations
        """
        url = "{}/locations".format(self.api_root)
        response = self.session.get(url, params={
            'ids[]': [device_id]
        })
        self.validate_response(response, "Unable to get locations for device {}".format(
            device_id))
        return response.json()

    def get_device_open_ports(self, device_id):
        """
        Get the open ports of a given device.
        :param device_id: {string} The device id
        :return: {list} The open ports
        """
        url = "{}/devices/{}/details/openports".format(self.api_root, device_id)
        response = self.session.get(url)
        self.validate_response(response, "Unable to get open ports for device {}".format(
            device_id))
        return response.json()

    def search_device(self, key, value, search_type="Equals"):
        """
        Search for device by key value filtering
        :param key: {string} The key to search in
        :param value: {string} The expected value in key
        :param search_type: {string} Search type. Valid values:
            Contains, StartsWith, EndsWith, Equals
        :return: {dict} Device details (if multiple devices match the search,
            the first device is selected)
        """
        url = "{}/devices".format(self.api_root)
        data = {
            "query": {
                "search": [{
                    "key": key,
                    "value": value,
                    "searchType": search_type
                }]
            }
        }
        response = self.session.post(url, json=data)
        self.validate_response(response,
                               "Unable to search for {}-{}".format(
                                   key, value))

        if not response.json():
            raise PortnoxManagerError("No devices were found for {}:{}".format(key, value))

        return response.json()[0]

    def wait_for_device_revalidation(self, device_id, timeout=1000):
        """
        Revalidate device policy over NAC and wait for revalidation confirmation
        :param device_id: {string} The device to revalidate
        :param timeout: {int} Time to wait for confirmation (in Seconds)
        :return: {bool} True if successful, exception otherwise.
        """
        device_details = self.get_device_info(device_id)
        if 'securityStatus' not in device_details:
            raise PortnoxManagerError("Invalid details for device {} details".format(device_id))

        timeout_timestamp = arrow.utcnow().shift(seconds=timeout)

        # Run with timeout checking
        while True:
            if arrow.utcnow() > timeout_timestamp:
                raise PortnoxManagerError("Timeout reached while waiting for device {} revalidation.".format(device_id))

            if device_details.get('securityStatus') == REVALIDATE_DONE_STATUS:
                return True

            # Update device details
            device_details = self.get_device_info(device_id)

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        """
        Validate Portnox responses
        :param response: {requests.Response}
        :param error_msg: {str} Message to display on error
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            text = response.content

            try:
                # If Portnox error exists - the error may be found
                # in message of the error.
                if response.json().get('message'):
                    text = response.json()['message']
            except:
                # The error doens't contain message.
                pass

            raise PortnoxManagerError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=text)
            )


