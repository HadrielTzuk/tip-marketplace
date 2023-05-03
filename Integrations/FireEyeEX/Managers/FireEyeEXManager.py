# ============================================================================#
# title           :FireEyeEXManager.py
# description     :This Module contain all FireEye EX operations functionality
# author          :avital@siemplify.co
# date            :18-06-2020
# python_version  :2.7
# libreries       :requests
# requirments     :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #
import requests
import json
import os
from urlparse import urljoin
import defusedxml.ElementTree as ET

from FireEyeEXParser import FireEyeEXParser

# ============================== CONSTS ===================================== #
BASE_PATH = u"{}/wsapis/{}"
HEADERS = {
    u'Content-type': u'application/json'
}
API_TIME_FORMAT = u'%Y-%m-%dT%H:%M:%S.%f-00:00'

# ============================= CLASSES ===================================== #


class FireEyeEXManagerError(Exception):
    """
    General Exception for FireEye EX manager
    """
    pass


class FireEyeEXNotFoundError(Exception):
    """
    Not Found Exception for FireEye EX manager
    """
    pass


class FireEyeEXUnsuccessfulOperationError(Exception):
    """
    Unsuccessful operation exception for FireEye EX manager
    """
    pass

class FireEyeEXDownloadFileError(Exception):
    """
    Unsuccessful download of a file exception for FireEye EX manager
    """
    pass


class FireEyeEXManager(object):
    """
    FireEye EX Manager
    """
    def __init__(self, api_root, username, password, version=u'v2.0.0', verify_ssl=False):
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers = HEADERS
        self.session.auth = (username, password)
        self.api_root = BASE_PATH.format(api_root[:-1] if api_root.endswith(u'/') else api_root, version)
        self.session.headers[u'X-FeApi-Token'] = self.get_token()
        self.parser = FireEyeEXParser()

    def get_token(self):
        """
        Get a token (equals to login)
        """
        url = u'{}/auth/login'.format(self.api_root)
        response = self.session.post(url)
        self.validate_response(response, u"Unable to obtain token")
        token = response.headers.get(u'X-FeApi-Token')

        if not token:
            raise FireEyeEXManagerError(u"Authentication failed. No X-FeApi-Token found.")

        return token

    def test_connectivity(self):
        """
        Test connectivity to FireEye EX
        :return: {bool} True if connection is successful, exception otherwise.
        """
        url = u'{}/health/system'.format(self.api_root)
        response = self.session.get(url)
        self.validate_response(response, u"Unable to connect to the FireEye EX")
        return True

    def list_quarantined_emails(self, limit=None, start_time=None, end_time=None, sender=None, subject=None):
        """
        Lists quarantined emails.
        :param limit: {int} Number of records to return. Default - 10000.
        :param start_time: {string} (YYYY-MM-DD'T'HH:MM:SS.SSS-HHMM). If specified, only emails that were created after
            start time will be returned. If Start Time and End Time are not specified, action returns quarantined emails
            from the last 24 hours.
        :param end_time: {string} (YYYY-MM-DD'T'HH:MM:SS.SSS-HHMM). If specified, only emails that were created before
            end time time will be returned. If Start Time and End Time are not specified, action returns quarantined
            emails from the last 24 hours.
        :param sender: {string} If specified, returns all of the quarantined emails only from this sender.
        :param subject: {string} If specified, returns all of the quarantined emails only with this subject.
        :return: {[QuarantinedEmail]} Found emails
        """
        url = u'{}/emailmgmt/quarantine'.format(self.api_root)

        url_params = {
            u'limit': limit,
            u'subject': subject,
            u'sender': sender,
            u'start_time': start_time,
            u'end_time': end_time,
            u'from': sender
        }

        # Remove None values
        url_params = {k: v for k, v in url_params.items() if v is not None}

        response = self.session.get(
            url,
            params=url_params,
        )
        self.validate_response(response, u"Unable to get quarantined emails")
        return [self.parser.build_siemplify_email_obj(email) for email in response.json()]

    def release_quarantined_email(self, queue_id):
        """
        Release quarantined email based on queue ID.
        :param queue_id: {str} The queue id
        :return: {bool} True if successful, exception otherwise.
        """
        url = u'{}/emailmgmt/quarantine/release'.format(self.api_root)
        response = self.session.post(url, json={
            u"queue_ids": [queue_id]
        })
        self.validate_response(response, u'Unable to release queue ID {}.'.format(queue_id))

        if response.content:
            try:
                raise FireEyeEXUnsuccessfulOperationError(response.json()[queue_id])

            except FireEyeEXUnsuccessfulOperationError:
                raise

            except Exception:
                # Error is of unknown format
                raise FireEyeEXUnsuccessfulOperationError(response.content)

        return True

    def delete_quarantined_email(self, queue_id):
        """
        Delete quarantined email based on queue ID.
        :param queue_id: {str} The queue id
        :return: {bool} True if successful, exception otherwise.
        """
        url = u'{}/emailmgmt/quarantine/delete'.format(self.api_root)
        response = self.session.post(url, json={
            u"queue_ids": [queue_id]
        })
        self.validate_response(response, u'Unable to delete queue ID {}.'.format(queue_id))

        if response.content:
            try:
                raise FireEyeEXUnsuccessfulOperationError(response.json()[queue_id])

            except FireEyeEXUnsuccessfulOperationError:
                raise

            except Exception:
                # Error is of unknown format
                raise FireEyeEXUnsuccessfulOperationError(response.content)

        return True

    def download_quarantined_email(self, queue_id):
        """
        Download quarantined email based on queue ID.
        :param queue_id: {str} The queue id
        :return: {unicode} The content of the downloaded email.
        """
        url = u'{}/emailmgmt/quarantine/{}'.format(self.api_root, queue_id)
        response = self.session.get(url)
        self.validate_response(response, u'Unable to download queue ID {}.'.format(queue_id))

        content = response.content

        try:
            root = ET.fromstring(content)
            message = root.find(u'message')

            if message:
                raise FireEyeEXUnsuccessfulOperationError(message.text or response.content)

            raise FireEyeEXUnsuccessfulOperationError(response.content)

        except FireEyeEXUnsuccessfulOperationError:
            raise

        except Exception:
            # Response is valid - no XML (XML is error)
            return response

    def download_alert_artifacts(self, alert_uuid):
        """
        Download alert artifacts on alert UUID.
        :param alert_uuid: {str} The alert UUID
        :return: {unicode} The content of the downloaded zip of the alert's artifacts.
        """
        url = u'{}/artifacts/{}'.format(self.api_root, alert_uuid)
        response = self.session.get(url)
        self.validate_response(response, u'Unable to download artifacts for alert UUID {}.'.format(alert_uuid))

        return response

    def logout(self):
        """
        Logout from FireEye HX
        :return: {bool} True if successful, exception otherwise
        """
        url = u'{}/auth/logout'.format(self.api_root)
        response = self.session.post(url)
        self.validate_response(response, u'Failed to logout with token')
        return True

    def get_alerts(self, duration=u'48_hours', info_level=u'extended', start_time=None):
        """
        Get alerts by filters
        :param duration: {str} Specifies the time interval to search. This filter is used with either the start_time or
            end_time filter. If duration, start time, and end time are not specified, the system defaults to
            duration=48_hours, end_time=current_ time. If only duration is specified, the end_time defaults to the
            current time. You cannot specify both a start_time filter and an end_time filter in the same request.
            Syntax: duration=time_interval:
            - 1_hour
            - 2_hours
            - 6_hours
            - 12_hours
            - 24_hours
            - 48_hours
        :param info_level: {str} Specifies the level of information to be returned. The default is concise.
            - concise
            - normal
            - extended
        :param start_time: {str} Specifies the start time of the search. This filter is used with the duration filter.
            If the start_time is specified but not the duration, the system defaults to duration=12_hours, starting at
            the specified start_time.
        :return: {[Alert]} List of found alerts
        """
        url = u"{}/alerts".format(self.api_root)

        params = {
            u'duration': duration,
            u'info_level': info_level
        }

        if start_time:
            start_time = self._convert_datetime_to_api_format(start_time)
            params.update({
                u'start_time': start_time
            })

        response = self.session.get(url, params=params, headers={
            u"Accept": u"application/json"
        })
        self.validate_response(response, u"Unable to get alerts")

        alerts_data = response.json().get(u'alert', [])
        return [self.parser.build_siemplify_alert_obj(alert_data) for alert_data in alerts_data]

    @staticmethod
    def _convert_datetime_to_api_format(time):
        """
        Convert datetime object to the API time format of EX
        :param time: {datetime.Datetime} The datetime object
        :return: {unicode} The formatted time string
        """
        base_time, miliseconds_zone = time.strftime(API_TIME_FORMAT).split(u'.')
        return u'{}.{}'.format(base_time, miliseconds_zone[:3] + miliseconds_zone[-6:])

    @staticmethod
    def validate_response(response, error_msg=u"An error occurred"):
        """
        Validate a response
        :param response: {requests.Response} The response
        :param error_msg: {unicode} The error message to display on failure
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            if response.content:
                try:
                    root = ET.fromstring(response.content)
                    message = root.find(u'message')

                    if message:
                        raise FireEyeEXManagerError(message.text or response.content)

                    raise FireEyeEXManagerError(response.content)

                except Exception:
                    try:
                        error_msg = response.json()[u"fireeyeapis"][u"message"]
                        raise FireEyeEXManagerError(
                            u"{error_msg}: {error} {text}".format(
                                error_msg=error_msg,
                                error=error,
                                text=error_msg)
                        )

                    except FireEyeEXManagerError:
                        raise

                    except Exception:
                        raise FireEyeEXManagerError(
                            u"{error_msg}: {error} {text}".format(
                                error_msg=error_msg,
                                error=error,
                                text=response.content)
                        )

            raise FireEyeEXManagerError(
                u"{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.content)
            )

    def save_artifacts_to_file(self, response, download_path):
        """
        Save raw data to a zip in defined path.
        :param response: Download response.
        :param download_path: Path to save the files.
        :return: True if successful, exception otherwise
        """
        try:
            if not os.path.exists(download_path):
                with open(download_path, 'wb') as f:
                    for chunk in response.iter_content():
                        f.write(chunk)
                return True
            return False
        except Exception as e:
            raise FireEyeEXDownloadFileError(e)