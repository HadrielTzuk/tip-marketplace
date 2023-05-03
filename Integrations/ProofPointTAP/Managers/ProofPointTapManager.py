import requests
from urllib.parse import urljoin
from exceptions import ProofPointTapManagerError
from ProofPointTapParser import ProofPointTapParser


HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

ENDPOINTS = {
    "ping": "/v2/campaign/{campaign_id}",
    "get_campaign": "/v2/campaign/{campaign_id}",
    "get_forensics": "/v2/forensics",
    'decode_urls': "/v2/url/decode"
}


class ProofPointTapManager(object):
    """
    ProofPoint TAP Manager
    """
    def __init__(self, server_address, username, password, verify_ssl=False, force_check_connectivity=False):
        self.server_address = self._get_adjusted_root_url(server_address)
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers = HEADERS
        self.session.auth = (username, password)
        self.parser = ProofPointTapParser()
        if force_check_connectivity:
            self.test_connectivity()

    @staticmethod
    def _get_adjusted_root_url(api_root):
        return api_root if api_root[-1] == r'/' else f'{api_root}/'

    @staticmethod
    def _get_url(url_id, **kwargs):
        """
        Get url from url identifier.
        :param url_id: {str} The id of url
        :param general_api: {bool} whether to use general api or not
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The url
        """
        return ENDPOINTS[url_id].format(**kwargs)

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param general_api: {bool} whether to use general api or not
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.server_address, self._get_url(url_id, **kwargs))

    def test_connectivity(self):
        """
        Test connectivity to ProofPoint
        :return: {bool} True if successful, exception otherwise.
        """
        params = {
            "size": 1
        }
        campaign_id = 'fd50bbd0-5529-41b5-b8a4-257e861f2aca'
        response = self.session.get(self._get_full_url('ping', campaign_id=campaign_id), params=params)
        self.validate_response(response)

        return True

    def get_events(self, since_seconds=300, since_time=None, threat_type=None, threat_status=None):
        """
        Get events
        :param since_seconds: {int} An integer representing a time window in
        seconds from the current API server time. The start of the window is
        the current API server time, rounded to the nearest minute, less the
        number of seconds provided. The end of the window is the current API
        server time rounded to the nearest minute. If JSON output is selected,
        the end time is included in the returned result.
        :param: since_time: {str} A string containing an ISO8601 date. It
        represents the start of the data retrieval period. The end of the
        period is determined by current API server time rounded to the nearest
        minute. If JSON output is selected, the end time is included in the
        returned result.
        :param threat_type: {str} A string specifying which threat type will be
        returned in the data. If no value is specified, all threat types are
        returned. The following values are accepted:
        - url
        - attachment
        - messageText
        :param threat_status: {str} A string specifying which threat statuses
        will be returned in the data. If no value is specified, active and
        cleared threats are returned. The following values are accepted:
        - active
        - cleared
        - falsePositive
        :return: {list} The found events
        """
        url = "{]/v2/siem/all".format(self.server_address)

        params = {
            "sinceSeconds": since_seconds,
            "sinceTime": since_time,
            "format": "json",
            "threatType": threat_type,
            "threatStatus": threat_status
        }

        params = {k:v for k,v in params.items() if v}

        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to fetch events")

        return response.json()

    def decode_urls(self, urls=None):
        """
        Decode urls
        :param urls: {list} List of encoded urls
        :return: {list} List of decoded urls
        """
        payload = {
            "urls": urls
        }

        response = self.session.post(self._get_full_url('decode_urls'), json=payload)
        self.validate_response(response, "Unable to resolve urls")

        return self.parser.build_results(raw_json=response.json(), method='build_decode_url', data_key='urls')

    def get_campaign(self, campaign_id):
        """
        Get campaign info
        :param campaign_id: {str} The campaign id
        :return: {datamodels.Campaign} The campaign object
        """
        response = self.session.get(self._get_full_url("get_campaign", campaign_id=campaign_id))
        self.validate_response(response, f"Unable to get campaign {campaign_id}")

        return self.parser.build_campaign_obj(response.json())

    def get_campaign_forensics(self, campaign_id, filters, limit):
        """
        Get campaign forensics
        :param campaign_id: {str} The campaign id
        :param filters: {str} filters for getting forensics by type
        :param limit: {int} limit how many forensics should be returned
        :return: {datamodels.Campaign} The campaign object
        """
        params = {
            "campaignId": campaign_id
        }
        response = self.session.get(self._get_full_url('get_forensics'), params=params)
        self.validate_response(response)

        return self.parser.build_forensic_data_object(response.json(), filters=filters, limit=limit)

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            if response.status_code == 429:
                raise ProofPointTapManagerError(
                    "The user has made too many requests over the past 24 hours and has been throttled.")

            raise ProofPointTapManagerError(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )


