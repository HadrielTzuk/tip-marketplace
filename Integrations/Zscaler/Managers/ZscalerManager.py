# ============================================================================#
# title           :ZscalerManager.py
# description     :This Module contain all Zscaler operations functionality
# author          :zivh@siemplify.co
# date            :15-05-2019
# python_version  :2.7
# libreries       :
# product_version : api v1
# docs            : https://help.zscaler.com/zia/api
# ============================================================================#

# ============================= IMPORTS ===================================== #
import requests
import copy
import json
import time
from urlparse import urlparse


# ============================== CONSTS ===================================== #

HEADERS = {
    'Content-Type': 'application/json'
}

EXCEEDED_RATE_LIMIT_STATUS_CODE = 429
BATCH_SIZE = 100

BASE_URL = '{0}/api/v1'

ADD_WHITE_LIST_KEY = 'Add'
REMOVE_WHITE_LIST_KEY = 'Remove'


# ============================= CLASSES ===================================== #


class ZscalerMissingError(Exception):
    """
    General Exception for Zscaler missing entity
    """
    pass


class ZscalerManagerError(Exception):
    """
    General Exception for Zscaler manager
    """
    pass


class LOGGER(object):
    def __init__(self, logger):
        self.logger = logger

    def info(self, msg):
        if self.logger:
            self.logger.info(msg)


class ZscalerManager(object):
    """
    Zscaler Manager
    """

    def __init__(self, api_root, login_id, api_key, password, verify_ssl=False, logger=None):
        """

        :param api_root: {string} Cloud_Name (admin.zscloud.net, admin.zscaler.net)
        :param login_id: {string} the email ID of the API admin
        :param api_key: {string} the api key. An organization can only have one API key
        :param password: {string} the password for the API admin
        :param verify_ssl: {bool}
        """

        self.LOGGER = LOGGER(logger)
        self.api_root = BASE_URL.format(api_root)
        self.username = login_id
        self.password = password
        self.api_key = None
        self.timestamp = None
        # Obfuscate the api key
        self.obfuscate_api_key(api_key)
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers = HEADERS
        # authenticate
        self.authenticate()

    def obfuscate_api_key(self, api_key):
        """
        Zscaler function
        Obfuscate the API key
        :param api_key:
        :return:
        """
        now = int(time.time() * 1000)
        n = str(now)[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(str(n)), 1):
            key += api_key[int(str(n)[i])]
        for j in range(0, len(str(r)), 1):
            key += api_key[int(str(r)[j]) + 2]

        self.api_key = key

        # A string that contains the a long value that represents the current time in milliseconds since
        # midnight, January 1, 1970 UTC. This timestamp value is used to obfuscate the API key given by Zscaler.
        self.timestamp = str(now)

    def authenticate(self):
        """
        Creates an authenticated session.
        """
        # Api key - A string that contains the obfuscated API key (the return value of the obfuscateApiKey() method)
        # Note: the Zscaler service checks that the timestamp passed by the request is within
        # a two-hour range of Zscaler's measured epoch time.
        # Creates an authenticated session. The response returns a cookie in the header called JSESSIONID

        params = {
            "apiKey": self.api_key,
            "username": self.username,
            "password": self.password,
            "timestamp": self.timestamp
        }
        res = self.session.post('{0}/authenticatedSession'.format(self.api_root), json=params)
        self.validate_response(res)
        self.LOGGER.info(u"Successfully authenticated.")

    def log_out(self):
        """
        Ends an authenticated session
        """
        # By default, the JSESSIONID that returned from activate expires within 30 minutes from the last activity
        # or request on that session, or when you explicitly log out
        res = self.session.delete('{0}/authenticatedSession'.format(self.api_root))
        self.validate_response(res)

    def test_connectivity(self):
        """
        Test connectivity to Zscaler by Checking if there is an authentication session.
        :return: {bool} True if successfully connected, Exception otherwise.
        """
        res = self.session.get('{0}/authenticatedSession'.format(self.api_root))
        self.validate_response(res)

        return True

    def get_blacklist_items(self):
        """
        Gets a list of black-listed URLs
        :return: {dict} that includes list of black-listed URLs {strings} or none
        """
        res = self.session.get("{}/security/advanced".format(self.api_root))
        self.validate_response(res)
        return res.json()

    def add_to_blacklist(self, url):
        """
        Adds a URL to black list.
        The action applied to the Advanced Threat Protection policys blacklist
        :param url: {str} url to be added
        """
        request_url = "{}/security/advanced/blacklistUrls?action=ADD_TO_LIST".format(self.api_root)
        res = self.session.post(request_url, json.dumps({
            "blacklistUrls": [url]
        }))

        self.validate_response(res)

    def remove_from_blacklist(self, url):
        """
        removes a URL from the black list.
        The action applied to the Advanced Threat Protection policys blacklist
        :param url: {str} url to be removed
        """
        # check if the url is blacklisted
        blacklisted_urls = self.get_blacklist_items()
        if url not in blacklisted_urls:
            raise ZscalerMissingError('Given host address is not blacklisted')

        request_url = "{}/security/advanced/blacklistUrls?action=REMOVE_FROM_LIST".format(self.api_root)
        res = self.session.post(request_url, json={
            "blacklistUrls": [url]
        })

        self.validate_response(res)

    def get_whitelist_items(self):
        """
        Gets a list of white-listed URLs
        :return: {dict} that includes list of white-listed URLs {strings}
        """
        res = self.session.get("{}/security".format(self.api_root))
        self.validate_response(res)
        return res.json()

    def update_to_whitelist(self, url, action):
        """
        Updates the list of white-listed URLs.
        :param url: {string} url
        :param action: {string} add or remove from whitelist
        """

        # first, get the list of white-listed urls
        # because the update will overwrite the previously-generated white list.
        url_list = self.get_whitelist_items().get('whitelistUrls') or []
        new_url_list = copy.copy(url_list)
        if url not in url_list:
            if action == ADD_WHITE_LIST_KEY:
                new_url_list.append(url)
            if action == REMOVE_WHITE_LIST_KEY:
                raise ZscalerMissingError('Given host address is not whitelisted')

        if url in url_list:
            if action == REMOVE_WHITE_LIST_KEY:
                new_url_list.remove(url)
            if action == ADD_WHITE_LIST_KEY:
                raise ZscalerMissingError('Given host address is already whitelisted')

        request_url = "{}/security".format(self.api_root)
        res = self.session.put(request_url, json={
            "whitelistUrls": new_url_list
        })

        self.validate_response(res)

    def list_url_categories(self):
        """
        Gets information about all URL categories.
        :return: {list} of url category and its urls {dict}
        """
        res = self.session.get("{}/urlCategories".format(self.api_root))
        self.validate_response(res)
        return res.json()

    def get_sandbox_report(self, md5_hash):
        """
        Get a full (i.e., complete) or summary detail report for an MD5 hash of a file that was analyzed by Sandbox.
        :param md5_hash: {string}
        :return:
        """
        request_url = "{0}/sandbox/report/{1}?details=full".format(self.api_root, md5_hash)
        res = self.session.get(request_url)
        self.validate_response(res)
        response = res.json()
        if not isinstance(response['Full Details'], dict):
            return {}
        return response

    def lookup_url(self, url):
        """
        Look up the categorization of the given set of URLs.
        Up to 100 URLs can be looked up per request, and a URL cannot exceed 1024 characters.
        :return: {list} of found urls {dict}
        """
        res = self.session.post("{}/urlLookup".format(self.api_root), json=[url])
        self.validate_response(res)
        return res.json()

    def lookup_urls(self, urls):
        """
        Look up the categorization of the given set of URLs.
        Up to 100 URLs can be looked up per request, and a URL cannot exceed 1024 characters.
        :return: {list} of found urls {dict}
        """
        def divide_chunks(data, chunk_size):
            """
            A generator for dividing a list to chunks of given size
            :param data: {list} List of items
            :param chunk_size: {int} Size of the chunks
            :yields: {list} The generated chunks
            """
            for i in range(0, len(data), chunk_size):
                yield data[i:i + chunk_size]

        results = []
        for chunk in divide_chunks(urls, BATCH_SIZE):
            res = self.session.post("{}/urlLookup".format(self.api_root), json=chunk)
            self.validate_response(res)
            results.extend(res.json())

        return results

    def activate_changes(self):
        """
        Activates configuration changes. (e.g. add to blacklist)
        :return: {dict} activates status {string}
        """
        request_url = "{0}/status/activate".format(self.api_root)
        res = self.session.post(request_url)
        self.validate_response(res)
        return res.json()

    def get_activate_status(self):
        """
        Gets the activation status for a configuration change.
        :return: {string} activates status
        """
        request_url = "{0}/status".format(self.api_root)
        res = self.session.get(request_url)
        self.validate_response(res)
        return res.json().get('status')

    @staticmethod
    def validate_response(response):
        """
        Validate response
        :param response: {requests.response} requests information
        """
        try:
            if response.status_code == EXCEEDED_RATE_LIMIT_STATUS_CODE:
                raise ZscalerManagerError("Error: you exceed the API request rate limit")

            response.raise_for_status()

        except requests.HTTPError as error:
            raise ZscalerManagerError(
                "Error: {error}. Status code:{code}. {text}".format(error=error, code=response.status_code,
                                                                    text=error.response.content))

    @staticmethod
    def validate_and_extract_url(url):
        # valid URL address in Zscaler is url without an http:// or https:// prefix.
        # URL should have at least host.domain pattern to qualify.
        if url.startswith('http://') or url.startswith('https://'):
            return '{uri.netloc}'.format(uri=urlparse(url))
        return url

