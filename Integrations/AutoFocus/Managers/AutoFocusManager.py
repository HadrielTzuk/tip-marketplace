# ==============================================================================
# title           : AutoFocusManager.py
# description     : This Module contains all AutoFocus API operations functionality
# author          : igor_tca@favorites.org.ua
# date            : 12-14-17
# python_version  : 2.7
# libraries       : pan-python
# requirements    :
# product_version :
# ==============================================================================


# =====================================
#              IMPORTS                #
# =====================================
import sys
import pan.afapi
import json

# =====================================
#              CONSTS                 #
# =====================================

NOT_COMPLETED = u'0'
COMPLETED = u'1'
NOT_SUSPICIOUS = u'2'
COOKIE = u'af_cookie'
STATUS = u'af_status'
PERCENTAGE = u'af_percentage'


# =====================================
#              CLASSES                #
# =====================================
class AutoFocusManagerError(Exception):
    """
    General Exception for Auto Focus manager
    """
    pass


class AutoFocusManager:
    """
    Responsible for all Auto Focus operations functionality
    """

    def __init__(self, api_key):
        # Initialize AF API object
        try:
            self.afapi = pan.afapi.PanAFapi(panrc_tag='autofocus',
                                            api_key=api_key,
                                            verify_cert=False)
        except pan.afapi.PanAFapiError as e:
            print('pan.afapi.PanAFapi:', e)

    def test_connectivity(self):
        """
        Validates connectivity to AutoFocus
        :return: bool
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "alias.ip_address",
                    "operator": "contains",
                    "value": "8.8.8.8"
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)
        res = self.afapi.samples_search(data)
        res.raise_for_status()
        return True


    def get_report(self, tag):
        """
        Get further details about an AutoFocus tag
        :param str tag: Autofocus Tag
        :return: json 
        """
        pass

    def hunt_url(self, url, af_cookie=None):
        """
        Hunt a URL and retrieve a list of associated intelligence
        :param url {str}: URL
        :param af_cookie {str}: the query's cookie (query identifier)
        :return: If not af_cookie: return af_cookie, status (cookie of the
        new scan, and its completion status). If af_cookie and scan is still running,
        returns scan completion percentage, and completion status. If af_cookie
        and scan is complete, returns scan results and completion status.
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "alias.url",
                    "operator": "contains",
                    "value": url
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)

        if not af_cookie:
            # Query is running for first time
            res = self.afapi.samples_search(data)
            res.raise_for_status()

            result = res.json
            if result is None:
                raise AutoFocusManagerError(
                    'Response not JSON while hunting for {}'.format(url))

            af_cookie = result.get('af_cookie')

            if af_cookie is None:
                raise AutoFocusManagerError(
                    'No af_cookie in response while hunting for {}'.format(
                        url))

            return af_cookie, NOT_COMPLETED

        # af_cookie exists - check status of query and return appropriate response.
        res = self.afapi.samples_results(af_cookie=af_cookie)
        res.raise_for_status()

        result = res.json
        if result is None:
            raise AutoFocusManagerError(
                'Response not JSON while hunting for {}'.format(url))

        if result.get('af_message') and result.get(
                'af_message') == "complete":
            # Query completed
            return result.get('hits'), COMPLETED

        # Query is still running
        return result.get('af_complete_percentage'), NOT_COMPLETED

    def hunt_domain(self, domain, af_cookie=None):
        """
        Hunt a domain and retrieve a list of associated intelligence
        :param domain {str}: domain name
        :param af_cookie {str}: the query's cookie (query identifier)
        :return: If not af_cookie: return af_cookie, status (cookie of the
        new scan, and its completion status). If af_cookie and scan is still running,
        returns scan completion percentage, and completion status. If af_cookie
        and scan is complete, returns scan results and completion status.
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "alias.domain",
                    "operator": "contains",
                    "value": domain
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)

        if not af_cookie:
            # Query is running for first time
            res = self.afapi.samples_search(data)
            res.raise_for_status()

            result = res.json
            if result is None:
                raise AutoFocusManagerError(
                    'Response not JSON while hunting for {}'.format(domain))

            af_cookie = result.get('af_cookie')

            if af_cookie is None:
                raise AutoFocusManagerError(
                    'No af_cookie in response while hunting for {}'.format(
                        domain))

            return af_cookie, NOT_COMPLETED

        # af_cookie exists - check status of query and return appropriate response.
        res = self.afapi.samples_results(af_cookie=af_cookie)
        res.raise_for_status()

        result = res.json
        if result is None:
            raise AutoFocusManagerError(
                'Response not JSON while hunting for {}'.format(domain))

        if result.get('af_message') and result.get(
                'af_message') == "complete":
            # Query completed
            return result.get('hits'), COMPLETED

        # Query is still running
        return result.get('af_complete_percentage'), NOT_COMPLETED

    def hunt_ip(self, ip, af_cookie=None):
        """
        Hunt an IP and retrieve a list of associated intelligence
        :param ip {str}: IP address
        :param af_cookie {str}: the query's cookie (query identifier)
        :return: If not af_cookie: return af_cookie, status (cookie of the
        new scan, and its completion status). If af_cookie and scan is still running,
        returns scan completion percentage, and completion status. If af_cookie
        and scan is complete, returns scan results and completion status.
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "alias.ip_address",
                    "operator": "contains",
                    "value": ip,
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)

        if not af_cookie:
            # Query is running for first time
            res = self.afapi.samples_search(data)
            res.raise_for_status()

            result = res.json
            if result is None:
                raise AutoFocusManagerError(
                    'Response not JSON while hunting for {}'.format(ip))

            af_cookie = result.get('af_cookie')

            if af_cookie is None:
                raise AutoFocusManagerError(
                    'No af_cookie in response while hunting for {}'.format(
                        ip))

            return af_cookie, NOT_COMPLETED

        # af_cookie exists - check status of query and return appropriate response.
        res = self.afapi.samples_results(af_cookie=af_cookie)
        res.raise_for_status()

        result = res.json
        if result is None:
            raise AutoFocusManagerError(
                'Response not JSON while hunting for {}'.format(ip))

        if result.get('af_message') and result.get(
                'af_message') == "complete":
            # Query completed
            return result.get('hits'), COMPLETED

        # Query is still running
        return result.get('af_complete_percentage'), NOT_COMPLETED

    def hunt_file_md5(self, md5, af_cookie=None):
        """
        Hunt a file and retrieve a list of associated intelligence
        :param md5 {str}: MD5 hash of a file
        :param af_cookie {str}: the query's cookie (query identifier)
        :return: If not af_cookie: return af_cookie, status (cookie of the
        new scan, and its completion status). If af_cookie and scan is still running,
        returns scan completion percentage, and completion status. If af_cookie
        and scan is complete, returns scan results and completion status.
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "sample.md5",
                    "operator": "is",
                    "value": md5
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)

        if not af_cookie:
            # Query is running for first time
            res = self.afapi.samples_search(data)
            res.raise_for_status()

            result = res.json
            if result is None:
                raise AutoFocusManagerError(
                    'Response not JSON while hunting for {}'.format(md5))

            af_cookie = result.get('af_cookie')

            if af_cookie is None:
                raise AutoFocusManagerError(
                    'No af_cookie in response while hunting for {}'.format(
                        md5))

            return af_cookie, NOT_COMPLETED

        # af_cookie exists - check status of query and return appropriate response.
        res = self.afapi.samples_results(af_cookie=af_cookie)
        res.raise_for_status()

        result = res.json
        if result is None:
            raise AutoFocusManagerError(
                'Response not JSON while hunting for {}'.format(md5))

        if result.get('af_message') and result.get(
                'af_message') == "complete":
            # Query completed
            return result.get('hits'), COMPLETED

        # Query is still running
        return result.get('af_complete_percentage'), NOT_COMPLETED

    def hunt_file_sha1(self, sha1, af_cookie=None):
        """
        Hunt a file and retrieve a list of associated intelligence
        :param sha1 {str}: SHA1 hash of a file
        :param af_cookie {str}: the query's cookie (query identifier)
        :return: If not af_cookie: return af_cookie, status (cookie of the
        new scan, and its completion status). If af_cookie and scan is still running,
        returns scan completion percentage, and completion status. If af_cookie
        and scan is complete, returns scan results and completion status.
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "sample.sha1",
                    "operator": "is",
                    "value": sha1
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)

        if not af_cookie:
            # Query is running for first time
            res = self.afapi.samples_search(data)
            res.raise_for_status()

            result = res.json
            if result is None:
                raise AutoFocusManagerError(
                    'Response not JSON while hunting for {}'.format(sha1))

            af_cookie = result.get('af_cookie')

            if af_cookie is None:
                raise AutoFocusManagerError(
                    'No af_cookie in response while hunting for {}'.format(
                        sha1))

            return af_cookie, NOT_COMPLETED

        # af_cookie exists - check status of query and return appropriate response.
        res = self.afapi.samples_results(af_cookie=af_cookie)
        res.raise_for_status()

        result = res.json
        if result is None:
            raise AutoFocusManagerError(
                'Response not JSON while hunting for {}'.format(sha1))

        if result.get('af_message') and result.get('af_message') == "complete":
            # Query completed
            return result.get('hits'), COMPLETED

        # Query is still running
        return result.get('af_complete_percentage'), NOT_COMPLETED

    def hunt_file_sha256(self, sha256, af_cookie=None):
        """
        Hunt a file and retrieve a list of associated intelligence
        :param sha256 {str}: SHA256 hash of a file
        :param af_cookie {str}: the query's cookie (query identifier)
        :return: If not af_cookie: return af_cookie, status (cookie of the
        new scan, and its completion status). If af_cookie and scan is still running,
        returns scan completion percentage, and completion status. If af_cookie
        and scan is complete, returns scan results and completion status.
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "sample.sha256",
                    "operator": "is",
                    "value": sha256
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)

        if not af_cookie:
            # Query is running for first time
            res = self.afapi.samples_search(data)
            res.raise_for_status()

            result = res.json
            if result is None:
                raise AutoFocusManagerError(
                    'Response not JSON while hunting for {}'.format(sha256))

            af_cookie = result.get('af_cookie')

            if af_cookie is None:
                raise AutoFocusManagerError(
                    'No af_cookie in response while hunting for {}'.format(
                        sha256))

            return af_cookie, NOT_COMPLETED

        # af_cookie exists - check status of query and return appropriate response.
        res = self.afapi.samples_results(af_cookie=af_cookie)
        res.raise_for_status()

        result = res.json
        if result is None:
            raise AutoFocusManagerError(
                'Response not JSON while hunting for {}'.format(sha256))

        if result.get('af_message') and result.get(
                'af_message') == "complete":
            # Query completed
            return result.get('hits'), COMPLETED

        # Query is still running
        return result.get('af_complete_percentage'), NOT_COMPLETED

    def hunt_file_filename(self, filename, af_cookie=None):
        """
        Hunt a file and retrieve a list of associated intelligence
        :param filename {str}: filename with extention
        :param af_cookie {str}: the query's cookie (query identifier)
        :return: If not af_cookie: return af_cookie, status (cookie of the
        new scan, and its completion status). If af_cookie and scan is still running,
        returns scan completion percentage, and completion status. If af_cookie
        and scan is complete, returns scan results and completion status.
        """
        data = {
            "query": {
                "operator": "all",
                "children": [{
                    "field": "alias.filename",
                    "operator": "contains",
                    "value": filename
                }]
            },
            "scope": "global",
            "size": 100,
            "from": 0
        }

        data = json.dumps(data)

        if not af_cookie:
            # Query is running for first time
            res = self.afapi.samples_search(data)
            res.raise_for_status()

            result = res.json
            if result is None:
                raise AutoFocusManagerError(
                    'Response not JSON while hunting for {}'.format(filename))

            af_cookie = result.get('af_cookie')

            if af_cookie is None:
                raise AutoFocusManagerError(
                    'No af_cookie in response while hunting for {}'.format(
                        filename))

            return af_cookie, NOT_COMPLETED

        # af_cookie exists - check status of query and return appropriate response.
        res = self.afapi.samples_results(af_cookie=af_cookie)
        res.raise_for_status()

        result = res.json
        if result is None:
            raise AutoFocusManagerError(
                'Response not JSON while hunting for {}'.format(filename))

        if result.get('af_message') and result.get(
                'af_message') == "complete":
            # Query completed
            return result.get('hits'), COMPLETED

        # Query is still running
        return result.get('af_complete_percentage'), NOT_COMPLETED

    def get_results_iterator(self, data):
        """
        Internal method to facilitate data exchange
        """
        try:
            r = self.afapi.samples_search_results(data, False)
            return r
        except pan.afapi.PanAFapiError as e:
            print('ERROR while trying to get results iterator:', e)
            sys.exit(1)

    def construct_csv(self, results):
        """
        Constructs csv from results
        :param results {list}: AutoFocus hits list
        :return: csv formatted str
        """
        return construct_csv(results)

