# ============================================================================#
# title           :DeepSightManager.py
# description     :This Module contain all DeepSight operations functionality
# author          :avital@siemplify.co
# date            :26-04-2018
# python_version  :2.7
# libreries       : requests, urlparse, urllib
# requirments     :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #
import requests
from urlparse import urljoin
import urllib

# ============================== CONSTS ===================================== #
API = "https://deepsightapi.symantec.com/v1/"
SCAN_FILES = "files/"
SCAN_IPS = "ips/"
SCAN_DOMAINS = "domains/"
SCAN_URLS = "urls/"
SCAN_EMAILS = "mati/emails"
SCAN_FILENAMES = "mati/files"
HEADERS = {'Accept': 'application/json'}
TEST_IP = "8.8.8.8"

# ============================= CLASSES ===================================== #
class DeepSightManagerException(Exception):
    """
    General Exception for DeepSight manager
    """
    pass


class DeepSightManager(object):
    """
    DeepSight manager
    """
    def __init__(self, api_key, use_ssl=True):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers = HEADERS
        self.session.headers.update({'API-KEY': self.api_key})
        self.session.verify = use_ssl

    def test_connectivity(self):
        """
        Test connectivity
        :return:
        """
        self.scan_ip(TEST_IP)
        return True

    def scan_url(self, url):
        """
        Scan a url
        :param url: {str} The url to scan
        :return: {JSON} The info about the url
        """
        request_url = urljoin(API, SCAN_URLS)
        request_url = urljoin(request_url, urllib.quote_plus(url))
        result = self.session.get(request_url)
        self.validate_response(result, "Unable to scan url {}".format(url))
        return result.json()

    def scan_file(self, filehash):
        """
        Scan a filehash
        :param filehash: {str} The filehash to scan
        :return: {JSON} The info about the filehash
        """
        request_url = urljoin(API, SCAN_FILES)
        request_url = urljoin(request_url, filehash)
        result = self.session.get(request_url)
        self.validate_response(result, "Unable to scan hash {}".format(filehash))
        return result.json()

    def scan_domain(self, domain):
        """
        Scan a domain
        :param domain: {str} The domain to scan
        :return: {JSON} The info about the domain
        """
        request_url = urljoin(API, SCAN_DOMAINS)
        request_url = urljoin(request_url, domain)
        result = self.session.get(request_url)
        self.validate_response(result, "Unable to scan domain {}".format(domain))
        return result.json()

    def scan_ip(self, ip):
        """
        Scan a ip
        :param ip: {str} The ip to scan
        :return: {JSON} The info about the ip
        """
        request_url = urljoin(API, SCAN_IPS)
        request_url = urljoin(request_url, ip)
        result = self.session.get(request_url)
        self.validate_response(result, "Unable to scan ip {}".format(ip))
        return result.json()

    def scan_filename(self, filename):
        """
        Scan a filename
        :param filename: {str} The filename to scan
        :return: {JSON} The info about the filename
        """
        request_url = urljoin(API, SCAN_FILENAMES)
        request_url = "%s?q=%s" % (request_url, filename)
        result = self.session.get(request_url)
        self.validate_response(result, "Unable to scan file {}".format(filename))
        return result.json()

    def scan_email_address(self, email_address):
        """
        Scan an email address
        :param email_address: {str} The email address to scan
        :return: {JSON} The info about the email address
        """
        request_url = urljoin(API, SCAN_EMAILS)
        request_url = "%s?q=%s" % (request_url, email_address)
        result = self.session.get(request_url)
        self.validate_response(result, "Unable to scan email {}".format(email_address))
        return result.json()

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise DeepSightManagerException(
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
                          map(str, [unicode(result.get(h, None)).encode('utf-8') for h in headers])]))

        return csv_output


