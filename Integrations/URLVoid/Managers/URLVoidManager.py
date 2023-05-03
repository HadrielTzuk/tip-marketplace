# ==============================================================================
# title           :URLVoidManager.py
# description     :This Module contain all URLVoid cloud operations functionality
# author          :zdemoniac@gmail.com
# date            :01-06-18
# python_version  :2.7
# libreries       : copy, json, requests, urllib2, xml
# requirments     :
# product_version :
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from copy import copy
import json
from urlparse import urlparse 
import requests
import urllib2


# =====================================
#              CLASSES                #
# =====================================
class URLVoidManagerError(Exception):
    """
    General Exception for URLVoid manager
    """
    pass


class URLVoidManager(object):
    """
    Responsible for all URLVoid system operations functionality
    """
    def __init__(self, api_root, api_key, verify_ssl=False):
        self.api_key = api_key
        self.api_root = api_root
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def test_connectivity(self):
        """
        Test connectivity to URLVoid
        :return: {bool} True if successful, exception otherwise.
        """
        response = self.session.get(
            url="{}/domainbl/v1/pay-as-you-go/?stats".format(self.api_root),
            params={
                "key": self.api_key
            }
        )
        self.validate_response(response, "Unable to connect to URLVoid")
        return True

    def get_domain_reputation(self, domain):
        """
        Get domain reputation from URLVoid
        :param domain: {string}
        :return: {dict}
        """
        response = self.session.get(
            url="{}/domainbl/v1/pay-as-you-go/".format(self.api_root),
            params={
                "host": domain,
                "key": self.api_key
            }
        )

        self.validate_response(
            response, "Unable to get reputation for {}".format(domain)
        )

        return response.json().get("data", {}).get("report", {})

    @staticmethod
    def create_blacklist_report_from_raw_data(reputation_data):
        """
        Create a blacklist report dict from the raw reputation data
        :param reputation_data: {dict} The raw reputation data
        :return: {dict} Blacklist report
        """
        blacklist_report = []

        for engine in reputation_data.get("blacklists", {}).get("engines",
                                                                {}).values():
            if "elapsed" in engine:
                # Elapsed - How long it took to get the data.
                # This is not important data - remove it.
                del engine["elapsed"]

            blacklist_report.append(engine)

        return blacklist_report

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                response.json()
            except:
                raise URLVoidManagerError(
                    "{error_msg}: {error} - {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=response.content)
                )

            raise URLVoidManagerError(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.json().get("error", "No error message."))
            )
 