# ============================================================================#
# title           :IntezerManager.py
# description     :This Module contain all Intezer operations functionality
# author          :avital@siemplify.co
# date            :14-02-2019
# python_version  :2.7
# libreries       :requests
# requirments     :
# product_version :
# ============================================================================#

# ============================= IMPORTS ===================================== #
import urllib3
import hashlib
import requests
import os
import time


# ============================== CONSTS ===================================== #
API_ROOT = "https://analyze.intezer.com/api/v2-0"
SUCCESS_STATUS = "succeeded"
FAILED_STATUS = "failed"
MALICIOUS_VERDICTS = ["malicious", "suspicious"]

# ============================= CLASSES ===================================== #

class IntezerManagerError(Exception):
    """
    General Exception for Intezer manager
    """
    pass


class IntezerManager(object):

    def __init__(self, api_key, verify_ssl=False):
        self.session = requests.session()
        self.session.verify = verify_ssl

        access_token = self.obtain_access_token(api_key)
        self.session.headers["Authorization"] = "Bearer {}".format(access_token)

    def obtain_access_token(self, api_key):
        """
        Perform login and obtain access token
        :param api_key: {str} The api key to login with
        :return: {str} The access token
        """
        response = self.session.post("{}/get-access-token".format(API_ROOT),
                                     json={'api_key': api_key})
        self.validate_response(response, "Unable to obtain token")

        return response.json().get("result")

    def get_existing_analysis(self, file_hash):
        """
        Get existing analysis report of a hash if it exists
        :param file_hash: {str} The hash
        :return: {dict} Analysis report if exists, None otherwise.
        """
        response = self.session.get("{}/files/{}".format(API_ROOT, file_hash))

        if response.status_code == 404:
            # Hash analysis doesn't exist -return None
            return

        self.validate_response(response, "Unable to get existing analysis of {}".format(file_hash))
        return response.json().get("result")

    def submit_file(self, file_path):
        """
        Submit a file for analysis
        :param file_path: {str} The path of the file
        :return: {str} The url to query the result for
        """
        if not os.path.exists(file_path):
            raise IntezerManagerError("File {} doesn't exist.".format(file_path))

        with open(file_path, 'rb') as file_to_upload:
            files = {'file': ('file_name', file_to_upload)}

            response = self.session.post("{}/analyze".format(API_ROOT), files=files)
            self.validate_response(response, "Unable to submit file {}".format(file_path))

            return response.json()["result_url"]

    def submit_hash(self, file_hash):
        """
        Submit a hash for analysis
        :param file_hash: {str} The has of the file
        :return: {str} The url to query the result for
        """
        response = self.session.post("{}/analyze-by-hash".format(API_ROOT),
                                     json={
                                         "hash": file_hash
                                     })
        if response.status_code == 404:
            raise IntezerManagerError(
                "Hash {} is not available in Intezer Analyze".format(
                    file_hash))
        self.validate_response(response, "Unable to submit hash {}".format(file_hash))

        return response.json()["result_url"]

    def get_results(self, results_url):
        """
        Get analysis results
        :param results_url: {str} The url to query results for
        :return: {dict} The analysis results (report)
        """
        while not self.is_analysis_completed(results_url):
            time.sleep(1)

        if self.is_analysis_failed(results_url):
            response = self.session.get("{}{}".format(API_ROOT, results_url))
            raise IntezerManagerError("Analysis failed. Error: {}".format(
                response.json().get("error")))

        response = self.session.get("{}{}".format(API_ROOT, results_url))
        return response.json().get("result")

    def is_analysis_completed(self, results_url):
        """
        Check whether an analysis has completed or not
        :param results_url: {str} The url to query results for
        :return: {bool} True if completed, otherwise False.
        """
        response = self.session.get("{}{}".format(API_ROOT, results_url))
        self.validate_response(response,
                               "Unable to get results for {}".format(
                                   results_url))
        return response.json().get("status") in [SUCCESS_STATUS, FAILED_STATUS]

    def is_analysis_failed(self, results_url):
        """
        Check whether an analysis has failed or not
        :param results_url: {str} The url to query results for
        :return: {bool} True if failed, otherwise False.
        """
        response = self.session.get("{}{}".format(API_ROOT, results_url))
        self.validate_response(response,
                               "Unable to get results for {}".format(
                                   results_url))
        return response.json().get("status") == FAILED_STATUS

    def is_analysis_succeeded(self, results_url):
        """
        Check whether an analysis has succeeded or not
        :param results_url: {str} The url to query results for
        :return: {bool} True if succeeded, otherwise False.
        """
        response = self.session.get("{}{}".format(API_ROOT, results_url))
        self.validate_response(response,
                               "Unable to get results for {}".format(
                                   results_url))
        return response.json().get("status") == SUCCESS_STATUS

    @staticmethod
    def md5(file_path):
        """
        Generate an md5 hash of a file
        :param file_path: {str} The path of the file
        :return: {str} The md5 of the file
        """
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def sha256(file_path):
        """
        Generate an sha256 hash of a file
        :param file_path: {str} The path of the file
        :return: {str} The sha256 of the file
        """
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise IntezerManagerError(
                "{error_msg}: {error} {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=response.json().get("error", response.content)
                )
            )


