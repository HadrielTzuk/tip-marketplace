# ==============================================================================
# title           :WebsenseManager.py
# description     :This Module contain all Websense operations functionality
# author          :org@siemplify.co
# date            :11-15-17
# python_version  :2.7
# ==============================================================================

# =====================================
#              IMPORTS               #
# =====================================
import requests
from base64 import b64encode
from urlparse import urljoin
from copy import deepcopy
import urllib

# =====================================
#             CONSTANTS               #
# =====================================
# API Consts
CONTENT_GATEWAY_RESTART_COMMAND = "/opt/WCG/WCGAdmin restart"
GET_TRANSACTION_ID_URL_SUFFIX = "categories/start"
COMMIT_CHANGES_URL_SUFFIX = "categories/commit?transactionid={0}"
ROLLBACK_CHANGES_URL_SUFFIX = "categories/rollback?transactionid={0}"
ADD_URL_URL_SUFFIX = "categories/urls"
REMOVE_URL_URL_SUFFIX = "categories/delete/urls"
GET_URLS_URL_SUFFIX = "categories/urls?catname={0}"
GET_ALL_CATEGORIES_URL_SUFFIX = "categories/all"
CREATE_NEW_CATEGORY_URL_SUFFIX = "categories"
ADD_URL_JSON_FORMAT = {
    "Transaction ID":"",
    "Category Name":"siemplify security risk",
    "URLs" : []
}
CREATE_CATEGORY_FORMAT = {
    "Transaction ID":"",
    "Categories": [{"Category Name": "siemplify security",
                    "Category Description": "Categories found by XYZ",
                    "Parent": 0
                   }]
}

# =====================================
#              CLASSES                #
# =====================================
class WebsenseManagerError(Exception):
    """
    General Exception for websense manager
    """
    pass

class WebsenseAPIManager(object):
    """
    Responsible for all websense operations via API functionality
    """

    def __init__(self, api_root, username, password, verify_ssl=True):
        self.api_root = api_root
        self.verify = verify_ssl
        creds = "{0}:{1}".format(username, password)
        creds_b64 = b64encode(creds)
        self.headers = {"Authorization": "Basic {0}".format(creds_b64)}

    def _obtain_transaction_id(self):
        """
        Get transaction id from server in order to perform actions
        :return: {string} transaction_id
        """
        url = urljoin(self.api_root, GET_TRANSACTION_ID_URL_SUFFIX)
        req = requests.post(url, headers=self.headers, verify=self.verify)
        if req.ok:
            return req.json()["Transaction ID"]
        raise WebsenseManagerError("Cannot obtain transactionID via API request error-{0}".format(req.content))

    def _commit_changes(self, transaction_id):
        """
        Commit all changes and release transaction token
        :param transaction_id: {string}
        :return: {boolean} Success indicator
        """
        # Attach the transaction id to url
        try:
            commit_suffix = COMMIT_CHANGES_URL_SUFFIX.format(transaction_id)
            url = urljoin(self.api_root, commit_suffix)
            req = requests.post(url, headers=self.headers, verify=self.verify)
            if req.ok:
                return True
            else:
                self._discard(transaction_id)
                raise WebsenseManagerError("Cannot commit changes via API, error-{0}".format(req.content))
        except Exception as error:
            self._discard(transaction_id)
            raise WebsenseManagerError("Error occurred: {0}, message:{1}".format(error, error.message))

    def _discard(self, transaction_id):
        """
        Discard all changes and release transaction token
        :param transaction_id: {string}
        :return: {boolean} Success indicator
        """
        # Attach the transaction id to url
        discard_suffix = ROLLBACK_CHANGES_URL_SUFFIX.format(transaction_id)
        url = urljoin(self.api_root, discard_suffix)
        req = requests.post(url, headers=self.headers, verify=self.verify)
        if req.ok:
            return True
        raise WebsenseManagerError("Cannot discard changes via API, error-{0}".format(req.content))

    def test_connectivity(self):
        """
        Test connectivity to Websense API server
        :return: {boolean} Success indicator
        """
        transaction_id = self._obtain_transaction_id()
        if transaction_id:
            # Close the transaction
            try:
                response = self._commit_changes(transaction_id)
                if response:
                    return True
                return False
            except Exception as error:
                self._discard(transaction_id)
                raise WebsenseManagerError("Error occurred: {0}, message:{1}".format(error, error.message))

    def add_url_to_category(self, url, category_name):
        """
        Add url to API manage category in Websense content gateway (Only API created categories can be manipulate)
        :param url: {string} The url to block
        :param category_name: {string} The API manage category name
        :return: {boolean} Success indicator
        """
        transaction_id = self._obtain_transaction_id()
        try:
            request_url = urljoin(self.api_root, ADD_URL_URL_SUFFIX)
            request_json = deepcopy(ADD_URL_JSON_FORMAT)
            # Add relevant details
            request_json["Transaction ID"] = transaction_id
            request_json["Category Name"] = category_name
            request_json["URLs"] = [url]
            req = requests.post(request_url, headers=self.headers, json=request_json, verify=self.verify)
            if req.ok:
                commit_status = self._commit_changes(transaction_id)
                if commit_status:
                    return True
                else:
                    self._discard(transaction_id)
            else:
                self._discard(transaction_id)
            raise WebsenseManagerError("Cannot add url-{0} to category-{1} via API, error-{2}".format(url, category_name, req.content))
        except Exception as error:
            self._discard(transaction_id)
            raise WebsenseManagerError("Error occurred: {0}, message:{1}".format(error, error.message))

    def remove_url_form_category(self, url, category_name):
        """
        Remove url from API manage category in Websense content gateway(Only API created categories can be manipulate)
        :param url: {string} The url to unblock
        :param category_name: {string} The API manage category name
        :return: {boolean} Success indicator
        """
        transaction_id = self._obtain_transaction_id()
        try:
            request_url = urljoin(self.api_root, REMOVE_URL_URL_SUFFIX)
            request_json = deepcopy(ADD_URL_JSON_FORMAT)
            # Add relevant details
            request_json["Transaction ID"] = transaction_id
            request_json["Category Name"] = category_name
            request_json["URLs"] = [url]
            req = requests.post(request_url, headers=self.headers, json=request_json, verify=self.verify)
            if req.ok:
                commit_status = self._commit_changes(transaction_id)
                if commit_status:
                    return True
                else:
                    self._discard(transaction_id)
            else:
                self._discard(transaction_id)
            raise WebsenseManagerError("Cannot add url-{0} to category-{1} via API, error-{2}".format(url, category_name, req.content))
        except Exception as error:
            self._discard(transaction_id)
            raise WebsenseManagerError("Error occurred: {0}, message:{1}".format(error, error.message))

    def get_category_urls_list(self, category_name):
        """
        Get urls list of a specific API manage category
        :param category_name: {string} The API manage category name
        :return: {list of strings} Urls
        """
        # Handle whitespaces
        category_name = urllib.quote(category_name)
        get_urls_suffix = GET_URLS_URL_SUFFIX.format(category_name)
        url = urljoin(self.api_root, get_urls_suffix)
        req = requests.get(url, headers=self.headers, verify=self.verify)
        if req.ok:
            return req.json()["URLs"]
        raise WebsenseManagerError("Cannot retrive category-{0} details, error-{1}".format(category_name, req.content))
    
    def create_api_manage_policy(self, category_name, category_description, category_parent_id):
        """
        Create new API managed category
        :param category_name: {string}
        :param category_description: {string}
        :param category_parent_id: {int}
        :return: {boolean} is_succeed
        """
        transaction_id = self._obtain_transaction_id()
        try:
            request_url = urljoin(self.api_root, CREATE_NEW_CATEGORY_URL_SUFFIX)
            request_json = deepcopy(CREATE_CATEGORY_FORMAT)
            request_json["Transaction ID"] = transaction_id
            request_json["Categories"][0]["Category Name"] = category_name
            request_json["Categories"][0]["Category Description"] = category_description
            request_json["Categories"][0]["Parent"] = int(category_parent_id)
            req = requests.post(request_url, headers=self.headers, json=request_json, verify=self.verify)
            if req.ok:
                commit_status = self._commit_changes(transaction_id)
                if commit_status:
                    return True
                else:
                    self._discard(transaction_id)
            else:
                self._discard(transaction_id)
            raise WebsenseManagerError("Cannot create category-{0} via API, error-{1}".format(category_name, req.content))
        except Exception as error:
            self._discard(transaction_id)
            raise WebsenseManagerError("Error occurred: {0}, message:{1}".format(error, error.message))

    def get_all_categories(self):
        """
        Retrieve all exist categories
        :return: {dict} all categories
        """
        request_url = urljoin(self.api_root, GET_ALL_CATEGORIES_URL_SUFFIX)
        req = requests.get(request_url, headers=self.headers, verify=self.verify)
        if req.ok:
            return req.json()
        raise WebsenseManagerError("Cannot get all categories via API, error-{0}".format(req.content))

    
if __name__ == "__main__":
    pass