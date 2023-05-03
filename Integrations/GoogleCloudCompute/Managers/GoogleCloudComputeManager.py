# ============================================================================#
# title           :GoogleCloudComputeManager.py
# description     :This Module contain all Google Cloud Compute operations functionality
# author          :amit.levizky@siemplify.co
# date            :31-05-2021
# python_version  :3.7
# product_version :1.0
# ============================================================================#

from typing import List, Optional, Dict
from urllib.parse import urljoin

# ============================= IMPORTS ===================================== #
import requests
import requests.adapters
from google.auth.exceptions import TransportError
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2 import service_account

from GoogleCloudComputeParser import GoogleCloudComputeParser
from consts import (
    SCOPES,
    API_URL,
    INTEGRATION_NAME,
    DEFAULT_MAX_RESULT,
    DEFAULT_PAGE_SIZE,
    INVALID_ZONE_ERROR,
    INVALID_LABELS_ERROR,
    DEFAULT_ORDER,
    NOT_FOUND_RESOURCE_ERROR
)
from datamodels import Instance
from exceptions import (
    GoogleCloudComputeManagerError,
    GoogleCloudComputeInvalidZone,
    GoogleCloudTransportException,
    GoogleCloudComputeLabelsValidationError,
    GoogleCloudComputeInvalidInstanceID,
    GoogleCloudComputeValidationError
)
from utils import parse_string_to_dict

# ============================= CLASSES ===================================== #

ENDPOINTS = {
    "ping": "compute/v1/projects/{project_id}/zones",
    "list_instances": "compute/v1/projects/{project_id}/zones/{zone}/instances",
    "get_instance": "compute/v1/projects/{project_id}/zones/{zone}/instances/{resource_id}",
    "get_instance_iam_policy": "compute/v1/projects/{project_id}/zones/{zone}/instances/{resource_id}/getIamPolicy",
    "set_instance_iam_policy": "compute/v1/projects/{project_id}/zones/{zone}/instances/{resource_id}/setIamPolicy",
    "add_labels_to_instance": "compute/v1/projects/{project_id}/zones/{zone}/instances/{resource_id}/setLabels",
    "start_instance": "compute/v1/projects/{project_id}/zones/{zone}/instances/{resource_id}/start",
    "stop_instance": "compute/v1/projects/{project_id}/zones/{zone}/instances/{resource_id}/stop",
    "delete_instance": "compute/v1/projects/{project_id}/zones/{zone}/instances/{resource_id}"
}


class GoogleCloudComputeManager(object):
    """
    Google Cloud Compute Manager
    """

    def __init__(self, account_type: str, project_id: str, private_key_id: str, private_key: str, client_email: str,
                 client_id: str, auth_uri: str, token_uri: str, auth_provider_x509_url: str,
                 client_x509_cert_url: str, force_test_connectivity: Optional[bool] = False,
                 service_account_json: str = None, verify_ssl: bool = True):

        if service_account_json:
            creds = parse_string_to_dict(service_account_json)
        else:
            creds = {
                "type": account_type,
                "project_id": project_id,
                "private_key_id": private_key_id,
                "private_key": private_key.replace("\\n", "\n") if private_key else None,
                "client_email": client_email,
                "client_id": client_id,
                "auth_uri": auth_uri,
                "token_uri": token_uri,
                "auth_provider_x509_cert_url": auth_provider_x509_url,
                "client_x509_cert_url": client_x509_cert_url
            }
            if any(param is None for param in creds.values()):
                raise GoogleCloudComputeValidationError(
                    "Please fill either 'Service Account Json File Content' or all other parameters"
                )

        self.parser = GoogleCloudComputeParser()

        self.project_id = creds["project_id"]
        credentials = service_account.Credentials.from_service_account_info(info=creds, scopes=SCOPES)
        self.session = AuthorizedSession(credentials, auth_request=self.prepare_auth_request(verify_ssl))
        self.session.verify = verify_ssl

        if force_test_connectivity:
            self.test_connectivity()

    @staticmethod
    def prepare_auth_request(verify_ssl: bool = True):
        """
        Prepare an authenticated request.

        Note: This method is a duplicate of the same method in the GoogleCloudComputeManager class. The only change is
        that created session is using verify_ssl parameter to allow self-signed certificates.
        """
        auth_request_session = requests.Session()
        auth_request_session.verify = verify_ssl

        # Using an adapter to make HTTP requests robust to network errors.
        # This adapter retries HTTP requests when network errors occur
        # and the requests seems safely retryable.
        retry_adapter = requests.adapters.HTTPAdapter(max_retries=3)
        auth_request_session.mount("https://", retry_adapter)

        # Do not pass `self` as the session here, as it can lead to
        # infinite recursion.
        return Request(auth_request_session)

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        """
        Validate a response
        :param response: {requests.Response} The response
        :param error_msg: {str} The error message to display on failure
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                response_json = response.json()

                if INVALID_LABELS_ERROR in response_json.get("error", {}).get("message"):
                    raise GoogleCloudComputeLabelsValidationError(
                        f"{error_msg}: {response_json.get('error', {}).get('message', response.content)}"
                    )

                if INVALID_ZONE_ERROR in response_json.get("error", {}).get("message"):
                    raise GoogleCloudComputeInvalidZone(
                        f"{error_msg}: {response_json.get('error', {}).get('message', response.content)}")

                if all(s in response_json.get("error", {}).get("message") for s in NOT_FOUND_RESOURCE_ERROR):
                    raise GoogleCloudComputeInvalidInstanceID(
                        f"{error_msg}: {response_json.get('error', {}).get('message', response.content)}")

                raise GoogleCloudComputeManagerError(
                    f"{error_msg}: {error} {response.json().get('error', {}).get('message', response.content)}"
                )

            except (GoogleCloudComputeManagerError, GoogleCloudComputeLabelsValidationError,
                    GoogleCloudComputeInvalidZone, GoogleCloudComputeInvalidInstanceID):
                raise

            except:
                raise GoogleCloudComputeManagerError(
                    f"{error_msg}: {error} {response.content}"
                )

    def _get_full_url(self, url_key, **kwargs) -> str:
        """
        Get full url from url key.
        :param url_id: {str} The key of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(API_URL, ENDPOINTS[url_key].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity
        """
        request_url = self._get_full_url('ping', **{'project_id': self.project_id})
        response = self.session.get(request_url)
        self.validate_response(response, f"Unable to connect to {INTEGRATION_NAME}")

    def list_instances(self, zone: str, limit: int = DEFAULT_MAX_RESULT, filter: str = None, order: str = DEFAULT_ORDER) -> List[
        Instance]:
        """
        List Google Cloud Compute instances based on the specified search criteria.
        :param zone: {str} instance zone name to search for instances in.
        :param limit: {int} how many instances to return.
        :param filter: {str} Filter the instances according to attributes. for example:
        :param order: {int} Sorts list results by a certain order.
        (status = \"RUNNING\") (name = \"instance-1\")
        :return: {List[datamodels.instances]} List of Instances model
        """
        params = {'maxResults': DEFAULT_PAGE_SIZE}

        if order and not filter:
            params['orderBy'] = order

        if filter:
            params['filter'] = filter
            params['pageToken'] = None

        request_url = self._get_full_url('list_instances', **{'project_id': self.project_id, 'zone': zone})
        response = self.session.get(request_url, params=params)
        self.validate_response(response, f"Unable to list instances from {INTEGRATION_NAME}")

        instances = []
        while response.json().get('items'):
            instances.extend(self.parser.build_instances_objs(response.json()))

            params['pageToken'] = response.json().get('nextPageToken')

            if not params['pageToken'] or len(instances) >= limit:
                break

            response = self.session.get(request_url, params=params)
            self.validate_response(response, f"Unable to list instances from {INTEGRATION_NAME}")

        return instances[:limit]

    def get_instance(self, zone: str, resource_id: str) -> Instance:
        """
        Get specific instance data
        :param zone: {str} instance zone name to search for instances in.
        :param resource_id: {str} The instance ID
        :return: {datamodels.Instance} Instance data model
        """
        try:
            request_url = self._get_full_url('get_instance',
                                             **{'project_id': self.project_id, 'zone': zone, 'resource_id': resource_id})
            response = self.session.get(request_url)
            self.validate_response(response, f"Unable to get resource with id: {resource_id} from {INTEGRATION_NAME}")
            return self.parser.build_instance_obj(response.json())

        except TransportError as error:
            raise GoogleCloudTransportException(error)

    def get_instance_iam_policy(self, zone: str, project_id: str, instance_id: str):
        """
        Gets the access control policy for the instance. May be empty if no such policy or instance exists.
        :param zone: {str} Zone name of the instance
        :param project_id: {str} Project ID of the instance
        :param instance_id: {str} Instance ID
        :return: {InstanceIAMPolicy} Instance IAM Policy data model
        """
        request_url = self._get_full_url('get_instance_iam_policy', project_id=project_id, zone=zone,
                                         resource_id=instance_id)
        response = self.session.get(request_url)
        self.validate_response(response, error_msg=f"Failed to get IAM policy for instance with id: {instance_id}")
        return self.parser.build_instance_iam_policy_obj(response.json())

    def set_instance_iam_policy(self, zone: str, project_id: str, instance_id: str, policy_json: dict):
        """
        Sets the access control policy for the instance.
        :param zone: {str} Zone name of the instance
        :param project_id: {str} Project ID of the instance
        :param instance_id: {str} Instance ID
        :param policy_json: {dict} Policy JSON to set
        :return: {InstanceIAMPolicy} Instance IAM Policy data model
        """
        request_url = self._get_full_url('set_instance_iam_policy', project_id=project_id, zone=zone,
                                         resource_id=instance_id)
        response = self.session.post(
            request_url,
            json=policy_json
        )
        self.validate_response(response, error_msg=f"Failed to set IAM policy for instance with id: {instance_id}")
        return self.parser.build_instance_iam_policy_obj(response.json())

    def set_labels_to_instance(self, project_id: str, zone: str, instance_id: str, labels: Optional[Dict[str, str]],
                               label_fingerprint: str):
        """
        Set labels on an instance
        :param project_id: {str} Project ID of the instance
        :param zone: {str} The name of the zone for the instance
        :param instance_id: {str} Instance ID
        :param labels: [{str}] List of labels to set
        :param label_fingerprint: {str} Fingerprint of the previous set of labels for this instance, used to prevent conflicts. A
        base64-encoded string.
        :return: {OperationResource} Operation resource datamodel
        """
        request_url = self._get_full_url("add_labels_to_instance", project_id=project_id, zone=zone,
                                         resource_id=instance_id)
        payload = {
            "labels": labels,
            "labelFingerprint": label_fingerprint
        }
        response = self.session.post(request_url, json=payload)
        self.validate_response(response, error_msg=f"Failed to set labels for instance with id: {instance_id}")
        return self.parser.build_operation_resource_obj(response.json())

    def start_instance(self, zone: str, instance_id: str) -> Dict:
        """
        Start a previously stopped Google Cloud Compute Instance. Note that it can take a few minutes for the instance
        to enter the running status.
        :param zone: {str} The name of the zone for the instance.
        :param instance_id: {str} Instance ID.
        :return: {Dict} The results of the operation
        """
        request_url = self._get_full_url("start_instance", project_id=self.project_id, zone=zone,
                                         resource_id=instance_id)
        response = self.session.post(request_url)
        self.validate_response(response, error_msg=f"Failed to start instance with id: {instance_id}")
        return response.json()

    def stop_instance(self, zone: str, instance_id: str) -> Dict:
        """
        Stops a running instance, shutting it down cleanly, and allows you to restart the instance at a later time.
        Stopped instances do not incur VM usage charges while they are stopped. However, resources that the VM is using,
        such as persistent disks and static IP addresses, will continue to be charged until they are deleted.
        :param zone: {str} The name of the zone for the instance.
        :param instance_id: {str} Instance ID.
        :return: {Dict} The results of the operation
        """
        request_url = self._get_full_url("stop_instance", project_id=self.project_id, zone=zone,
                                         resource_id=instance_id)
        response = self.session.post(request_url)
        self.validate_response(response, error_msg=f"Failed to stop instance with id: {instance_id}")
        return response.json()

    def delete_instance(self, zone: str, instance_id: str) -> Dict:
        """
        Deletes the specified Instance resource.
        :param zone: {str} The name of the zone for the instance.
        :param instance_id: {str} Name of the instance resource to delete.
        :return: {Dict} The results of the operation
        """
        request_url = self._get_full_url("delete_instance", project_id=self.project_id, zone=zone,
                                         resource_id=instance_id)
        response = self.session.delete(request_url)
        self.validate_response(response, error_msg=f"Failed to delete instance with id: {instance_id}")
        return response.json()
