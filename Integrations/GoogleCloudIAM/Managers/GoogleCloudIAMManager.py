# ============================================================================#
# title           :GoogleCloudIAMManager.py
# description     :This Module contain all Google Cloud IAM operations functionality
# author          :gabriel.munits@siemplify.co
# date            :23-06-2021
# python_version  :3.7
# product_version :1.0
# ============================================================================#
from typing import Optional, List
from urllib.parse import urljoin

import requests
import requests.adapters
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2 import service_account

from GoogleCloudIAMParser import GoogleCloudIAMParser
from SiemplifyLogger import SiemplifyLogger
from consts import (
    INTEGRATION_DISPLAY_NAME,
    API_URL,
    SCOPES,
    INVALID_JSON_PAYLOAD,
    INVALID_ARGUMENT,
    MAX_PAGE_SIZE,
    DEFAULT_PAGE_SIZE,
    ALREADY_EXISTS,
    NON_EXISTING_ROLE_NAME,
    ROLE_ALREADY_DELETED,
    MAX_PAGE_SIZE_SERVICE_ACCOUNTS,
    INVALID_ROLE_ID
)
from datamodels import (
    Policy,
    Role
)
from exceptions import (
    GoogleCloudIAMManagerError,
    GoogleCloudIAMPolicyJSONError,
    GoogleCloudIAMRoleExistsError,
    GoogleCloudIAMRoleJSONError,
    GoogleCloudIAMRoleMissingError,
    GoogleCloudIAMServiceAccountExistsError,
    GoogleCloudIAMRoleIDInvalidError,
    GoogleCloudIAMValidationError
)
from utils import parse_string_to_dict


# ============================= CONSTS ===================================== #

ENDPOINTS = {
    'ping': '/v1/projects/{project_id}/serviceAccounts',
    'get-service-account-iam-policy': '/v1/projects/{project_id}/serviceAccounts/{resource}:getIamPolicy',
    'set-service-account-iam-policy': '/v1/projects/{project_id}/serviceAccounts/{resource}:setIamPolicy',
    'disable-service-account': '/v1/projects/{project_id}/serviceAccounts/{resource}:disable',
    'enable-service-account': '/v1/projects/{project_id}/serviceAccounts/{resource}:enable',
    'delete-service-account': '/v1/projects/{project_id}/serviceAccounts/{resource}',
    'list-roles': '/v1/roles',
    'list-project_roles': '/v1/projects/{project_id}/roles',
    'create-projects-role': '/v1/projects/{project_id}/roles',
    'get-projects-role': '/v1/projects/{project_id}/roles/{role_id}',
    'delete-role': '/v1/projects/{project_id}/roles/{role_id}',
    'list-service-accounts': '/v1/projects/{project_id}/serviceAccounts',
    'create-service-account': '/v1/projects/{project_id}/serviceAccounts'
}


# ============================= CLASSES ===================================== #

class GoogleCloudIAMManager(object):
    """
    Google Cloud IAM Manager
    """

    def __init__(self, account_type: Optional[str] = None, project_id: Optional[str] = None, private_key_id: Optional[str] = None,
                 private_key: Optional[str] = None, client_email: Optional[str] = None, client_id: Optional[str] = None,
                 auth_uri: Optional[str] = None, token_uri: Optional[str] = None, auth_provider_x509_url: Optional[str] = None,
                 client_x509_cert_url: Optional[str] = None, force_test_connectivity: Optional[bool] = False,
                 logger: Optional[SiemplifyLogger] = None, service_account_json: str = None, verify_ssl: bool = True):
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
                raise GoogleCloudIAMValidationError(
                    "Please fill either 'Service Account Json File Content' or all other parameters"
                )
        self.project_id = creds["project_id"]
        self._session = AuthorizedSession(
            service_account.Credentials.from_service_account_info(info=creds, scopes=SCOPES),
            auth_request=self.prepare_auth_request(verify_ssl=verify_ssl)
        )
        self._session.verify = verify_ssl

        if force_test_connectivity:
            self.test_connectivity()

        self._parser = GoogleCloudIAMParser()
        self._siemplify_logger = logger

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

    @classmethod
    def _get_full_url(cls, url_key: str, **kwargs) -> str:
        """
        Get full url from url key.
        :param url_id: {str} The key of url
        :param kwargs: {dict} Key value arguments passed for string formatting
        :return: {str} The full url
        """
        return urljoin(API_URL, ENDPOINTS[url_key].format(**kwargs))

    @classmethod
    def validate_response(cls, response: requests.Response, error_msg: str = "An error occurred"):
        """
        Validate response
        :param response: {requests.Response} The response to validate
        :param error_msg: {str} Default message to display on error
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            try:
                response_json = response.json()
                raise GoogleCloudIAMManagerError(
                    f"{error_msg}: {error} {response_json.get('error', {}).get('message', response.text)}"
                )
            except GoogleCloudIAMManagerError:
                raise
            except:
                raise GoogleCloudIAMManagerError(
                    f"{error_msg}: {error} {response.text}"
                )

    def test_connectivity(self):
        """
        Test connectivity with Google Cloud IAM
            raise Exception if failed to test connectivity
        """
        request_url = self._get_full_url('ping', project_id=self.project_id)
        response = self._session.get(
            request_url,
            params={
                'pageSize': 1
            }
        )
        self.validate_response(response, error_msg=f"Failed to test connectivity with {INTEGRATION_DISPLAY_NAME}")

    def get_service_account_iam_policy(self, service_account_email: str) -> Policy:
        """
        Gets the IAM Policy that is attached to a Service Account.
        :param service_account_email: {str} Service account email
        :return: {IAMPolicy} IAM Policy data model
        """
        request_url = self._get_full_url('get-service-account-iam-policy', project_id=self.project_id, resource=service_account_email)
        response = self._session.post(request_url)
        self.validate_response(response, error_msg=f"Failed to get service account IAM policy for account: {service_account_email}")
        return self._parser.build_service_account_iam_policy(response.json())

    def set_service_account_iam_policy(self, service_account_email: str, policy_json: dict) -> Policy:
        """
        Sets an IAM policy that is attached to a ServiceAccount.
        :param service_account_email: {str} Service account email
        :param policy_json: {dict} The complete policy to be applied to the service account. The size of the policy is limited to a few 
        10s of KB.
        :return: {IAMPolicy} IAM Policy data model of the updated policy
        """
        request_url = self._get_full_url('set-service-account-iam-policy', project_id=self.project_id, resource=service_account_email)
        response = self._session.post(request_url, json={"policy": policy_json})
        error_msg = f"Failed to set IAM policy for account: {service_account_email}"
        try:
            self.validate_response(response, error_msg)
        except Exception as error:
            if INVALID_JSON_PAYLOAD in response.json().get("error", {}).get("message", response.text) or \
                    INVALID_ARGUMENT in response.json().get("error", {}).get("status", ""):
                raise GoogleCloudIAMPolicyJSONError(
                    f"{error_msg}: {error} {response.json().get('error', {}).get('message', response.text)}"
                )
            raise
        return self._parser.build_service_account_iam_policy(response.json())

    def disable_service_account(self, service_account_email: str):
        """
        Disables a Service Account immediately.
        :param service_account_email: {str} Service Account email
        """
        request_url = self._get_full_url('disable-service-account', project_id=self.project_id, resource=service_account_email)
        response = self._session.post(request_url)
        self.validate_response(response, error_msg=f"Failed to disable account: {service_account_email}")

    def enable_service_account(self, service_account_email: str):
        """
        Enables a Service Account that was disabled.
        :param service_account_email: {str} Service Account email
        """
        request_url = self._get_full_url('enable-service-account', project_id=self.project_id, resource=service_account_email)
        response = self._session.post(request_url)
        self.validate_response(response, error_msg=f"Failed to enable account: {service_account_email}")

    def delete_service_account(self, service_account_email: str):
        """
        Deletes a Service Account.
        :param service_account_email: {str} Service Account email
        """
        request_url = self._get_full_url('delete-service-account', project_id=self.project_id, resource=service_account_email)
        response = self._session.delete(request_url)
        self.validate_response(response, error_msg=f"Failed to delete service account: {service_account_email}")

    def list_roles(self, show_deleted: bool, role_view: str, max_results: int) -> List[Role]:
        """
        List every predefined Role that IAM supports, or every custom role that is defined for an organization or project.
        :param show_deleted: {bool} True if to include roles that have been deleted
        :param role_view: {str} View of roles. Can be BASIC or FULL.
        :param max_results: {int} Max roles to return
        :return: {[Role]} List of Role data models
        """
        request_url = self._get_full_url('list-roles')
        response = self._session.get(
            request_url,
            params={
                'pageSize': min(max_results, MAX_PAGE_SIZE),
                'showDeleted': show_deleted,
                'view': role_view
            }
        )
        self.validate_response(response, error_msg=f"Failed to list roles")
        roles = self._parser.build_role_obj_list(response.json())
        self._siemplify_logger.info(f"Fetched total of {len(roles)} roles")

        while len(roles) < max_results:
            # Fetch more roles if available
            next_page_token = self._parser.get_next_page_token_from_listed_roles(response.json())
            if not next_page_token:
                break

            self._siemplify_logger.info(f"Fetching more roles..")
            response = self._session.get(
                request_url,
                params={
                    'pageToken': next_page_token,
                    'pageSize': DEFAULT_PAGE_SIZE,
                    'showDeleted': show_deleted,
                    'view': role_view
                }
            )
            self.validate_response(response, error_msg="Failed to list more roles")
            more_fetched_roles = self._parser.build_role_obj_list(response.json())
            self._siemplify_logger.info(f"Fetched more {len(more_fetched_roles)} roles")
            roles.extend(more_fetched_roles)

        return roles[:max_results] if max_results else roles

    def list_project_roles(self, show_deleted: bool, role_view: str, max_results: int) -> List[Role]:
        """
        Lists every predefined Role that IAM supports, or every custom role that is defined for an organization or project.
        :param show_deleted: {bool} True if to include roles that have been deleted
        :param role_view: {str} View of roles. Can be BASIC or FULL.
        :param max_results: {int} Max roles to return
        :return: {[Role]} List of Role data models
        """
        request_url = self._get_full_url('list-project_roles', project_id=self.project_id)
        response = self._session.get(
            request_url,
            params={
                'pageSize': min(max_results, MAX_PAGE_SIZE),
                'showDeleted': show_deleted,
                'view': role_view
            }
        )
        self.validate_response(response, error_msg=f"Failed to list roles")
        roles = self._parser.build_role_obj_list(response.json())
        self._siemplify_logger.info(f"Fetched total of {len(roles)} roles")

        while len(roles) < max_results:
            # Fetch more roles if available
            next_page_token = self._parser.get_next_page_token_from_listed_roles(response.json())
            if not next_page_token:
                break

            self._siemplify_logger.info(f"Fetching more roles..")
            response = self._session.get(
                request_url,
                params={
                    'pageToken': next_page_token,
                    'pageSize': DEFAULT_PAGE_SIZE,
                    'showDeleted': show_deleted,
                    'view': role_view
                }
            )
            self.validate_response(response, error_msg="Failed to list more roles")
            more_fetched_roles = self._parser.build_role_obj_list(response.json())
            self._siemplify_logger.info(f"Fetched more {len(more_fetched_roles)} roles")
            roles.extend(more_fetched_roles)

        return roles[:max_results] if max_results else roles

    def create_projects_role(self, role_id: str, role_definition_json: str):
        """
        Creates a new custom Role.
        :param role_id: {str} The role ID to use for this role
        :param role_definition_json: {dict} Role resource to create
        :return: {Role} Created Role data model
        """
        request_url = self._get_full_url('create-projects-role', project_id=self.project_id)
        response = self._session.post(
            request_url,
            json={
                'roleId': role_id,
                'role': role_definition_json
            }
        )
        try:
            self.validate_response(response, error_msg=f"Failed to create role with id: {role_id}")
        except Exception as error:
            if all(key in response.json().get("error", {}).get("message", response.text) for key in INVALID_ROLE_ID):
                raise GoogleCloudIAMRoleIDInvalidError(response.json().get("error", {}).get("message", response.text))
            if INVALID_ARGUMENT in response.json().get("error", {}).get("status", "") or \
                    INVALID_JSON_PAYLOAD in response.json().get("error", {}).get("message", response.text):
                raise GoogleCloudIAMRoleJSONError(error)
            if ALREADY_EXISTS in response.json().get("error", {}).get("status", ""):
                raise GoogleCloudIAMRoleExistsError(error)
            raise

        return self._parser.build_role_obj(response.json())

    def get_project_role(self, role_id):
        """
        Gets a definition of a Role.
        :param role_id: {str} Role id
        :return: {Role} Role data model
        """
        request_url = self._get_full_url('get-projects-role', project_id=self.project_id, role_id=role_id)
        response = self._session.get(request_url)
        try:
            self.validate_response(response, error_msg=f"Failed to get role with id: {role_id}")
        except Exception as error:
            if any(key in response.json().get("error", {}).get("message", response.text) for key in
                   NON_EXISTING_ROLE_NAME) or INVALID_ARGUMENT in response.json().get("error", {}).get("status", ""):
                raise GoogleCloudIAMRoleMissingError(error)
            raise
        return self._parser.build_role_obj(response.json())

    def delete_projects_role(self, role_id: str, etag: str):
        """
        Deletes a custom Role.
        :param role_id: {str} Role id
        :param etag: {str} etag of the Role
        :return: {Role} Role data model
        """
        request_url = self._get_full_url('delete-role', project_id=self.project_id, role_id=role_id)
        response = self._session.delete(
            request_url,
            params={
                'etag': etag
            }
        )
        try:
            self.validate_response(response, error_msg=f"Failed to delete role with id: {role_id}")
        except:
            if any(key in response.json().get("error", {}).get("message", response.text) for key in ROLE_ALREADY_DELETED):
                # Ignore exception if role was already deleted
                self._siemplify_logger.info(f"Role {role_id} was already deleted")
            else:
                raise
        return self._parser.build_role_obj(response.json())

    def list_service_accounts(self, max_results: Optional[int] = None):
        """
        Lists evey Service Account that belongs to a specific project.
        :param max_results: {int} Max service accounts to return. If not provided, all service accounts will be returned.
        :return: {[ServiceAccount]} List of Service Account data models
        """
        request_url = self._get_full_url('list-service-accounts', project_id=self.project_id)
        response = self._session.get(
            request_url,
            params={
                'pageSize': min(max_results, MAX_PAGE_SIZE_SERVICE_ACCOUNTS) if max_results is not None else MAX_PAGE_SIZE_SERVICE_ACCOUNTS
            }
        )
        self.validate_response(response, error_msg=f"Failed to list service accounts")
        service_accounts = self._parser.build_service_account_obj_list(response.json(), project_id=self.project_id)
        self._siemplify_logger.info(f"Fetched total of {len(service_accounts)} service accounts")

        while (max_results is None) or len(service_accounts) < max_results:
            # Fetch more roles if available
            next_page_token = self._parser.get_next_page_token_from_listed_service_accounts(response.json())
            if not next_page_token:
                break

            self._siemplify_logger.info(f"Fetching more service accounts..")
            response = self._session.get(
                request_url,
                params={
                    'pageToken': next_page_token,
                    'pageSize': MAX_PAGE_SIZE_SERVICE_ACCOUNTS
                }
            )
            self.validate_response(response, error_msg="Failed to list more service accounts")
            more_fetched_service_accounts = self._parser.build_service_account_obj_list(response.json(), project_id=self.project_id)
            self._siemplify_logger.info(f"Fetched more {len(more_fetched_service_accounts)} service accounts")
            service_accounts.extend(more_fetched_service_accounts)

        return service_accounts[:max_results] if max_results is not None else service_accounts

    def create_service_account(self, account_id: str, display_name: Optional[str] = None, description: Optional[str] = None):
        """
        Creates a Service Account.
        :param account_id: {str} The account id that is used to generate the service account email address and a stable unique id.
        :param display_name: {str} Human-readable name for the service account.
        :param description: {str} Human-readable description of the service account.
        :return: {ServiceAccount} Service Account data model
        """
        request_url = self._get_full_url('create-service-account', project_id=self.project_id)
        payload = {
            'accountId': account_id,
            'serviceAccount': {}
        }
        if display_name:
            payload['serviceAccount'].update({'displayName': display_name})
        if description:
            payload['serviceAccount'].update({'description': description})

        response = self._session.post(
            request_url,
            json={k: v for k, v in payload.items() if v}
        )

        try:
            self.validate_response(response, error_msg=f"Failed to create service account with account id: {account_id}")
        except Exception as error:
            if ALREADY_EXISTS in response.json().get("error", {}).get("status", ""):
                raise GoogleCloudIAMServiceAccountExistsError(error)
            raise

        return self._parser.build_service_account_obj(response.json(), project_id=self.project_id)
