import requests, json
from urllib.parse import urljoin
from copy import deepcopy
from AzureADParser import AzureADParser
from exceptions import AzureADError, AzureADNotFoundError, AzurePasswordComplexityError
from constants import ALL_FIELDS_IDENTIFIER, SELECT_ONE_FILTER_KEY

NOT_FOUNT_ERROR_CODE = 404
DEFAULT_ORDER_BY = "ASC"
DEFAULT_ORDER_BY_FIELD = "displayName"
SCOPE = "https://graph.microsoft.com/.default"
GRANT_TYPE = "client_credentials"
TOKEN_PAYLOAD = {"client_id": None,
                 "scope": SCOPE,
                 "client_secret": None,
                 "grant_type": GRANT_TYPE}

ACCESS_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
DUMMY_URL = "https://graph.microsoft.com/v1.0/"
USERS_URL = "https://graph.microsoft.com/v1.0/users"
USER_URL = "https://graph.microsoft.com/v1.0/users/{}"
USERS_MEMBERSOF_URL = "https://graph.microsoft.com/v1.0/users/{}/memberOf"
GROUPS_URL = "https://graph.microsoft.com/v1.0/groups"
MANAGER_URL = "https://graph.microsoft.com/v1.0/users/{}/manager"
DEVICES_URL = "https://graph.microsoft.com/v1.0/devices"
DIRECTORY_OBJECT = "https://graph.microsoft.com/v1.0/directoryObjects/{}"

LIST_OF_USERS_ORDER = "$orderby={}%20{}&$select={}"
LIST_OF_GROUPS_ORDER = "$orderby={}%20{}"
DEVICES_FILTER = "$filter=displayName%20eq%20'{}'"
USER_IN_GROUP = "$filter=id%20eq%20'{}'"
ENABLE_USER_ACCOUNT = {"accountEnabled": "true"}
DISABLE_USER_ACCOUNT = {"accountEnabled": "false"}
FORCE_PASSWORD_UPDATE = {
    "passwordProfile": {
        "forceChangePasswordNextSignIn": "true"
    }
}

GET_MANAGER_INFO = "$select=displayName, mobilePhone"

DEFAULT_API_ROOT = "https://graph.microsoft.com"

API_ENDPOINTS = {
    "ping": "/v1.0",
    "users": 'v1.0/users',
    "user": "v1.0/users/{user}",
    "group_users": "v1.0/groups/{group_id}/members/$ref",
    "user_member_of": "v1.0/users/{user}/memberOf",
    "manager": "v1.0/users/{user}/manager",
    "groups": "v1.0/groups",
    "devices": "v1.0/devices",
    "remove_user_from_group": "v1.0/groups/{group_id}/members/{user_id}/$ref",
    "list_user_groups": "v1.0/users/{username}/getMemberGroups",
    "group_members_details": "v1.0/groups/{group_id}/members",
    "revoke_user_session": "v1.0/users/{user_id}/revokeSignInSessions"
}


class AzureADManager(object):
    def __init__(self, client_id, client_secret, tenant, verify_ssl, force_check_connectivity=False, api_root=None):
        self.api_root = DEFAULT_API_ROOT
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant = tenant
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.access_token = self.generate_token(self.client_id, self.client_secret, self.tenant)
        self.session.headers.update(
            {"Authorization": "Bearer {0}".format(self.access_token), "Content-Type": "application/json"})
        self.parser = AzureADParser()

        if force_check_connectivity:
            self.test_connectivity()

    def generate_token(self, client_id, client_secret, tenant):
        """
        Request access token (Valid for 60 min)
        :param client_id: {string} The Application ID that the registration portal
        :param client_secret: {string} The application secret that you created in the app registration portal for your app.
        :param tenant: {string} Tenant or also called directory ID
        :return: {string} Access token. The app can use this token in calls to Microsoft Graph.
        """
        payload = deepcopy(TOKEN_PAYLOAD)
        payload["client_id"] = client_id
        payload["client_secret"] = client_secret
        res = self.session.post(ACCESS_TOKEN_URL.format(tenant=tenant), data=payload)
        self.validate_response(res)
        return res.json().get('access_token')

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier
        :param url_id: {str} the id of url
        :param kwargs: {dict} variables passed for string formatting
        :return: {str} the full url
        """

        return urljoin(self.api_root, API_ENDPOINTS[url_id].format(**kwargs))

    @staticmethod
    def validate_response(response, error_msg="An error occurred", validate_azure_status=False, handle_404=False,
                          check_message=False):

        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            try:
                response.json()
            except:
                raise AzureADError(
                    f"{error_msg}: {error} - {response.content}"
                )

            if handle_404 and response.status_code == NOT_FOUNT_ERROR_CODE:
                raise AzureADNotFoundError
            if check_message:
                message = response.json().get('error', {}).get('message', '')
                if message == "The specified password does not comply with password complexity requirements. " \
                              "Please provide a different password.":
                    raise AzurePasswordComplexityError(
                        f"{error_msg}: {error} - {response.json().get('error', 'No error message.')}"
                    )
            raise AzureADError(
                f"{error_msg}: {error} - {response.json().get('error', 'No error message.')}"
            )
        if validate_azure_status and not response.status_code == 204:
            raise AzureADError(f"{error_msg} - please check the logs.")

    def get_list_of_users(self, filter_field, filter_value, filter_logic, order_by=DEFAULT_ORDER_BY,
                          order_by_field=DEFAULT_ORDER_BY_FIELD, limit=None):
        """
        Function that requests a list of all users from the AzureAD
        :param filter_field: {string} A single value which specifies the user fields returned from the AzureAD
        :param filter_value: {string} What value should be used in the filter
        :param filter_logic: {string} What filter logic should be applied.
        :param order_by: {string} DESC or ASC keywords to specify the order of the results
        :param order_by_field: {string} Field name on based on which the order is done
        :param limit: {int} Max number of results to return
        :return: {List} List of users
        """
        if filter_field == ALL_FIELDS_IDENTIFIER:
            filter_field = ""

        url = self._get_full_url('users')
        additional_params = LIST_OF_USERS_ORDER.format(order_by_field, order_by, filter_field)

        return self._paginate_results(url=url, parser_method="build_siemplify_user_list", params=additional_params,
                                      limit=limit,
                                      err_msg="Unable to get list of users from Azure Active Directory, please check the connection.",
                                      filter_value=filter_value, filter_logic=filter_logic)


    def get_group_members(self, filter_key, filter_value, filter_logic, group_id, limit=None):
        """
        Function that requests a list of group members
        :param filter_key: {string} What filter key should be applied.
        :param filter_value: {string} What value should be used in the filter
        :param filter_logic: {string} What filter logic should be applied.
        :param limit: {int} Max number of results to return
        :return: {List} List of group members
        """
        
        if filter_key == SELECT_ONE_FILTER_KEY:
            filter_key = ""

        url = self._get_full_url('group_members_details', group_id=group_id)

        return self._paginate_results(url=url, parser_method="build_group_members_list", params=None,
                                      limit=limit,
                                      err_msg="Unable to get list of users from Azure Active Directory, please check the connection.",
                                      filter_value=filter_value, filter_logic=filter_logic, filter_key=filter_key)



    def get_list_of_groups(self, filter_value, filter_logic, order_by, limit=None):
        """
        Function that requests a list of all groups from the AzureAD
        :param order_by: {string} DESC or ASC keywords to specify the order of the results
        :param filter_value: {string} What value should be used in the filter
        :param filter_logic: {string} What filter logic should be applied.
        :return: {List} List of groups
        """
        url = self._get_full_url('groups')
        additional_params = LIST_OF_GROUPS_ORDER.format(DEFAULT_ORDER_BY_FIELD, order_by)
        return self._paginate_results(url=url, parser_method="build_siemplify_group_list", params=additional_params,
                                      limit=limit,
                                      err_msg="Unable to get list of groups from Azure Active Directory, please check the connection.",
                                      filter_value=filter_value, filter_logic=filter_logic)

    def get_list_of_all_groups(self):
        """
        Function that requests a list of all groups from the AzureAD
        :return: {List} List of groups
        """
        url = self._get_full_url('groups')
        return self._paginate_results(url=url, parser_method="build_siemplify_group_list",
                                      limit=None,
                                      err_msg="Unable to get list of groups from Azure Active Directory, please check the connection.")


    def enable_user(self, user_principal_name):
        """
        Function that enables used in the AzureAD
        :param user_principal_name: {string} User's principal name
        """
        payload = {
            "accountEnabled": "true"
        }
        response = self.session.patch(self._get_full_url("user", user=user_principal_name),
                                      json=payload)
        self.validate_response(
            response, f"Unable to enable the user {user_principal_name} in Azure Active Directory, please check the "
                      f"connection. ", validate_azure_status=True
        )

    def disable_user(self, user_principal_name):
        """
        Function that disables used in the AzureAD
        :param user_principal_name: {string} User's principal name
        """
        payload = {
            "accountEnabled": "false"
        }
        response = self.session.patch(self._get_full_url("user", user=user_principal_name),
                                      json=payload)
        self.validate_response(
            response, f"Unable to disable the user {user_principal_name} in Azure Active Directory, please check the "
                      f"connection.", validate_azure_status=True
        )

    def get_user(self, user_principal_name):
        """
        Function that enriches the USER entity
        :param user_principal_name: {string} User's principal name
        :return: {User} User object containing enrichment data for an user
        """
        response = self.session.get(self._get_full_url('user', user=user_principal_name))
        self.validate_response(response, f"Unable to enrich the user: {user_principal_name} in Azure Active Directory.")

        return self.parser.build_siemplify_user_object(response.json())

    def get_host(self, hostname):
        """
        Function that enriches the HOSTNAME entity
        :param hostname: {string} hostname that will be enriched, called device in AzureAD
        :return: {Host} Host object containing enrichment data for a host
        """
        response = self.session.get(self._get_full_url('devices'), params=DEVICES_FILTER.format(hostname))
        self.validate_response(response, f"Unable to enrich the host: {hostname} in Azure Active Directory.")
        results = self.parser.get_host_values(response.json())
        if results:
            filtered_results = [host for host in results if host.account_enabled]
            return sorted(filtered_results, key=lambda filtered_host: filtered_host.last_sign_in)[-1]

        raise AzureADError("Hostname {} was not found in the Azure Active Directory.".format(hostname))

    def force_password_update(self, user_principal_name):
        """
        Function that forces the password update based on user's principal name
        :param user_principal_name: {string} User's principal name
        """
        response = self.session.patch(self._get_full_url('user', user=user_principal_name), json=FORCE_PASSWORD_UPDATE)
        self.validate_response(response, f"Unable to force the password update for user: {user_principal_name}.",
                               validate_azure_status=True)

    def reset_user_password(self, user_principal_name, new_password):
        """
        Function that sets new password for a user based on user's principal name
        :param user_principal_name: {string} User's principal name
        :param new_password: {string} New password set for the user
        """
        payload = {
            "passwordProfile": {
                "forceChangePasswordNextSignIn": "true",
                "password": new_password
            }
        }

        response = self.session.patch(self._get_full_url('user', user=user_principal_name), json=payload)
        self.validate_response(response, f"Unable to reset password for user: {user_principal_name}.",
                               validate_azure_status=True, check_message=True)

    def check_user_in_group(self, user_principal_name, group_id):
        """
        Function that checks if an user is a member of a group.
        :param user_principal_name: {string} User's principal name
        :param group_id: {string} Group ID that identifies the group
        :return: {Bool} True is the user is a member of the group False otherwise
        """
        params = USER_IN_GROUP.format(group_id)
        response = self.session.get(self._get_full_url('user_member_of', user=user_principal_name), params=params)
        self.validate_response(response, f"Unable to check if user {user_principal_name} is in group {group_id}.")

        return self.parser.check_is_user_member_of(response.json())

    def get_user_id(self, user_principal_name):
        """
        Function that gets user's ID based on the user principal name
        :param user_principal_name: {string} User's principal name
        :return: {string} user's ID in AZureAD
        """
        response = self.session.get(self._get_full_url('user', user=user_principal_name))
        self.validate_response(response, f"Unable to get the ID of the user {user_principal_name}.")

        return self.parser.user_id_based_on_name(response.json())

    def get_user_id_with_filter(self, user_identifier, filter_keys):
        """
        Get user id by either user name or email
        :param user_identifier: {str} user name or email
        :param filter_keys: {list} displayName or mail
        :return: {string} user id if exist
        """
        url = self._get_full_url('users')

        if not filter_keys:
            raise AzureADError("Filter keys are not provided.")

        filter_string = " or ".join(
            f"{filter_key} eq \'{user_identifier}\'"
            for filter_key in filter_keys
        )

        params = {"$filter": filter_string}
        response = self.session.get(url, params=params)
        self.validate_response(response)

        users = response.json().get("value")

        for user in users:
            user_has_desired_attribute = any(
                user.get(filter_key) == user_identifier
                for filter_key in filter_keys
            )
            if user_has_desired_attribute:
                return user.get("id")

        raise AzureADNotFoundError("User not found")

    def revoke_user_session(self, user_id):
        """
        Revoke user session
        :param user_id: {str} Id of the user
        """
        url = self._get_full_url('revoke_user_session', user_id=user_id)
        response = self.session.post(url)
        self.validate_response(response)

        return response.json()

    def add_user_to_group(self, group_id, user_principal_name):
        """
        Function that adds an user to the group
        :param user_principal_name: {string} User's principal name
        :param group_id: {string} Group ID that identifies the group
        """
        payload = {
            "@odata.id": DIRECTORY_OBJECT.format(self.get_user_id(user_principal_name))
        }
        response = self.session.post(self._get_full_url('group_users', group_id=group_id), json=payload)
        self.validate_response(response, f"Unable to add user {user_principal_name} to the group {group_id}.",
                               validate_azure_status=True)

    def remove_user_from_group(self, group_id, user_id):
        """
        Function that removes the user from the group
        :param user_id: {string} User's ID
        :param group_id: {string} Group ID that identifies the group
        """
        request_url = self._get_full_url('remove_user_from_group', group_id=group_id, user_id=user_id)
        response = self.session.delete(request_url)
        self.validate_response(response, f"Unable to remove user from the group.",
                               validate_azure_status=True, handle_404=True)

    def get_group_id(self, group_name):
        """
        Function that gets group's ID based on the group name
        :param group_name: {string} Group's name
        :return: {string} group's ID in AZureAD
        """
        request_url = self._get_full_url('groups')
        groups = self._paginate_results(url=request_url, parser_method="build_siemplify_group_list",
                                        err_msg="Unable to get list of groups from Azure Active Directory, "
                                                "please check the connection.")

        return next((group.id for group in groups if group.name == group_name), None)

    def get_user_groups(self, username, only_security_enabled_groups, limit=None):
        """
        Get user groups by username
        :param username: {str} username to get groups for
        :param only_security_enabled_groups: {bool} specifies if only security groups that the user is a member should be returned
        :param limit: {int} limit for results
        :return: {list} list of Group objects
        """
        url = self._get_full_url('list_user_groups', username=username)
        payload = {
            "securityEnabledOnly": only_security_enabled_groups
        }

        response = self.session.post(url, json=payload)
        self.validate_response(response)
        return response.json().get("value", [])[:limit] if limit else response.json().get("value", [])

    def test_connectivity(self):
        """
        Function that checks the connection to the AzureAD
        """
        response = self.session.get(self._get_full_url("ping"))
        self.validate_response(
            response, "Unable to connect to Azure Active Directory"
        )

    def get_users_manager(self, user_principal_name):
        """
        Function that adds an user to the group
        :param user_principal_name: {string} User's principal name
        :return {User} information about the manager
        """
        response = self.session.get(self._get_full_url("manager", user=user_principal_name), params=GET_MANAGER_INFO)
        self.validate_response(response, f"Unable to get manager information for user {user_principal_name}.",
                               handle_404=True)

        return self.parser.build_users_manager_object(response.json())

    @staticmethod
    def validate_azure_status(response, error_message):
        """
        Function that validates the response from AzureAD, successful action resturns HTTP Code 204, everything else is considered as fail
        :param response: {Response} Raw response from the AzureAD
        :param error_message: {string} Error message used in the exception
        """
        if not response.status_code == 204:
            raise AzureADError(error_message)

    def _paginate_results(self, url, parser_method, method=None, params=None, body=None, limit=None, err_msg=None,
                          filter_value=None, filter_logic=None, filter_key=None):
        """
        Paginate the results of a job
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The url to send request to
        :param parser_method: {str} The name of parser method to build the result
        :param params: {dict} The params of the request
        :param body: {dict} The json payload of the request
        :param limit: {int} The limit of the results to fetch
        :param err_msg: {str} The message to display on error
        :param filter_value: {string} What value should be used in the filter
        :param filter_logic: {string} What filter logic should be applied.
        :param filter_key: {string} What filter key should be applied.
        :return: {list} List of results
        """
        method = method or 'GET'
        err_msg = err_msg or 'Unable to get results'
        params = params or {}

        response = self.session.request(method, url, params=params, json=body)

        self.validate_response(response, err_msg)
        results = getattr(self.parser, parser_method)(raw_data=response.json(), filter_value=filter_value,
                                                      filter_logic=filter_logic, filter_key=filter_key)
        while True:
            if limit and len(results) >= limit:
                break

            if not self.parser.get_page_next_link(response.json()):
                break

            response = self.session.request(method, self.parser.get_page_next_link(response.json()))
            self.validate_response(response, err_msg)
            results.extend(getattr(self.parser, parser_method)(raw_data=response.json(), filter_value=filter_value,
                                                               filter_logic=filter_logic, filter_key=filter_key))
        return results[:limit] if limit else results
