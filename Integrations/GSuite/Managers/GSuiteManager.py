# ============================================================================#
# title           :GSuiteManager.py
# description     :This Module contain all GSuite operations functionality
# author          :gabriel.munits@siemplify.co (refactored)
# date            :11-02-2020
# python_version  :3.7
# libraries       :requests
# requirements     :
# product_version :
# ============================================================================#

# HOW TO OBTAIN REFRESH TOKEN
# 1. Follow the instructions at the following link to enable Directory API and
# create OAuth client id and secret.
# https://developers.google.com/admin-sdk/directory/v1/get-start/getting-started
#
# 2. Using the generated client id and secret and selected redirect url use the
# Get Authorization action to generate an authorization url. Open the link and
# allow access to the needed scopes (must be done as a GSuite admin)
#
# 3. After completing the authorization, copy the url you were redirected to
# and use the Generate Token action to generate a refresh token. If the action
# resulted in an empty (None) refresh token, go to the link below:
# https://myaccount.google.com/u/0/permissions
# And remove the app permissions and repeat hte steps above.
#
# 4. Using the generated refresh token, configure the integration. Notice that
# the token is time limited and you will need to repeat the process in the
# future.

# ============================= IMPORTS ===================================== #

import crypt
import json
from typing import Optional, Any, Tuple
from urllib.parse import urljoin

import requests
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

import consts
import datamodels
import utils
from GSuiteParser import GSuiteParser
from consts import INTEGRATION_NAME
from exceptions import GSuiteManagerError, GSuiteEntityExistsException, GSuiteNotFoundException, GSuiteValidationException


# ============================== CONSTS ===================================== #
API_ROOT = "https://www.googleapis.com"

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user',
          'https://www.googleapis.com/auth/admin.directory.group.member',
          'https://www.googleapis.com/auth/admin.directory.customer.readonly',
          'https://www.googleapis.com/auth/admin.directory.domain.readonly',
          'https://www.googleapis.com/auth/admin.directory.group',
          'https://www.googleapis.com/auth/admin.directory.orgunit',
          'https://www.googleapis.com/auth/admin.directory.user.alias']

ENDPOINTS = {
    'ping': '/oauth2/v4/token',
    'refresh-token': '/oauth2/v4/token',
    'obtain-access-token': '/oauth2/v4/token',
    'create-group': '/admin/directory/v1/groups',
    'create-user': '/admin/directory/v1/users',
    'update-user': '/admin/directory/v1/users/{primary_email}',
    'get-user': '/admin/directory/v1/users/{primary_email}',
    'create-ou': '/admin/directory/v1/customer/{customer_id}/orgunits',
    'update-ou': '/admin/directory/v1/customer/{customer_id}/orgunits/{path}',
    'delete-ou': '/admin/directory/v1/customer/{customer_id}/orgunits/{org_path}',
    'delete-user': '/admin/directory/v1/users/{primary_email}',
    'delete-group': '/admin/directory/v1/groups/{group_email}',
    'add-member-to-group': '/admin/directory/v1/groups/{group_email}/members',
    'remove-member-from-group': '/admin/directory/v1/groups/{group_email}/members/{email_address}',
    'list-ou': '/admin/directory/v1/customer/{customer_id}/orgunits',
    'list-group-members': '/admin/directory/v1/groups/{group_email}/members',
    'list-users': '/admin/directory/v1/users'
}


# ============================= CLASSES ===================================== #

class GSuiteManager(object):

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None, refresh_token: Optional[str] = None,
                 service_account_creds_path: Optional[str] = None, delegated_email: Optional[str] = None, verify_ssl=False):
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.api_root = API_ROOT

        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token_param = refresh_token
        self.parser = GSuiteParser()

        self.service_account_auth = False

        if service_account_creds_path or delegated_email:
            self.auth_with_service_account(credentials_path_json=service_account_creds_path, delegated_email=delegated_email)
            self.service_account_auth = True
        else:
            if not (client_id and client_secret and refresh_token):
                raise GSuiteValidationException(
                    "Failed to authenticate with GSuite. 'Client ID', 'Client Secret' and 'Refresh Token' parameters must be provided")
            token_type, access_token = self.refresh_token(client_id, client_secret, refresh_token)
            self.session.headers = {
                "Authorization": "{} {}".format(token_type, access_token)
            }

    def auth_with_service_account(self, credentials_path_json: str, delegated_email: str) -> str:
        """
        Authenticate to GSuite with service account credentials
        :param credentials_path_json: {str} the path of the .json file of service account
        :param delegated_email: {str} user which is used to call API
        :return: raise Exception if failed to authenticate with GSuite using service account
        """
        try:
            if not (credentials_path_json and delegated_email):
                raise GSuiteValidationException(
                    "Failed to authenticate using service account. 'Service Account Json File Location' and 'Delegated Email' parameters must be provided")

            # Load GSuite service account json credentials
            try:
                credentials = json.loads(credentials_path_json)
            except Exception:
                credentials_file = open(credentials_path_json, 'r')
                credentials = json.load(credentials_file)
                credentials_file.close()

            credentials = service_account.Credentials.from_service_account_info(
                info=credentials,
                scopes=SCOPES
            ).with_subject(delegated_email)
            self.session = AuthorizedSession(credentials)

        except Exception as e:
            raise GSuiteManagerError(e)

    def _get_full_url(self, url_key, **kwargs) -> str:
        """
        Get full url from url key.
        :param url_id: {str} The key of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.api_root, ENDPOINTS[url_key].format(**kwargs))

    def test_connectivity(self):
        """
        Test connectivity with GSuite
        :return: raise Exception if failed to validate response
        """
        connectivity_err_msg = f"Unable to test connectivity with {INTEGRATION_NAME}"

        if self.service_account_auth:
            request_url = self._get_full_url('list-users')
            response = self.session.get(request_url, params={'maxResults': 1, 'customer': 'my_customer'})
            self.validate_response(response, error_msg=connectivity_err_msg)
        else:
            request_url = self._get_full_url('ping')
            data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "refresh_token",
                "refresh_token": self.refresh_token_param
            }
            response = self.session.post(request_url, data=data)
            self.validate_access_token_response(response, error_msg=connectivity_err_msg)

    def refresh_token(self, client_id: str, client_secret: str, refresh_token: str) -> Tuple[str, str]:
        """
        Refresh the access token
        :param client_id: {str} The client id to authenticate with
        :param client_secret: {str} The secret of the given client id
        :param refresh_token: {str} The current refresh token
        :return: {tuple} The token type and the new access token
        """
        request_url = self._get_full_url('refresh-token')
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token
        }
        response = self.session.post(request_url, data=data)
        self.validate_access_token_response(response, "Unable to refresh token")
        token = self.parser.build_token_obj(response.json())
        return token.token_type, token.access_token

    @staticmethod
    def obtain_access_token(client_id: str, client_secret: str, redirect_uri: str, code: str) -> datamodels.AccessToken:
        """
        Obtain an access token
        :param client_id: {str} The client id to authenticate with
        :param client_secret: {str} The secret of the given client id
        :param redirect_uri: {str} The redirect uri that matched the given client
        :param code: {str] The generated code from the authorizing step
        :return: {dict} The access token details
        """
        request_url = urljoin(API_ROOT, ENDPOINTS['obtain-access-token'])
        data = {
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }
        response = requests.post(request_url, data=data)
        GSuiteManager.validate_access_token_response(response, error_msg="Unable to obtain access token")
        return GSuiteParser.build_token_obj(response.json())

    def get_user(self, primary_email: str) -> datamodels.User:
        """
        Retrieves a user.
        :param primary_email: {str} Identifies the user in the API request. The value can be the user's primary email address,
        alias email address, or unique user ID.
        :return: {datamodels.User}
        """
        request_url = self._get_full_url('get-user', primary_email=primary_email)
        response = self.session.get(request_url)
        self.validate_response(response, error_msg=f"Failed to get user with email {primary_email}")
        return self.parser.build_user_obj(response.json())

    def create_user(self, given_name: str, family_name: str, password: str, primary_email: str,
                    change_password_at_next_login: Optional[bool] = False, phone: Optional[str] = None,
                    organization: Optional[str] = None, department=None, gender: Optional[str] = None,
                    note: Optional[str] = None) -> datamodels.User:
        """
        Create a new user
        :param given_name: {str} The user's first name. Required when creating
            a user account.
        :param family_name: {str} The user's last name. Required when creating
            a user account.
        :param password: {str} Stores the password for the user account.
            The user's password value is required when creating a user account.
            It is optional when updating a user and should only be provided if
            the user is updating their account password.
            A password can contain any combination of ASCII characters.
            A minimum of 8 characters is required. The maximum length is
            100 characters.
        :param primary_email: {str} The user's primary email address.
            This property is required in a request to create a user account.
            The primaryEmail must be unique and cannot be an alias of another
            user.
        :param phone: {str} User's phone number.
        :param organization: {str} Organization user belongs to.
        :param department: {str} Department user belongs to.
        :param change_password_at_next_login: {bool} Whether demand the user
            to change his password at next login
        :param gender: {str} The gender of the user. Insensitive capitalization. Valid values:
            - female
            - male
            - other
            - unknown
        :param note: {str} Note to add to the user.
        :return: {datamodels.User} user datamodel. Exception if failed to validate response
        """
        request_url = self._get_full_url('create-user')

        payload = {
            "name": {
                "familyName": family_name,
                "givenName": given_name
            },
            "password": crypt.crypt(password, crypt.METHOD_SHA256),
            "hashFunction": consts.SHA256_HASH_FUNCTION,
            "primaryEmail": primary_email,
            "notes": {
                "value": note
            } if note else {},
            "changePasswordAtNextLogin": change_password_at_next_login,
            "phones": [{
                "value": phone
            }] if phone else [],
            "gender": {
                "type": gender.lower()
            } if gender else {},
            "organizations": [{
                "name": organization if organization else "",
                "department": department if department else ""
            }] if organization or department else []
        }
        response = self.session.post(request_url, json=utils.remove_empty_kwargs(**payload))
        self.validate_response(response, f"Unable to create user with email {primary_email}")
        return self.parser.build_user_obj(response.json())

    def update_user(self, primary_email: str, given_name: Optional[str] = None, family_name: Optional[str] = None,
                    password: Optional[str] = None, change_password_at_next_login=False, phone: Optional[str] = None,
                    organization: Optional[str] = None, department: Optional[str] = None, gender=None,
                    suspended: bool = None) -> datamodels.User:
        """
        Update a user
        :param given_name: {str} The user's first name.
        :param family_name: {str} The user's last name.
        :param password: {str} Stores the password for the user account.
            The user's password value is required when creating a user account.
            It is optional when updating a user and should only be provided if
            the user is updating their account password.
            A password can contain any combination of ASCII characters.
            A minimum of 8 characters is required. The maximum length is
            100 characters.
        :param primary_email: {str} The user's primary email address.
            This property is required in a request to update a user account.
            The primaryEmail must be unique and cannot be an alias of another
            user.
        :param phone: {str} User's updated phone number.
        :param organization: {str} Updated organization the user belongs to.
        :param department: {str} Updated department the user belongs to.
        :param change_password_at_next_login: {bool} Whether demand the user
            to change his password at next login
        :param gender: {str} Gender of the user. Insensitive capitalization. Valid values are:
            - female
            - male
            - other
            - unknown
        :param suspended: {bool} Whether the user account suspended or not
        :return: {datamodels.User} User datamodel. Exception if failed to validate response
        """
        request_url = self._get_full_url('update-user', primary_email=primary_email)

        payload = {
            "name": {
                "familyName": family_name,
                "givenName": given_name
            } if family_name and given_name else {},
            "password": crypt.crypt(password, crypt.METHOD_SHA256) if password else None,
            "hashFunction": consts.SHA256_HASH_FUNCTION if password else None,
            "primaryEmail": primary_email,
            "changePasswordAtNextLogin": change_password_at_next_login,
            "phones": [{
                "value": phone
            }] if phone else [],
            "gender": {
                "type": gender.lower()
            } if gender else {}
        }

        if family_name:
            payload['name']['familyName'] = family_name
        if given_name:
            payload['name']['givenName'] = given_name
        if suspended is not None:
            payload['suspended'] = suspended

        organization_payload = {}
        if department:
            organization_payload['department'] = department
        if organization:
            organization_payload['name'] = organization

        if organization or department:
            payload['organizations'] = [organization_payload]

        response = self.session.put(request_url, json=utils.remove_empty_kwargs(**payload))
        self.validate_response(response, f"Unable to update user with email {primary_email}")
        return self.parser.build_user_obj(response.json())

    def delete_user(self, primary_email: str):
        """
        Delete a user
        :param primary_email: {str} The user's primary email address (unique)
        :return: raise GSuiteManagerError if failed to validate response
            raise GSuiteNotFoundException if user was not found
        """
        request_url = self._get_full_url('delete-user', primary_email=primary_email)
        res = self.session.delete(request_url)
        self.validate_response(res, f"Unable to delete user {primary_email}")

    def _map_query_params(self, param: Any):
        """
        Map query parameters
        :param param: {str} the param to map into the query
        :return: {str} mapped param
        """
        query_param_mapper = {
            'bool': utils.map_boolean_query_param,
            'str': utils.map_str_query_param
        }
        return query_param_mapper.get(type(param).__name__, lambda f: f)(param)

    def _query_builder(self, clauses_operator: Optional[str] = consts.AND, inclause_operator: Optional[str] = consts.EQUAL, **kwargs):
        """
        Returns query build for kwargs with an operator
        :param clauses_operator: {str} operator to join clauses (**kwargs)
        :param inclause_operator: {str} operator to join literals inside the each clause
        :param kwargs:  {dict} dictionary containing key values. Values must not be iterables unless it's a concrete string
        :return: {str} query built for provided parameters
        """
        return f"{clauses_operator}".join(f"{k}{inclause_operator}{self._map_query_params(v)}" for k, v in kwargs.items())

    def list_users(self, limit=None, customer_id: Optional[str] = None, domain: Optional[str] = None, order_by: Optional[str] = "givenName",
                   show_deleted: Optional[bool] = None, manager_email: Optional[str] = None, only_admin_accounts: Optional[bool] = None,
                   only_delegated_admin_accounts: Optional[bool] = None, only_suspended_users: Optional[bool] = None,
                   org_unit_path: Optional[str] = None, department: Optional[str] = None, custome_query: Optional[str] = None) -> [
        datamodels.User]:
        """
        List users in a domain
        :param limit: {int} Specify how many records can be returned by the action.
        :param customer_id: {str} The unique ID for the customer's Google Workspace account. In case of a multi-domain account,
            to fetch all groups for a customer, fill this field instead of domain.
            You can also use the my_customer alias to represent your account's customerId.
            The customerId is also returned as part of the Users resource.
            Either the customer or the domain parameter must be provided.
        :param manager_email: {str} The email address of a user's manager either directly or up the management chain.
        :param only_admin_accounts: {bool} True if to return only user admin accounts, otherwise False.
        :param only_delegated_admin_accounts: {bool} True if to return user accounts with delegated administrator privileges.
        :param only_suspended_users: {bool} True if to return user accounts that are suspended.
        :param org_unit_path: {str} The full path of an organization unit. All users in the organization will be returned.
        :param department: {str} The department to return users from.
        :param custome_query: {str} Custom query to add the list-users query call. Additional information can be found here - https://developers.google.com/admin-sdk/directory/v1/guides/search-users
        :param order_by: {str} Property to use for sorting results. Valid values:
            - email
            - familyName
            - givenName
        :param show_deleted: {bool} If set to true, retrieves the list of
            deleted users. Default is false.
        :param domain: {str} The domain name. Use this field to get fields from only one domain. To return all domains for a customer account,
            use the customer query parameter instead. Either the customer or the domain parameter must be provided.
            In case of a multi-domain account, to fetch all groups for a customer, don't fill the domain field.
            The my_customer alias will represent the account's customerId.
            The customerId is also returned as part of the Users resource. Either the customer or the domain parameter must be provided.
        :return: {[datamodels.User]} List of found users represented as User datamodels.
        """
        request_url = self._get_full_url('list-users')

        query = self._query_builder(clauses_operator=consts.SPACE, inclause_operator=consts.EQUAL, **utils.remove_empty_kwargs(
            manager=manager_email,
            isAdmin=only_admin_accounts,
            isDelegatedAdmin=only_delegated_admin_accounts,
            isSuspended=only_suspended_users,
            orgUnitPath=org_unit_path,
            orgDepartment=department,
        ))

        params = {
            "query": f"{query} {custome_query}" if custome_query else query,
            "orderBy": order_by,
            "projection": "full",
            "viewType": "admin_view",
            "showDeleted": show_deleted,
            'customer': customer_id if customer_id else "my_customer",
            'domain': domain if domain else None
        }

        raw_users_results = self._paginate_results(
            method="GET",
            url=request_url,
            results_key="users",
            params=utils.remove_empty_kwargs(**params),
            limit=limit,
            error_msg="Unable to paginate list users results"
        )

        return [self.parser.build_user_obj(raw_user) for raw_user in raw_users_results]

    def list_group_members(self, group_email_address: str,
                           include_derived_membership=True) -> [datamodels.Member]:
        """
        List members of a group
        :param group_email_address: {str} The email address of the group
        :param include_derived_membership: {bool} Whether to list indirect
            memberships.
        :return: {[datamodels.Member]} List of found members in a group
        """
        request_url = self._get_full_url('list-group-members', group_email=group_email_address)
        params = {
            "includeDerivedMembership": include_derived_membership
        }
        raw_member_results = self._paginate_results(
            method="GET",
            url=request_url,
            results_key="members",
            params=params,
            error_msg=f"Unable to list members of group {group_email_address}"
        )
        return [self.parser.build_member_obj(raw_member) for raw_member in raw_member_results]

    def add_member_to_group(self, group_email_address: str, primary_email_address: str) -> datamodels.Member:
        """
        Add a member to given group
        :param group_email_address: {str} The email of the group
        :param primary_email_address: {str} The email of the member to add to
            the group
        :return: {datamodels.Member} added member datamodel.
            raise GSuiteEntityExistsException if member already exists
            raise GSuiteManagerError if failed to validate status code
        """
        request_url = self._get_full_url('add-member-to-group', group_email=group_email_address)
        payload = {
            "email": primary_email_address
        }
        response = self.session.post(request_url, json=payload)
        self.validate_response(response, f"Unable to add {primary_email_address} to group {group_email_address}")
        return self.parser.build_member_obj(response.json())

    def remove_member_from_group(self, group_email_address: str, primary_email_address: str):
        """
        Remove a member from a given group
        :param group_email_address: {str} The email of the group
        :param primary_email_address: {str} The email of the member to remove
            from the group
        :return: raise GSuiteNotFoundException if member already exists
            raise GSuiteManagerError if failed to validate status code
            raise GSuiteNotFoundException / GSuiteValidateException if group or user was not found
        """
        request_url = self._get_full_url('remove-member-from-group', group_email=group_email_address, email_address=primary_email_address)
        response = self.session.delete(request_url)
        self.validate_response(response, f"Unable to remove {primary_email_address} from group {group_email_address}")

    def create_group(self, email: str, description: Optional[str] = None, name: Optional[str] = None) -> datamodels.Group:
        """
        Create a new group
        :param email: {str} The group's email address. Must be unique.
        :param description: {str} An extended description to help users
            determine the purpose of a group.
        :param name: {str} The group's display name.
        :return: {datamodels.Group} created group datamodel. Exception if failed to validate response
        """
        request_url = self._get_full_url('create-group')
        payload = {
            "email": email,
            "description": description,
            "name": name
        }
        response = self.session.post(request_url, json=utils.remove_empty_kwargs(**payload))
        self.validate_response(response, f"Unable to create group with email {email}")
        return self.parser.build_group_obj(response.json())

    def create_ou(self, name: Optional[str] = None, description: Optional[str] = None, parent_path: Optional[str] = None,
                  customer_id="my_customer") -> datamodels.OrgUnit:
        """
        Create an organizational unit
        :param name: {str} The name of the new OU
        :param description: {str} The description of the OU
        :param parent_path: {str} The organizational unit's parent path.
            For example, /corp/sales is the parent path for
            /corp/sales/sales_support organizational unit.
        :param customer_id: {str} The unique ID for the customer's G Suite
            account. As an account administrator, you can also use the
            my_customer alias to represent your account's customerId.
        :return: {datamodels.OrgUnit} created organization unit datamodel. Exception if failed to validate response
        """
        request_url = self._get_full_url('create-ou', customer_id=customer_id)

        payload = {
            "name": name,
            "description": description,
            "parentOrgUnitPath": parent_path
        }

        response = self.session.post(request_url, json=utils.remove_empty_kwargs(**payload))
        self.validate_response(response, f"Unable to create OU for customer id {customer_id}")
        return self.parser.build_ou_obj(response.json())

    def update_ou(self, customer_id: str, path: str, name: Optional[str] = None, description: Optional[str] = None) -> datamodels.OrgUnit:
        """
        Update an organizational unit
        :param path: {str} The full path to the organizational unit.
        :param customer_id: {str} The unique ID for the customer's G Suite
            account. As an account administrator, you can also use the
            my_customer alias to represent your account's customerId.
        :param name: {str} The name of the new OU
        :param description: {str} The description of the OU
        :return: {datamodels.OrgUnit} updated organization unit datamodel. Exception if failed to validate response
        """
        request_url = self._get_full_url('update-ou', customer_id=customer_id, path=path)
        payload = {
            "name": name,
            "description": description,
        }
        response = self.session.put(request_url, json=utils.remove_empty_kwargs(**payload))
        self.validate_response(response, f"Unable to update OU for customer id {customer_id}")
        return self.parser.build_ou_obj(response.json())

    def list_ou(self, customer_id: str) -> [datamodels.OrgUnit]:
        """
        Retrieves a list of all organizational units for an account.
        :param customer_id: {str} The unique ID for the customer's Google Workspace account. As an account administrator,
            you can also use the my_customer alias to represent your account's customerId.
        :return: {[datamodels.OrgUnit]} list of organization units datamodels. Exception if failed to validate response
        """
        request_url = self._get_full_url('list-ou', customer_id=customer_id)
        response = self.session.get(request_url)
        self.validate_response(response, f"Unable to list OU for customer {customer_id}")
        return self.parser.build_org_units_objs(response.json())

    def delete_ou(self, customer_id: str, path: str):
        """
        Delete an OU (Organization Unit) in GSuite
        :param path: {str} The full path to the organizational unit.
        :param customer_id: {str} The unique ID for the customer's G Suite
            account. As an account administrator, you can also use the
            my_customer alias to represent your account's customerId.
        :return: raise Exception if failed to validate response.
        """
        request_url = self._get_full_url('delete-ou', customer_id=customer_id, org_path=path)
        response = self.session.delete(request_url)
        self.validate_response(response, f"Unable to delete OU for customer id {customer_id} with organization path {path}")

    def delete_group(self, group_email_address: str):
        """
        Delete a Group in GSuite
        :param customer_id: {str} The unique ID for the customer's G Suite
            account. As an account administrator, you can also use the
            my_customer alias to represent your account's customerId.
        :param group_email_address: {str} the unique email address of the group to be deleted
        :return:
            raise GSuiteNotFoundException exception if entity was not found in GSuite
            raise GSuiteValidationException exception if failed to validate request
        """
        request_url = self._get_full_url('delete-group', group_email=group_email_address)
        response = self.session.delete(request_url)
        self.validate_response(response, error_msg=f"Failed to delete group {group_email_address}")

    def _paginate_results(self, method, url: str, results_key: str, params=None, body=None, limit=None,
                          error_msg="Unable to paginate results"):
        """
        Paginate results
        :param method: {str} The method of the request (GET, POST, PUT, DELETE, PATCH)
        :param url: {str} The request url to send request to
        :param params: {dict} The params of the request
        :param results_key: {str} The name of the key where the results are
        :param limit: {int} Max number of results to fetch
        :param error_msg: {str} Error message to display on failure
        :return: {list} List of found results
        """
        if limit is not None:
            params.update({'maxResults': limit})

        response = self.session.request(method=method, url=url, params=params, json=body)
        self.validate_response(response, error_msg)
        results = response.json().get(results_key, [])

        while response.json().get("nextPageToken"):
            if limit and len(results) >= limit:
                break
            params.update({
                'pageToken': response.json()["nextPageToken"]
            })
            response = self.session.request(method=method, url=url, params=params, json=body)
            self.validate_response(response, error_msg)
            results.extend(response.json().get(results_key, []))

        return results[:limit] if limit else results

    @staticmethod
    def validate_access_token_response(response, error_msg="An error occurred"):
        """
        Validate the access token response
        :param response: {requests.Response} The response
        :param error_msg: {str} The error message to display on failure
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            try:
                response.json()
            except:
                # Not a JSON - return content
                raise GSuiteManagerError(
                    "{error_msg}: {error} - {text}".format(
                        error_msg=error_msg,
                        error=error,
                        text=error.response.content)
                )

            raise GSuiteManagerError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=response.json().get('error'),
                    text=response.json().get('error_description'))
            )

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        """
        Validate GSuite response
        :param response: {json/html} response from GSuite api
        :param error_msg: {str} error message to display
        :return:
            raise GSuiteManagerError exception if failed to validate response's status code
            raise GSuiteEntityExistsException exception if entity already exists in GSuite
            raise GSuiteNotFoundException exception if entity was not found in GSuite
            raise GSuiteValidationException exception if failed to validate request
        """
        try:
            if response.status_code == consts.API_CONFLICT_STATUS_CODE:
                raise GSuiteEntityExistsException(
                    "{error_msg}: {error}".format(
                        error_msg=error_msg,
                        error=response.json().get("error", {}).get("message"))
                )
            if response.status_code == consts.API_NOT_FOUND_STATUS_CODE:
                raise GSuiteNotFoundException(
                    "{error_msg}: {error}".format(
                        error_msg=error_msg,
                        error=response.json().get("error", {}).get("message"))
                )
            if response.status_code == consts.API_BAD_REQUEST_STATUS_CODE:
                raise GSuiteValidationException(
                    "{error_msg}: {error}".format(
                        error_msg=error_msg,
                        error=response.json().get("error", {}).get("message"))
                )
            response.raise_for_status()
        except requests.HTTPError as error:
            try:
                response.json()
            except:
                # Not a JSON - return content
                raise GSuiteManagerError(
                    "{error_msg}: {error}".format(
                        error_msg=error_msg,
                        error=error.response.content)
                )
            raise GSuiteManagerError(
                "{error_msg}: {error}".format(
                    error_msg=error_msg,
                    error=response.json().get("error", {}).get("message"))
            )
