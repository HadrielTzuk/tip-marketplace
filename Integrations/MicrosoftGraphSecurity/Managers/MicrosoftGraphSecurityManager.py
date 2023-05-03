# README: Prerequisites

# Doc: follow the steps in https://docs.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0

# Get access without a user
# 1. Register your app: To authenticate with the Azure v2.0 endpoint,
# you must first register your app at Microsoft App Registration Portal (https://apps.dev.microsoft.com)
# You can use either a Microsoft account or a work or school account to register your app.
# Copy the following values: The Application ID, An Application Secret and a password
# Configure permissions for Microsoft Graph on your app, in the Microsoft App Registration Portal:
# choose Add next to Application Permissions and select: SecurityEvents.Read.All, SecurityEvents.ReadWrite.All
# 2. Get administrator consent

# Useful links:
# Microsoft API - https://docs.microsoft.com/en-us/graph/api/alert-get?view=graph-rest-1.0
# App registration - https://apps.dev.microsoft.com
# Azure portal - https://portal.azure.com/

# ==============================================================================
# title          :MicrosoftGraphSecurityManager.py
# description    :This Module contain all Microsoft teams operations functionality
# author         :zivh@siemplify.co
# date           :11-12-18
# python_version :2.7
# product_version: V1
# Doc            :https://developer.microsoft.com/en-us/graph/docs/concepts/auth_v2_service
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from copy import deepcopy
from datetime import datetime
import requests
import base64
import time
import uuid
import jwt
from OpenSSL import crypto

from MicrosoftGraphSecurityParser import MicrosoftGraphSecurityParser
from exceptions import MicrosoftGraphSecurityFileNotFound
from TIPCommon import filter_old_alerts


# =====================================
#             CONSTANTS               #
# =====================================

ALERT_ID_FIELD = "id"

# Access consts
TOKEN_PAYLOAD = {
    "client_id": None,
    "scope": "https://graph.microsoft.com/.default",
    "client_secret": None,
    "grant_type": "client_credentials"
}

HEADERS = {"Content-Type": "application/json"}
UPDATE_ALERT_HEADER = {"Prefer": "return=representation"}
UPDATE_ALERT_KEY = "Prefer"
INVALID_REFRESH_TOKEN_ERROR = 'Refresh Token is malformed or invalid'

GRANT_TYPE = "client_credentials"
SCOPE = "https://graph.microsoft.com/.default"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# urls
URL_AUTHORIZATION = "https://login.microsoftonline.com/{tenant}/adminconsent?client_id={client_id}&redirect_uri={redirect_uri}"
ACCESS_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
GET_ALERT_URL = "https://graph.microsoft.com/v1.0/security/alerts"
GET_USERS_URL = "https://graph.microsoft.com/v1.0/users"
KILL_USER_URL = "https://graph.microsoft.com/v1.0/users/{}/revokeSignInSessions"

FEEDBACK_VALUES = ["unknown", "truePositive", "falsePositive", "benignPositive"]
STATUS_VALUES = ["unknown", "newAlert", "inProgress", "resolved"]
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


# =====================================
#              CLASSES                #
# =====================================


class MicrosoftGraphSecurityManagerError(Exception):
    """
    General Exception for microsoft graph security manager
    """
    pass


class MicrosoftGraphSecurityManager(object):
    def __init__(self, client_id: str, client_secret: str, certificate_path: str, certificate_password: str,
                 tenant: str, verify_ssl: bool = False, siemplify=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.certificate_path = certificate_path
        self.certificate_password = certificate_password
        self.tenant = tenant
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.access_token: str = self.generate_token(
            self.client_id, self.client_secret, self.certificate_path, self.certificate_password, self.tenant
        )
        self.session.headers.update({"Authorization": "Bearer {0}".format(self.access_token)})
        self.parser = MicrosoftGraphSecurityParser()
        self.siemplify = siemplify

    def generate_token(self, client_id: str, client_secret: str, certificate_path: str, certificate_password: str, tenant: str) -> str:
        """
        Request access token
        :param client_id: {string} The Application ID that the registration portal
        :param client_secret: {string} The application secret that you created in the app registration portal for your app.
        :param certificate_path: {string} If authentication based on certificates is used instead of client secret, specify path to the certificate on Siemplify server..
        :param certificate_password: {string} If certificate is password-protected, specify the password to open the certificate file.
        :param tenant: {string} domain name from azure portal
        :return: {string} Access token. The app can use this token in calls to Microsoft Graph.
        """
        if client_secret:
            return self.generate_token_by_client_secret(client_id, client_secret, tenant)

        return self.generate_token_by_certificate(client_id, certificate_path, certificate_password, tenant)

    @staticmethod
    def generate_token_by_client_secret(client_id: str, client_secret: str, tenant: str) -> str:
        """
        Request access token by client secret (Valid for 60 min)
        :param client_id: {string} The Application ID that the registration portal
        :param client_secret: {string} The application secret that you created in the app registration portal for your app
        :param tenant: {string} domain name from azure portal
        :return: {string} Access token. The app can use this token in calls to Microsoft Graph
        """
        payload = deepcopy(TOKEN_PAYLOAD)
        payload["client_id"] = client_id
        payload["client_secret"] = client_secret
        res = requests.post(ACCESS_TOKEN_URL.format(tenant=tenant), data=payload)
        MicrosoftGraphSecurityManager.validate_response(res)
        return res.json().get('access_token')

    def generate_token_by_certificate(self, client_id, certificate_path, certificate_password, tenant):
        """
        Request access token by certificate (Valid for 60 min)
        :param client_id: {string} The Application ID that the registration portal
        :param certificate_path: {string} If authentication based on certificates is used instead of client secret, specify path to the certificate on Siemplify server
        :param certificate_password: {string} If certificate is password-protected, specify the password to open the certificate file
        :param tenant: {string} domain name from azure portal
        :return: {string} Access token. The app can use this token in calls to Microsoft Graph
        """
        thumbprint, private_key = self.get_certificate_thumbprint_and_private_key(certificate_path, certificate_password)
        jwt_token = self.get_jwt_token(client_id, tenant, thumbprint, private_key)

        params = {
            "grant_type": GRANT_TYPE,
            "scope": SCOPE,
            "client_id": client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": jwt_token
        }

        response = requests.post(ACCESS_TOKEN_URL.format(tenant=tenant), data=params)
        MicrosoftGraphSecurityManager.validate_response(response)
        return response.json().get('access_token')

    def get_certificate_thumbprint_and_private_key(self, certificate_path, certificate_password):
        """
        Get thumbprint and private key from certificate
        :param certificate_path: {string} If authentication based on certificates is used instead of client secret, specify path to the certificate on Siemplify server
        :param certificate_password: {string} If certificate is password-protected, specify the password to open the certificate file
        :return: {tuple} The certificate thumbprint and private key
        """
        try:
            with open(certificate_path, "rb") as pfx:
                certificate = crypto.load_pkcs12(pfx.read(), certificate_password)
                private_key_object = certificate.get_privatekey()
                x509_certificate = certificate.get_certificate()
                thumbprint_bytes = x509_certificate.digest("sha1")
                # Remove colons from thumbprint
                thumbprint = thumbprint_bytes.decode('utf-8').replace(':', '')
                private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key_object)

                return thumbprint, private_key
        except Exception:
            raise MicrosoftGraphSecurityFileNotFound("Unable to read certificate file")


    def get_jwt_token(self, client_id, tenant, thumbprint, private_key):
        """
        Get JWT token
        :param client_id: {string} The Application ID that the registration portal
        :param tenant: {string} domain name from azure portal
        :param thumbprint: {string} The certificate thumbprint
        :param private_key: The certificate private key
        :return: {bytes} The JWT token
        """
        # Encode hex to Base64
        encoded_thumbprint = base64.b64encode(bytes.fromhex(thumbprint)).decode('utf-8')
        # Perform base64url-encoding as per RFC7515 Appendix C
        x5t = encoded_thumbprint.replace("=", '').replace("+", '-').replace("/", '_')
        current_timestamp = int(time.time())

        payload = {
            "aud": ACCESS_TOKEN_URL.format(tenant=tenant),
            "exp": current_timestamp + 3600,
            "iss": client_id,
            "jti": str(uuid.uuid1()),
            "nbf": current_timestamp,
            "sub": client_id
        }

        jwt_token = jwt.encode(payload, private_key, algorithm='RS256', headers={'x5t': x5t})
        return jwt_token.decode('utf-8')

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        """
        Validate response
        :param response: {requests.Response} The response to validate
        :param error_msg: {unicode} Default message to display on error
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise MicrosoftGraphSecurityManagerError(
                f"{error_msg}: {error} {response.content}"
            )

    def get_alert_details(self, alert_id: str) -> dict:
        """
        Retrieve the properties and relationships of an alert object.
        :param alert_id: {string} alert id
        :return: {Alert} The alert
        """
        # There can be few alerts with the same title, therefore the search is by id
        response = self.session.get(f'{GET_ALERT_URL}/{alert_id}')
        self.validate_response(response, f"Unable to get alert {alert_id}")
        return self.parser.build_siemplify_alert_obj(response.json())

    @staticmethod
    def _build_api_parameters(provider_list: list = None, severity_list: list = None, status_list: list = None,
                              start_time: datetime = None,
                              asc: bool = True, filter_dict: dict = None) -> dict:
        """
        Build the parameters dict for API call
        :param provider_list: {list} List of provider names to filter with
        :param severity_list: {list} List of severities to filter with
        :param status_list: {list} List of statuses to filter with
        :param start_time: {str} Start time to filter with
        :param asc: {bool} Whether to return the results ascending or descending
        :param filter_dict: {dict} The filter params {key: , logic: , value: ,}
        :return: {dict} The params dict
        """
        filter_params = []

        if provider_list:
            provider_filter_group = " or ".join(map(lambda x: f"(vendorInformation/provider eq '{x}')", provider_list))
            filter_params.append("({})".format(provider_filter_group))

        if severity_list:
            severity_filter_group = " or ".join(map(lambda x: f"(severity eq '{x}')", severity_list))
            filter_params.append("({})".format(severity_filter_group))

        if status_list:
            status_filter_group = " or ".join(map(lambda x: f"(status eq '{x}')", status_list))
            filter_params.append("({})".format(status_filter_group))

        if start_time:
            filter_params.append(f"createdDateTime ge {start_time.strftime(TIME_FORMAT)}")

        if filter_dict is not None:
            if filter_dict['logic'] == 'Equal':
                filter_params.append(f"{filter_dict['key']} eq '{filter_dict['value']}'")
            elif filter_dict['logic'] == 'Contains':
                filter_params.append(f"contains({filter_dict['key']}, '{filter_dict['value']}')")

        # Apply filtering in oData format
        params = {
            u"$filter": " and ".join(filter_params) if filter_params else None,
            u"$orderby": f"createdDateTime {'asc' if asc else 'desc'}"
        }

        return params

    def update_alert(self, alert_id: str, assigned_to: str = None, closed_date_time: datetime = None,
                     comments: list = None, feedback: str = None, status: str = None,
                     tags: list = None):
        """
        Update an editable alert property within any integrated solution to keep alert status and assignments in sync across solutions.
        :param alert_id: {string} alert id
        :param assigned_to: {string} Name of the analyst the alert is assigned to for triage, investigation, or remediation.
        :param closed_date_time: {DateTime} Time at which the alert was closed. using iso format, always in UTC time. ex.'2014-01-01T00:00:00Z'
        :param comments: {list} Analyst comments on the alert
        :param feedback: {string} Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive.
        :param status: {string} Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved.
        :param tags: {list} User-definable labels that can be applied to an alert and can serve as filter conditions (for example, "HVA", "SAW).
        :return: {Alert} The updated alert
        """
        # In the request body, supply a JSON representation of the values for relevant fields that should be updated.
        # The body must contain the vendorInformation property with valid provider and vendor fields.
        # For best performance, don't include existing values that haven't changed.
        # Check which fields the user want to update.
        alert_updated_json = {}

        if assigned_to:
            alert_updated_json["assignedTo"] = assigned_to
        if closed_date_time:
            alert_updated_json["closedDateTime"] = closed_date_time
        if comments:
            alert_updated_json["comments"] = comments
        if feedback:
            if feedback in FEEDBACK_VALUES:
                alert_updated_json["feedback"] = feedback
        if status:
            if status in STATUS_VALUES:
                alert_updated_json["status"] = status
        if tags:
            alert_updated_json["tags"] = tags

        # The body must contain the vendorInformation property with valid provider and vendor fields.
        # Get this details from the alert
        alert_details = self.get_alert_details(alert_id)
        alert_updated_json["vendorInformation"] = alert_details.vendorInformation

        update_alert_headers = deepcopy(self.session.headers)
        update_alert_headers.update(UPDATE_ALERT_HEADER)
        response = self.session.patch(f'{GET_ALERT_URL}/{alert_id}', json=alert_updated_json,
                                      headers=update_alert_headers)

        self.validate_response(response)
        return self.parser.build_siemplify_alert_obj(response.json())

    def list_alerts(self, provider_list=None, severity_list=None, status_list=None, start_time=None, max_alerts=None,
                    asc=True, existing_ids=None, filter_dict=None):
        """
        Retrieve a list of alert objects.
        :param provider_list: {list} List of provider names to filter with
        :param severity_list: {list} List of severities to filter with
        :param status_list: {list} List of statuses to filter with
        :param start_time: {str} Start time to filter with
        :param max_alerts: {int} Max amount of alerts to return
        :param asc: {bool} Whether to return the results ascending or descending
        :param existing_ids: {list} The list of existing ids
        :param filter_dict: {dict} The filter params {key: , logic: , value: ,}
        :return: {[Alert]} List of found alerts
        """
        if existing_ids is None:
            existing_ids = []

        api_parameters = self._build_api_parameters(provider_list, severity_list, status_list,
                                                    start_time, asc, filter_dict)

        response = self.session.get(GET_ALERT_URL, params=api_parameters)
        self.validate_response(response)
        raw_alerts = response.json().get('value', [])
        alerts = [self.parser.build_siemplify_alert_obj(alert) for alert in raw_alerts]

        while response.json().get('@odata.nextLink'):
            if max_alerts and len(raw_alerts) >= max_alerts:
                break

            response = self.session.get(response.json().get('@odata.nextLink'))
            self.validate_response(response)
            raw_alerts.extend(response.json().get('value', []))
            alerts.extend([self.parser.build_siemplify_alert_obj(alert) for alert in response.json().get('value', [])])

        filtered_alerts = filter_old_alerts(
            siemplify=self.siemplify,
            alerts=alerts,
            existing_ids=existing_ids,
            id_key=ALERT_ID_FIELD
        )
        return filtered_alerts[:max_alerts] if max_alerts else filtered_alerts

    def list_users(self):
        """
        Retrieve a list of users objects.
        :return: {list} of alerts {dicts}
        """
        res = self.session.get(GET_USERS_URL)
        self.validate_response(res)
        return res.json().get('value', [])

    def kill_user_session(self, user_id):
        """
        Kill a user session by the userPrincipalName or the user id
        :param user_id: {str} The identifier of the user to kill
        :return: {bool} True if successful, exception otherwise
        """
        res = self.session.post(KILL_USER_URL.format(user_id))
        self.validate_response(res)
        return True
