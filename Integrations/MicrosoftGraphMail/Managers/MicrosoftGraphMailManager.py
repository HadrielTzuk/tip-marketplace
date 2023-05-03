# README: Prerequisites

# Doc: follow the steps in https://docs.microsoft.com/en-us/graph/auth-v2-service?view=graph-rest-1.0

# Get access without a user
# 1. Register your app: To authenticate with the Azure v2.0 endpoint,
# you must first register your app at Microsoft App Registration Portal (https://apps.dev.microsoft.com)
# You can use either a Microsoft account or a work or school account to register your app.
# Copy the following values: The Application ID, An Application Secret and a password
# Configure permissions for Microsoft Graph Mail on your app, in the Microsoft App Registration Portal
# 2. Get administrator consent

# Useful links:
# Microsoft API - https://docs.microsoft.com/en-us/graph/api/alert-get?view=graph-rest-1.0
# App registration - https://apps.dev.microsoft.com
# Azure portal - https://portal.azure.com/

# ==============================================================================
# title          :MicrosoftGraphMailManager.py
# description    :This Module contain all Microsoft Graph Mail operations functionality
# date           :14-09-22
# python_version :3.8
# product_version: V1
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
from copy import deepcopy
import requests

from exceptions import MicrosoftGraphMailManagerError
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional
from EmailUtils import filter_emails_with_regexes
from MicrosoftGraphMailParser import MicrosoftGraphMailParser
from datamodels import MicrosoftGraphEmail
from TIPCommon import is_approaching_timeout, TIMEOUT_THRESHOLD


# =====================================
#             CONSTANTS               #
# =====================================

HEADERS = {"Content-Type": "application/json"}
GRANT_TYPE = "client_credentials"
SCOPE = "https://graph.microsoft.com/.default"

# Access consts
TOKEN_PAYLOAD_FROM_SECRET = {
    "grant_type": GRANT_TYPE,
    "client_id": "",
    "scope": SCOPE,
    "client_secret": ""
}

# urls
ACCESS_TOKEN_URL = "{base_uri}/{tenant}/oauth2/v2.0/token"
BATCH_REQUEST = "{base_uri}/v1.0/$batch"
RELATIVE_EMAIL_DETAILS = "/{tenant}/users/{mail_address}/mailFolders/{folder_id}/messages/{email_id}"
GET_FOLDERS = "{base_uri}/v1.0/{tenant}/users/{mail_address}/mailFolders"
GET_EMAILS = (
    GET_FOLDERS +
    "/{folder_id}/messages"
)
GET_ATTACHMENTS = (
    GET_EMAILS +
    "/{email_id}/attachments"
)
GET_ATTACHMENTS_CONTENT = (
    GET_ATTACHMENTS +
    "/{attachment_id}/$value"
)

PER_REQUEST_ENTITIES_LIMIT = 10
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# =====================================
#              CLASSES                #
# =====================================


@dataclass
class OdataQueryParameters:
    filter_: str = None
    select_: Optional[List[str]] = None
    order_by_: Optional[str] = None
    top_: Optional[int] = PER_REQUEST_ENTITIES_LIMIT

    def build_query_dict(self):
        query_dict = {
            "$top": str(self.top_),
            "$select": ",".join(self.select_) if self.select_ else "*",
        }
        if self.filter_ is not None:
            query_dict["$filter"] = self.filter_
        if self.order_by_ is not None:
            query_dict["$order_by"] = self.order_by_
        return query_dict


class MicrosoftGraphMailManager(object):
    def __init__(self, client_id: str, client_secret: str, tenant: str,
                 azure_ad_endpoint: str, microsoft_graph_endpoint: str,
                 verify_ssl: bool = True, siemplify=None,
                 mail_address: str = ""):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant = tenant
        self.azure_ad_endpoint = azure_ad_endpoint
        self.microsoft_graph_endpoint = microsoft_graph_endpoint
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.access_token: str = self.generate_token(
            self.client_id, self.client_secret, self.tenant
        )
        self.mail_address = mail_address
        self.session.headers.update({"Authorization": "Bearer {0}".format(self.access_token)})
        self.parser = MicrosoftGraphMailParser()
        self.siemplify = siemplify

    def generate_token(self, client_id: str, client_secret: str, tenant: str) -> str:
        """
        Request access token by client secret (Valid for 60 min)
        :param client_id: {string} The Application ID that the registration portal
        :param client_secret: {string} The application secret that you created in the app registration portal for your app
        :param tenant: {string} domain name from azure portal
        :return: {string} Access token. The app can use this token in calls to Microsoft Graph
        """
        payload = deepcopy(TOKEN_PAYLOAD_FROM_SECRET)
        payload["client_id"] = client_id
        payload["client_secret"] = client_secret
        res = self.session.post(
            ACCESS_TOKEN_URL.format(base_uri=self.azure_ad_endpoint, tenant=tenant),
            data=payload
        )
        self.validate_response(res)
        return res.json().get('access_token')

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
            raise MicrosoftGraphMailManagerError(
                f"{error_msg}: {error} {response.content}"
            )

    def get_folder_by_name(self, folder_name: str):
        get_folders_link = GET_FOLDERS.format(base_uri=self.microsoft_graph_endpoint,
                                              tenant=self.tenant,
                                              mail_address=self.mail_address)
        query_params = OdataQueryParameters(
            filter_=f"displayName eq '{folder_name}'",
            select_=["id", "displayName"]
        )

        response = self.session.get(url=get_folders_link, params=query_params.build_query_dict())
        self.validate_response(response)
        results = response.json()["value"]
        if results:
            return self.parser.build_mg_folder(results[0])
        raise MicrosoftGraphMailManagerError(f"Mail folder {folder_name} does not exist")

    def parse_emails(self, raw_json, folder_name: str):
        new_emails = self.parser.build_mg_mail_objs(raw_json["value"],
                                                    mailbox_name=self.mail_address,
                                                    folder_name=folder_name)
        next_link = raw_json.get("@odata.nextLink")
        return new_emails, next_link

    def get_emails_by_folder(self, folder, datetime_from: datetime, max_email_per_cycle: int,
                             existing_ids: List[str], unread_only: bool = False, email_exclude_pattern: str = None):
        get_emails_link = GET_EMAILS.format(base_uri=self.microsoft_graph_endpoint,
                                            tenant=self.tenant,
                                            mail_address=self.mail_address,
                                            folder_id=folder.id)
        filter_string = f"receivedDateTime ge {datetime_from.strftime(TIME_FORMAT)}"
        if unread_only:
            filter_string += f" and isRead eq false"
        query_params = OdataQueryParameters(
            filter_=filter_string,
            top_=max_email_per_cycle if max_email_per_cycle < PER_REQUEST_ENTITIES_LIMIT else PER_REQUEST_ENTITIES_LIMIT
        )
        response = self.session.get(url=get_emails_link, params=query_params.build_query_dict())
        self.validate_response(response)
        new_emails, next_link = self.parse_emails(response.json(), folder.display_name)
        new_emails, excluded = filter_emails_with_regexes(new_emails, email_exclude_pattern)
        fetched_emails = [email for email in new_emails if email.id not in existing_ids]

        self.siemplify.LOGGER.info(f"Fetched {len(fetched_emails)} new emails out of {max_email_per_cycle}")

        while len(fetched_emails) < max_email_per_cycle:
            if next_link is None:
                break

            response = self.session.get(url=next_link)
            self.validate_response(response)
            new_emails, next_link = self.parse_emails(response.json(), folder.display_name)
            new_emails, _excluded = filter_emails_with_regexes(new_emails, email_exclude_pattern)
            excluded.extend(_excluded)
            fetched_emails.extend(email for email in new_emails if email.id not in existing_ids)

            self.siemplify.LOGGER.info(f"Fetched {len(fetched_emails)} new emails out of {max_email_per_cycle}")

        log_excluded = (
            "Excluded the following emails based on the provided Email exclude pattern:\n" +
            "\n".join(f"{email.id} {email.subject}" for email in excluded)
        )
        self.siemplify.LOGGER.info(log_excluded)

        return fetched_emails[:max_email_per_cycle]

    def load_attachments_for_email(self, folder_id: str, email_id: str):
        get_attachments_link = GET_ATTACHMENTS.format(
            base_uri=self.microsoft_graph_endpoint,
            tenant=self.tenant,
            mail_address=self.mail_address,
            folder_id=folder_id,
            email_id=email_id
        )
        query_params = OdataQueryParameters(
            select_=["id", "size", "contentType", "name"]
        ).build_query_dict()

        response = self.session.get(get_attachments_link, params=query_params)
        self.validate_response(response)
        return self.parser.build_mg_file_attachments(response.json()["value"])

    def load_attachment_content(self, folder_id: str, email_id: str, attachment_id: str):
        get_attachments_content_link = GET_ATTACHMENTS_CONTENT.format(
            base_uri=self.microsoft_graph_endpoint,
            tenant=self.tenant,
            mail_address=self.mail_address,
            folder_id=folder_id,
            email_id=email_id,
            attachment_id=attachment_id
        )
        response = self.session.get(get_attachments_content_link)
        self.validate_response(response)
        return response.content

    def get_emails(self, folder_name: str, datetime_from: datetime, max_email_per_cycle: int,
                   existing_ids: List[str], unread_only: bool = False, email_exclude_pattern: str = None,
                   connector_starting_time: int = None, script_timeout: int = None):
        folder = self.get_folder_by_name(folder_name)
        emails = self.get_emails_by_folder(
            folder=folder,
            datetime_from=datetime_from,
            max_email_per_cycle=max_email_per_cycle,
            existing_ids=existing_ids,
            unread_only=unread_only,
            email_exclude_pattern=email_exclude_pattern,
        )
        processed_emails = []
        for email in emails:
            # In case we stuck on fetching loads of emails with their attachments.
            # We can save at least 10% of time before timeout break to process some of them
            timeout_approaching = (
                script_timeout and connector_starting_time
                and is_approaching_timeout(
                    connector_starting_time=connector_starting_time,
                    python_process_timeout=script_timeout,
                    timeout_threshold=TIMEOUT_THRESHOLD - 0.1
                )
            )
            if timeout_approaching:
                self.siemplify.LOGGER.info('Timeout is approaching. Connector will gracefully exit')
                break

            if not email.has_attachments:
                processed_emails.append(email)
                continue

            self.siemplify.LOGGER.info(f"Loading attachments for email {email.id}")
            attachments = self.load_attachments_for_email(
                folder_id=folder.id,
                email_id=email.id
            )
            for attachment in attachments:
                if attachment.is_to_large:
                    self.siemplify.LOGGER.info(
                        f"Attachment {attachment.id} is to large and it's content wouldn't be loaded")
                    continue
                # Not exactly sure what should we do with other attachments
                # Reference Attachment f.ex. doesn't have any links or proper data to build proper
                # event or attachment on later stages
                can_load_content = attachment.is_file_attachment or attachment.is_item_attachment
                if can_load_content:
                    attachment.set_content(
                        self.load_attachment_content(
                            folder_id=folder.id,
                            email_id=email.id,
                            attachment_id=attachment.id
                        )
                    )
            email.set_attachments(attachments)
            processed_emails.append(email)

        return processed_emails

    def mark_emails_as_read(self, emails: List[MicrosoftGraphEmail]):
        if not emails:
            return
        requests_json = []
        for index, email in enumerate(emails):
            requests_json.append({
                "id": index,
                "method": "PATCH",
                "url": RELATIVE_EMAIL_DETAILS.format(
                    base_uri=self.microsoft_graph_endpoint,
                    tenant=self.tenant,
                    mail_address=self.mail_address,
                    folder_id=email.folder_id,
                    email_id=email.id
                ),
                "body": {"isRead": True},
                "headers": {"Content-Type": "application/json"}
            })
        barch_uri = BATCH_REQUEST.format(
            base_uri=self.microsoft_graph_endpoint
        )
        response = self.session.post(url=barch_uri, json={"requests": requests_json})
        self.validate_response(response)
