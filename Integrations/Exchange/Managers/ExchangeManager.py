# -*- coding: utf-8 -*-
# ==============================================================================
# title           :ExchangeManager.py
# description     :This Module contain all Microsoft Exchange operations functionality
# author          :org@siemplify.co
# date            :11-14-17
# python_version  :3.7
# ==============================================================================

# =====================================
#              IMPORTS                #
# =====================================
import re
from exchangelib import DELEGATE, IMPERSONATION, Account, \
    Configuration, OAUTH2, OAuth2AuthorizationCodeCredentials, \
    Message, EWSDateTime, HTMLBody, FileAttachment, ItemAttachment, Credentials, Identity
from exchangelib.items import ALWAYS_OVERWRITE
from exchangelib.properties import Mailbox
from exchangelib.version import EXCHANGE_2013, Version, EXCHANGE_2016
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from email.header import decode_header
from bs4 import BeautifulSoup
from base64 import b64decode, b64encode
import urllib3
import html2text
import json
import email
import requests
import os
import copy
from constants import PARAMETERS_DEFAULT_DELIMITER, TOKEN_FILE_PATH, CA_CERTIFICATE_FILE_PATH, KEY_FILE_PATH
from ExchangeParser import ExchangeParser
from EmailUtils import get_unicode_str, create_message, sign_message
from exceptions import ExchangeManagerError, NotFoundEmailsException, ExchangeException
from time import time
from oauthlib.oauth2 import OAuth2Token
from SiemplifyUtils import unix_now
from CustomExtendedProperties import register_custom_extended_properties
from ExchangeUtilsManager import save_file, delete_files
from smail import encrypt_message

# =====================================
#             CONSTANTS               #
# =====================================
# results will contain list of mail_json_format objects
RESULTS_JSON_OUTPUT = {
    "results": []
}

# Consts for siemplify html template parsing
HTML_IMAGE_TAG = "cstimage"
HTML_IMAGE_TAG_NAME_ATTR = "cid"
HTML_IMAGE_TAG_BASE64_ATTR = "base64image"

ENCODING_MAPPING = {
    "iso-8859-8-i": "iso-8859-8"
}

HTML_BODY_MSG_OBJECT_ATTR = 'body'
UNIQUE_BODY_MSG_OBJECT_ATTR = 'unique_body'

MISSING_ATTRIBUTE_MESSAGE_PATTERN = "Message object does not contain '{0}'"

DEFAULT_RESOLVED_BODY = "Message Has No Body."
DEFAULT_DELIMITER = ","
SYMBOLS_FOR_STRIPPING = " "
EML_TYPES = ["application/octet-stream", "message/rfc822"]

JUNK_OPERATIONS = {
    "junk": "junk",
    "not_junk": "not junk"
}

INVALID_REFRESH_TOKEN_ERROR = 'Refresh Token is malformed or invalid'
OAUTH_SCOPE = ['https://outlook.office365.com/EWS.AccessAsUser.All', 'offline_access']
ACCESS_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
URL_AUTHORIZATION = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&response_mode=query" + "&scope={scope}".format(scope='%20'.join(OAUTH_SCOPE))
TOKEN_PAYLOAD = {"client_id": None,
                 "client_secret": None,
                 "scope": ' '.join(OAUTH_SCOPE),
                 "grant_type": "authorization_code",
                 "code": None,
                 "redirect_uri": None}

REFRESH_PAYLOAD = {"client_id": None,
                   "client_secret": None,
                   "scope": ' '.join(OAUTH_SCOPE),
                   "refresh_token": None,
                   "grant_type": "refresh_token",
                   "redirect_uri": None}

OAUTH2TOKEN_BODY = {
    "token_type": "Bearer",
    "scope": "",
    "expires_in": 0,
    "ext_expires_in": 0,
    "access_token": "",
    "refresh_token": ""
}


def get_msg_attachments_content(msg):
    """
    Get contents of all attachments with *.msg extension from msg message
    :param msg: {exchangelib.Message} Message object from Exchange library
    :return: {dict} Dictionary representing {attachment_name; attachment_contents} pairs of all *.msg attachments from the msg
    """
    return get_common_file_attachment(msg, ".msg")


def get_ics_attachments_content(msg):
    """
    Get contents of all attachments with *.ics extension from msg message
    :param msg: {exchangelib.Message} Message object from Exchange library
    :return: {dict} Dictionary representing {attachment_name; attachment_contents} pairs of all *.ics attachments from the msg
    """
    return get_common_file_attachment(msg, ".ics")


def get_common_file_attachment(msg, extension=".msg"):
    """
    Extracts string representation of the msg attachments matching defined extension
    :param msg: {exchangelib.Message} Message object from Exchange library
    :param extension: {str} Extension against which attachments should be filtered. Different types of attachments may need special treatment
    :return: {dict} Dictionary representing {attachment_name; attachment_contents} pairs
    """
    contents = {}
    for attachment in msg.attachments:
        if isinstance(attachment, FileAttachment):
            if os.path.splitext(attachment.name)[-1].lower() == extension:
                contents[attachment.name] = attachment.content
    return contents


def get_msg_eml_content(msg):
    """
    Get contents of all attachments with *.eml extension from msg message
    :param msg: {exchangelib.Message} Message object from Exchange library
    :return: {dict} Dictionary representing {attachment_name; attachment_contents} pairs of all *.eml attachments from the msg
    """
    attachments = {}
    for attachment in msg.attachments:
        if isinstance(attachment, FileAttachment):
            if os.path.splitext(attachment.name)[-1].lower() == ".eml":
                attachments[attachment.name] = attachment.content
        elif isinstance(attachment, ItemAttachment):
            # When attaching emails in outlook, they are attached as an ItemAttachment and not regular file.
            # An ItemAttachment has an item property which is a exchangelib.items.Message object, that contains
            # mime_content field. In this way we can extract this attachment as an eml.
            attachments[attachment.name] = attachment.item.mime_content
    return attachments


# =====================================
#              CLASSES                #
# =====================================


class SiemplifyMessageDictKeys(object):
    AUTHOR_KEY = "author"
    SUBJECT_KEY = "subject"
    RESOLVED_BODY_KEY = "body"
    HTML_BODY_KEY = "html_body"
    PLAINTEXT_BODY_KEY = "plaintext_body"
    CREATED_TIME_KEY = "datetime_created"
    ATTACHMENTS_KEY = "attachments_list"
    MAILBOX_KEY = "account"
    FOLDER_NAME_KEY = "email_folder"


class OAuthCredentials(OAuth2AuthorizationCodeCredentials):
    def __init__(self, client_id, identity, client_secret=None, access_token=None, tenant_id=None, redirect_url=None,
                 verify_ssl=False):
        super().__init__(client_id=client_id, client_secret=client_secret, identity=identity, tenant_id=tenant_id)
        self.access_token = access_token
        self.redirect_url = redirect_url
        self.verify_ssl = verify_ssl

    def refresh(self):
        payload = copy.deepcopy(REFRESH_PAYLOAD)
        payload["client_id"] = self.client_id
        payload["client_secret"] = self.client_secret
        payload["refresh_token"] = self.access_token['refresh_token']
        payload["redirect_uri"] = self.redirect_url
        res = requests.post(ACCESS_TOKEN_URL.format(tenant=self.tenant_id), data=payload, headers={
            'Content-Type': 'application/x-www-form-urlencoded'}, verify=self.verify_ssl)

        # Validate token lifetime.
        if res.status_code == 400:
            raise ExchangeException("ERROR! Refresh token is invalid or malformed. (Token is valid only for 90 days, "
                                    "please renew your refresh token)")

        self.access_token = res.json()


class ExchangeManager(object):
    """
    Responsible for all Exchange client operations functionality
    """

    def __init__(self, exchange_server_ip, domain, user_mail_address, username=None, password=None,
                 use_domain_in_auth=True, autodiscover=False, siemplify_logger=None, client_id=None, client_secret=None,
                 tenant_id=None, auth_token=None, redirect_url=None, version=None, verify_ssl=False):
        register_custom_extended_properties()
        self._set_ssl_verification(verify_ssl=verify_ssl)
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.logger = siemplify_logger

        if client_id and tenant_id and auth_token:
            token_dict = OAUTH2TOKEN_BODY
            token_dict.update({'refresh_token': auth_token})
            auth_token = OAuth2Token(token_dict)
            self.credentials = OAuthCredentials(client_id=client_id, client_secret=client_secret,
                                                access_token=auth_token, tenant_id=tenant_id,
                                                identity=Identity(primary_smtp_address=user_mail_address),
                                                redirect_url=redirect_url,
                                                verify_ssl=verify_ssl)
            self.credentials.refresh()
            self.config = self._create_config_obj(exchange_server_ip, self.credentials, auth_type=OAUTH2,
                                                  version=EXCHANGE_2016)
            self.account = self._create_account_obj(user_mail_address, self.config, auto_discover=False,
                                                    access_type=IMPERSONATION)
        elif username and password:
            self.credentials = self._create_creds_obj(
                domain,
                username,
                password,
                logger=siemplify_logger,
                use_domain_in_auth=use_domain_in_auth,
            )
            self.config = self._create_config_obj(exchange_server_ip, self.credentials)
            self.autodiscover = autodiscover
            self.account = self._create_account_obj(user_mail_address, self.config, auto_discover=autodiscover)
        else:
            raise ExchangeException("Please provide necessary parameters for either Basic or Oauth authentication")

        self.email_address = user_mail_address
        self.parser = ExchangeParser()
        self.support_all_attachment_types = False

    @staticmethod
    def get_access_token_behalf_user(code, client_id, client_secret, tenant, redirect_url, logger):
        """
        Use the authorization code to request an access token
        :param code: {string} The authorization_code
        :param client_id: {string} Client (App) ID of Azure Active Directory App that will be used for the authorization
        :param client_secret: {string} The Client secret of Azure Active Directory App
        :param tenant: {string} Azure Tenant (Directory) ID
        :param redirect_url: The Redirect URL that will be used to authenticate integration.
        :param logger: Siemplify logger object
        :return: {string} An OAuth 2.0 refresh token. Refresh tokens are long-lived, and can be used to retain access to
         resources.
        """
        payload = copy.deepcopy(TOKEN_PAYLOAD)
        payload["client_id"] = client_id
        payload["client_secret"] = client_secret
        payload["code"] = code
        payload["redirect_uri"] = redirect_url

        res = requests.post(ACCESS_TOKEN_URL.format(tenant=tenant), data=payload)
        res.raise_for_status()
        ExchangeManager.write_token_timestamp(logger)

        return res.json()["refresh_token"]

    @staticmethod
    def write_token_timestamp(logger):
        """
        Function to write current refresh token timestamp to a file.
        """
        try:
            logger.info("Writing token timestamp to file: {}".format(TOKEN_FILE_PATH))
            with open(TOKEN_FILE_PATH, "w") as f:
                f.write(json.dumps({"Token Update Date": unix_now()}))
        except Exception as err:
            logger.error("Failed writing token timestamp to a file, ERROR: {0}".format(str(err)))
            logger.exception(err)
            return False

    @staticmethod
    def read_token_timestamp(logger):
        """
        Function to read previously saved token timestamp from a file, if exists.
        """

        if not os.path.exists(TOKEN_FILE_PATH):
            logger.info("Token timestamp file doesn't exist at path {}. ".format(TOKEN_FILE_PATH))
            ExchangeManager.write_token_timestamp(logger)
            return {}

        try:
            with open(TOKEN_FILE_PATH) as f:
                logger.info("Reading token timestamp from file")
                return json.loads(f.read())
        except Exception as e:
            logger.error('Unable to read token timestamp file: {}'.format(e))
            logger.exception(e)
            ExchangeManager.write_token_timestamp(logger)
            return {}

    def test_connectivity(self):
        """
        Test connectivity.
        :return: {bool} True if successful else raise exception.
        """
        return bool(self.account.oof_settings)

    @staticmethod
    def _set_ssl_verification(verify_ssl):
        """
        Set server ssl verification and disable warnings alerts
        :param verify_ssl: {bool} If False, will ignore verifying the SSL certificate
        :return:
        """
        if not verify_ssl:
            # Ignore SSL verification
            BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

    @classmethod
    def _create_creds_obj(cls, domain, username, password, logger, use_domain_in_auth=True):
        """
        Create exchange credentials instance
        :param domain: {string}
        :param username: {string}
        :param password: {string}
        :return:{object} Credential instance
        """

        slash_username = f"{domain}\\" in username
        at_username = f"@{domain}" in username

        if not use_domain_in_auth:
            return Credentials(username=username, password=password)
        else:
            if at_username or slash_username:
                logger.warn(
                    "Cant use “Use Domain For Authentication“ logic, as the Username is provided in "
                    "the username@domain (domain\\username) format, connector will not try to concatenate "
                    "Username and Domain values specified in connector parameters, only the Username "
                    "will be provided as is for authentication"
                )
                return Credentials(username=username, password=password)

            if not slash_username and not at_username:
                return Credentials(username="{user}@{domain}".format(user=username, domain=domain), password=password)

    @classmethod
    def _create_config_obj(cls, exchange_server_ip, credentials, auth_type=None, version=None):
        """
        Create exchange configuration instance
        :param exchange_server_ip: {string}
        :param credentials: {object} exchange credentials object
        :param auth_type: {string} authentication type
        :param version: {string} exchange version
        :return:{object} exchange configuration object
        """
        if version:
            return Configuration(server=exchange_server_ip, credentials=credentials, auth_type=auth_type,
                                 version=Version(version))
        else:
            return Configuration(server=exchange_server_ip, credentials=credentials, auth_type=auth_type)

    @classmethod
    def _create_account_obj(cls, user_mail_address, config, access_type=DELEGATE, auto_discover=False):
        """
        Create exchange account instance according to user credentials and smtp address
        :param user_mail_address: {string} the user smtp address
        :param config: {object} exchange configuration object
        :param auto_discover: {bool} If true, autodiscover mode will be enabled
        :return: {object} exchange user account object
        """
        try:
            return Account(primary_smtp_address=user_mail_address, config=config,
                           autodiscover=auto_discover, access_type=access_type)
        except Exception as e:
            try:
                if config.protocol.version.build < EXCHANGE_2013:
                    # Old exchange - try adjusting schema and try again
                    Mailbox.get_field_by_fieldname(
                        'routing_type').supported_from = EXCHANGE_2013
                    return Account(primary_smtp_address=user_mail_address,
                                   config=config,
                                   autodiscover=auto_discover, access_type=access_type)
            except:
                raise e

    @classmethod
    def _extract_images_from_html(cls, html_body):
        """
        Run over siemplify html template and retrieve all <cstImage> tags elements in order to create embedded image in mail
        :param html_body: {str} Siemplify html convention template
        :return: {list}{FileAttacment} list of FileAttachments object (exchangelib objects)
        """
        images = []
        soup = BeautifulSoup(html_body)
        for cst_tag in soup.findAll(HTML_IMAGE_TAG):
            image_name = cst_tag[HTML_IMAGE_TAG_NAME_ATTR]
            image_content = b64decode(cst_tag[HTML_IMAGE_TAG_BASE64_ATTR])
            images.append(FileAttachment(name=image_name, content=image_content))
        return images

    @classmethod
    def _clean_siemplify_html(cls, html_body):
        """
        Remove <cstImage> tags elements from siemplify html convention template
        :param html_body: {str} Siemplify html convention template
        :return: {str} the new html body
        """
        soup = BeautifulSoup(html_body)
        for cst_tag in soup.findAll(HTML_IMAGE_TAG):
            cst_tag.extract()
        return soup.prettify()

    @staticmethod
    def get_mail_mime_content(message_content, base64_encode=False):
        """
        Get message's mime content.
        :param message_content: {string} Mail message ID.
        :param base64_encode: {bool} Return in base64 format.
        :return: {string} Base64 content string.
        """
        if message_content:
            if base64_encode:
                return get_unicode_str(b64encode(message_content.mime_content))
            return get_unicode_str(message_content.mime_content.decode())

        raise ExchangeManagerError('Error, No message data received.')

    # TODO: Delete unused methods
    @staticmethod
    def extract_content_transfer_encoding_from_message(msg):
        """
        Get content transfer type string from email massage object.
        :param msg: {Message} Email message object.
        :return: {string} Content transfer type.
        """
        if msg.get_payload():
            return msg.get_payload()[0].get('Content-Transfer-Encoding')

    @staticmethod
    def render_html_body(html_body):
        """
        Render html body to plain text plain
        :param html_body: {str} The HTML body of the email
        :return: {str} Plain text rendered HTML
        """
        html_renderer = html2text.HTML2Text()
        html_renderer.ignore_tables = True
        html_renderer.protect_links = True
        html_renderer.ignore_images = False
        html_renderer.ignore_links = False
        return html_renderer.handle(html_body)

    def message_object_to_dict(self, message_object, set_mailbox=False, folder_name=None):
        """
        Convert message object to dictionary.
        :param message_object: {message} message object.
        :param set_mailbox: {bool} Whether result should contain mailbox.
        :param folder_name: {str} folder name to set in result.
        :return: {dict} message dict.
        """
        # TODO: Decode all fields based on header charset, then encode to utf-8
        # TODO should use Deepcopy, but it fails on TypeError: can't pickle thread.lock objects
        raw_dict = message_object.__dict__

        for f in message_object.FIELDS:
            val = getattr(message_object, f.name)

            if isinstance(val, bytes):
                try:
                    val = val.decode()
                except:
                    pass
            try:
                if isinstance(val, list):
                    raw_dict[f.name] = [str(v) for v in val]
                    continue

                raw_dict[f.name] = str(val)
            except:
                continue

        # Exclude 'conversation_index' field. Encoded field UTF-8 undecodable.
        if 'conversation_index' in raw_dict:
            raw_dict.pop('conversation_index')

        if set_mailbox:
            raw_dict[SiemplifyMessageDictKeys.MAILBOX_KEY] = str(message_object.account)

        if folder_name:
            raw_dict[SiemplifyMessageDictKeys.FOLDER_NAME_KEY] = folder_name

        raw_dict[SiemplifyMessageDictKeys.AUTHOR_KEY] = message_object.author.email_address
        raw_dict[
            SiemplifyMessageDictKeys.SUBJECT_KEY] = message_object.subject  # TODO: Decode based on header charset, then encode to utf-8

        raw_dict[
            SiemplifyMessageDictKeys.PLAINTEXT_BODY_KEY] = message_object.text_body.strip() if message_object.text_body else ""

        raw_dict[SiemplifyMessageDictKeys.HTML_BODY_KEY] = message_object.body if \
            hasattr(message_object, HTML_BODY_MSG_OBJECT_ATTR) else ""

        # Form message resoled body.
        if raw_dict[SiemplifyMessageDictKeys.PLAINTEXT_BODY_KEY]:
            raw_dict[SiemplifyMessageDictKeys.RESOLVED_BODY_KEY] = raw_dict[SiemplifyMessageDictKeys.PLAINTEXT_BODY_KEY]
        elif raw_dict[SiemplifyMessageDictKeys.HTML_BODY_KEY]:
            raw_dict[SiemplifyMessageDictKeys.RESOLVED_BODY_KEY] = self.render_html_body(
                raw_dict[SiemplifyMessageDictKeys.HTML_BODY_KEY])
        elif hasattr(message_object, UNIQUE_BODY_MSG_OBJECT_ATTR):
            raw_dict[SiemplifyMessageDictKeys.RESOLVED_BODY_KEY] = message_object.unique_body
        else:
            raw_dict[SiemplifyMessageDictKeys.RESOLVED_BODY_KEY] = DEFAULT_RESOLVED_BODY

        # Manage attachments.
        raw_dict[SiemplifyMessageDictKeys.ATTACHMENTS_KEY] = self.extract_attachments(message_object)

        # Convert all values to strings and return.
        return raw_dict

    def enable_support_all_attachment_types(self):
        """
        Force to support all attachments types. (Ex. ItemAttachment)
        For some methods it is not enables.
        Initially this parameter created for extract_attachments
        Since it used to extract ONLY FileAttachment types
        """
        self.support_all_attachment_types = True

    def extract_attachments(self, message_object):
        """
        Get files Base64 mapped for file names.
        :param message_object: {Exchangelib Message} Exchangelib message object.
        :return: {dict} Dict where the keys are file names and the values are file base64.
        """
        result_dict = {}
        for attachment in message_object.attachments:
            attachment_content = ''
            if isinstance(attachment, FileAttachment):
                attachment_content = attachment.content

            if self.support_all_attachment_types:
                # this is disabled by default call enable_all_attachments_extracting to enable
                # right now we are supporting only FileAttachment and ItemAttachment
                if isinstance(attachment, ItemAttachment):
                    attachment_content = attachment.item.mime_content
                # add some other type

            if attachment_content:
                result_dict[attachment.name] = get_unicode_str(b64encode(attachment_content))

        return result_dict

    def send_mail(self, to_addresses, subject, body, attachments_paths=[]):
        """
        Send mail using exchange api
        :param to_addresses: {string}
        :param subject: {string}
        :param body: {string}
        :param attachments_paths: {list} List of paths of attachments to attach
        :return: {boolean} Success indicator
        """
        # Create mail message instance
        msg = Message(
            account=self.account,
            subject=subject,
            body=body,
            to_recipients=[Mailbox(email_address=mail_address.strip(' ')) for mail_address in to_addresses.split(',')]
        )

        for attachment_path in attachments_paths:
            if not os.path.exists(attachment_path):
                raise ExchangeManagerError("Attachment {} doesn't exist.".format(attachment_path))

            with open(attachment_path, 'rb') as attachment:
                file_content = attachment.read()
                file_name = os.path.basename(attachment_path)
                msg.attach(FileAttachment(name=file_name, content=file_content))

        msg.send()
        return True

    def send_mail_html_embedded_photos(self, to_addresses, subject, html_body, attachments_paths=[], cc=None, bcc=None,
                                       generate_mail_id=True, vote_structure=None, reply_to_recipients=None,
                                       original_mail=None):
        """
        Sends HTML email with attachments using provided details
        :param to_addresses: {str} Comma-separated list of emails to be included to TO
        :param subject: {str} Email subject
        :param html_body: {str} Email contents in HTML format
        :param attachments_paths: {list} List of absolute paths to attachments
        :param cc: {str} Comma-separated list of emails to be included to CC
        :param bcc: {str} Comma-separated list of emails to be included to BCC
        :param generate_mail_id: {bool} Flag defining if message_id should be generated by the servers. Some Exchange servers don't support it, so we're verifying it in a separate method.
        :param vote_structure: {bytes} Structure of voting options
        :param reply_to_recipients: {list} List of emails for reply-to header
        :param original_mail: {Message} Original mail object
        :return: {MailData} The MailData object of the sent email or None (if generate_mail_id is False)
        """
        # Extract all images from siemplify html template
        image_files = self._extract_images_from_html(html_body)
        # Create html body
        body = HTMLBody(self._clean_siemplify_html(html_body))
        to_recipients = [Mailbox(email_address=mail_address.strip(SYMBOLS_FOR_STRIPPING)) for mail_address in
                         to_addresses.split(PARAMETERS_DEFAULT_DELIMITER)]
        cc_recipients = [Mailbox(email_address=mail_address.strip(SYMBOLS_FOR_STRIPPING)) for mail_address in
                         cc.split(PARAMETERS_DEFAULT_DELIMITER)] if cc else None
        bcc_recipients = [Mailbox(email_address=mail_address.strip(SYMBOLS_FOR_STRIPPING)) for mail_address in
                          bcc.split(PARAMETERS_DEFAULT_DELIMITER)] if bcc else None
        msg_id = None

        if generate_mail_id:
            msg_id = email.utils.make_msgid()

            # Create message object
            msg = Message(
                account=self.account,
                message_id=msg_id,
                subject=subject,
                body=body,
                to_recipients=to_recipients,
                cc_recipients=cc_recipients,
                bcc_recipients=bcc_recipients,
                vote_request=vote_structure,
                reply_to=reply_to_recipients
            )

        else:
            # Create message object
            msg = Message(
                account=self.account,
                subject=subject,
                body=body,
                to_recipients=to_recipients,
                cc_recipients=cc_recipients,
                bcc_recipients=bcc_recipients,
                vote_request=vote_structure,
                reply_to=reply_to_recipients
            )

        if original_mail:
            msg.in_reply_to = original_mail.message_id
            msg.references = original_mail.message_id

        # Attach images to message
        for img in image_files:
            msg.attach(img)

        for attachment_path in attachments_paths:
            if not os.path.exists(attachment_path):
                raise ExchangeManagerError("Attachment {} doesn't exist.".format(attachment_path))

            with open(attachment_path, 'rb') as attachment:
                file_content = attachment.read()
                file_name = os.path.basename(attachment_path)
                msg.attach(FileAttachment(name=file_name, content=file_content))

        # Send mail
        msg.send()
        return self.parser.get_mail_data(self.account.sent.get(message_id=msg.message_id)) if generate_mail_id else None

    def send_encoded_mail(self, to_addresses, subject, html_body, base64_certificate, attachments_paths=[], cc=None,
                          bcc=None, generate_mail_id=True, reply_to_recipients=None):
        """
        Sends encoded email with attachments using provided details
        :param to_addresses: {str} Comma-separated list of emails to be included to TO
        :param subject: {str} Email subject
        :param html_body: {str} Email contents in HTML format
        :param base64_certificate: {str} Base64 encoded certificate file content to use for encoding
        :param attachments_paths: {list} List of absolute paths to attachments
        :param cc: {str} Comma-separated list of emails to be included to CC
        :param bcc: {str} Comma-separated list of emails to be included to BCC
        :param generate_mail_id: {bool} Flag defining if message_id should be generated by the servers. Some Exchange servers don't support it, so we're verifying it in a separate method.
        :param reply_to_recipients: {list} List of emails for reply-to header
        :return: {MailData} The MailData object of the sent email or None (if generate_mail_id is False)
        """
        # Create html body
        body = HTMLBody(self._clean_siemplify_html(html_body))
        to_recipients = [mail_address.strip(SYMBOLS_FOR_STRIPPING) for mail_address in
                         to_addresses.split(PARAMETERS_DEFAULT_DELIMITER)]
        cc_recipients = [mail_address.strip(SYMBOLS_FOR_STRIPPING) for mail_address in
                         cc.split(PARAMETERS_DEFAULT_DELIMITER)] if cc else None
        bcc_recipients = [mail_address.strip(SYMBOLS_FOR_STRIPPING) for mail_address in
                          bcc.split(PARAMETERS_DEFAULT_DELIMITER)] if bcc else None

        message = create_message(recipients=to_recipients, subject=subject, html_content=body, cc=cc_recipients,
                                 bcc=bcc_recipients, attachments=attachments_paths)

        encrypted_message = encrypt_message(message, [save_file(base64_certificate, CA_CERTIFICATE_FILE_PATH)])
        delete_files(self.logger, [CA_CERTIFICATE_FILE_PATH])
        mime_content = encrypted_message.as_string().encode()

        if generate_mail_id:
            msg_id = email.utils.make_msgid()

            # Create message object
            msg = Message(
                account=self.account,
                message_id=msg_id,
                mime_content=mime_content,
                reply_to=reply_to_recipients
            )

        else:
            # Create message object
            msg = Message(
                account=self.account,
                mime_content=mime_content,
                reply_to=reply_to_recipients
            )

        msg.send()
        return self.parser.get_mail_data(self.account.sent.get(message_id=msg.message_id)) if generate_mail_id else None

    def send_signed_message(self, to_addresses, subject, html_body, base64_certificate, base64_private_key,
                            attachments_paths=[], cc=None, bcc=None, generate_mail_id=True, reply_to_recipients=None):
        """
        Sends signed email with attachments using provided details
        :param to_addresses: {str} Comma-separated list of emails to be included to TO
        :param subject: {str} Email subject
        :param html_body: {str} Email contents in HTML format
        :param base64_certificate: {str} Base64 encoded certificate file content to use for signing
        :param base64_private_key: {str} Base64 encoded private key file content to use for signing
        :param attachments_paths: {list} List of absolute paths to attachments
        :param cc: {str} Comma-separated list of emails to be included to CC
        :param bcc: {str} Comma-separated list of emails to be included to BCC
        :param generate_mail_id: {bool} Flag defining if message_id should be generated by the servers. Some Exchange servers don't support it, so we're verifying it in a separate method.
        :param reply_to_recipients: {list} List of emails for reply-to header
        :return: {MailData} The MailData object of the sent email or None (if generate_mail_id is False)
        """
        # Create html body
        body = HTMLBody(self._clean_siemplify_html(html_body))
        to_recipients = [mail_address.strip(SYMBOLS_FOR_STRIPPING) for mail_address in
                         to_addresses.split(PARAMETERS_DEFAULT_DELIMITER)]
        cc_recipients = [mail_address.strip(SYMBOLS_FOR_STRIPPING) for mail_address in
                         cc.split(PARAMETERS_DEFAULT_DELIMITER)] if cc else None
        bcc_recipients = [mail_address.strip(SYMBOLS_FOR_STRIPPING) for mail_address in
                          bcc.split(PARAMETERS_DEFAULT_DELIMITER)] if bcc else None

        message = create_message(recipients=to_recipients, subject=subject, html_content=body, cc=cc_recipients,
                                 bcc=bcc_recipients, attachments=attachments_paths)

        signed_message = sign_message(message, save_file(base64_private_key, KEY_FILE_PATH),
                                      save_file(base64_certificate, CA_CERTIFICATE_FILE_PATH))
        delete_files(self.logger, [KEY_FILE_PATH, CA_CERTIFICATE_FILE_PATH])
        mime_content = signed_message.as_string().encode()

        if generate_mail_id:
            msg_id = email.utils.make_msgid()

            # Create message object
            msg = Message(
                account=self.account,
                message_id=msg_id,
                mime_content=mime_content,
                reply_to=reply_to_recipients
            )

        else:
            # Create message object
            msg = Message(
                account=self.account,
                mime_content=mime_content,
                reply_to=reply_to_recipients
            )

        msg.send()
        return self.parser.get_mail_data(self.account.sent.get(message_id=msg.message_id)) if generate_mail_id else None

    def receive_mail(self,
                     folder_name='Inbox',
                     message_id=None,
                     from_filter=None,
                     subject_filter=None,
                     content_filter=None,
                     time_filter=None,
                     recipient_filter=None,
                     only_unread=False,
                     mark_as_read=False,
                     json_results=False,
                     account=None,
                     reply_to=None,
                     limit=None,
                     all_mailboxes=False,
                     siemplify_result=False,
                     conversation_id=None,
                     end_time_filter=None,
                     body_regex_filter=None,
                     set_folder=None):
        """
        Get mails from account using exchange api
        :param account: {exchangelib.Account} An account to receive mail in
        :param message_id: {unicode} Given by Exchange Default is None
        :param folder_name: {unicode} Default is Inbox folder
        :param from_filter: {unicode} Default is None
        :param subject_filter: {unicode} Default is None
        :param content_filter: {unicode} Default is None
        :param time_filter: {datetime} Default is None mus be aware (with time zone)
        :param recipient_filter: {unicode} Filter by recipient
        :param only_unread: {bool} Fetch only unread mails, Default is False
        :param mark_as_read: {bool} mark mails as read, Default is False
        :param json_results: {bool} Return results in json format, Default is False #TODO: Legacy, use siemplify_result instead.
        :param siemplify_result: {bool} Returns list of dicts when each dict represent a mail in JSON format.
        :param reply_to: {str} Email message_id, replies to which should be searched
        :param limit: {int} Max number of messages to return.
        :param all_mailboxes: {bool} Whether mails from specified mailbox or from all mailboxes.
        :param conversation_id: {ConversationId} Filter by conversation id.
        :param end_time_filter: {datetime} Filter by end time.
        :param body_regex_filter: {str} Filter by body in regex format.
        :param set_folder: {bool} Whether results should contain folder name.
        :return: {list} Messages OR Json Containing all suitable mails - example:
        {"results": [{"author": "David","subject": "Taking care","body": "How are you today?"}]}
        """
        # Find the relevant folder (Inbox is default)
        folder = self.get_folder_object_by_name(folder_name, account)

        if not folder:
            raise ExchangeManagerError("Cannot find \"{}\" in account folders".format(folder_name))
        # Get all user messages from folder
        query = folder.all()
        # Filter according to arguments
        if message_id:
            query = query.filter(message_id=message_id)
        if reply_to:
            query = query.filter(in_reply_to=reply_to)
        if conversation_id:
            query = query.filter(conversation_id=conversation_id)
        if from_filter:
            query = query.filter(sender__icontains=from_filter)
        if subject_filter:
            query = query.filter(subject__icontains=subject_filter)
        if only_unread:
            query = query.filter(is_read=False)

        if time_filter and end_time_filter:
            query = query.filter(datetime_received__range=(
                EWSDateTime.from_datetime(time_filter),
                EWSDateTime.from_datetime(end_time_filter)
            ))
        elif time_filter:
            # Create EWS datetime format
            # time_zone = EWSTimeZone.localzone()
            # time = time_zone.localize(EWSDateTime.from_datetime(time_filter))
            time = EWSDateTime.from_datetime(time_filter)
            query = query.filter(datetime_received__gt=time)

        # TODO: implement this!!!
        if content_filter:
            pass

        # Get the final query objects results
        messages_list = list(query)

        if recipient_filter or body_regex_filter:
            filtered_list = []

            for msg in messages_list:
                pass_recipient_filter = True
                pass_body_regex_filter = True

                if recipient_filter:
                    msg_recipients = [recipient.email_address.lower() for recipient in msg.to_recipients if
                                      recipient.email_address] if msg.to_recipients else []
                    msg_recipients.extend([recipient.email_address.lower() for recipient in msg.cc_recipients if
                                           recipient.email_address] if msg.cc_recipients else [])
                    msg_recipients.extend([recipient.email_address.lower() for recipient in msg.bcc_recipients if
                                           recipient.email_address] if msg.bcc_recipients else [])

                    pass_recipient_filter = True if recipient_filter.lower() in msg_recipients else False

                if body_regex_filter:
                    pass_body_regex_filter = True if re.search(body_regex_filter, msg.text_body or "") else False

                if pass_recipient_filter and pass_body_regex_filter:
                    filtered_list.append(msg)

            messages_list = filtered_list

        # Apply limit on results
        messages_list = messages_list[:limit] if limit else messages_list

        # Mark messages as redaen if necessary
        if mark_as_read:
            for msg in messages_list:
                msg.is_read = True
                # We have to force conflict resolution here to allow saving msg.is_read = True above.
                # If we won't do it, exchangelib would raise an exception on marking it as read.
                # Not even sure if it was working before.
                msg.save(conflict_resolution=ALWAYS_OVERWRITE)

        if json_results or siemplify_result:
            # TODO: CUrrently message_object_to_dict corrupts the original ExchangeLib Message object. So we call this oneliner only when needed
            siemplify_messages = [self.message_object_to_dict(message, all_mailboxes, folder_name if set_folder else None)
                                  for message in messages_list]

        if siemplify_result:
            return siemplify_messages

        # Legacy: should use siemplify result when possible.
        if json_results:
            # Create a copy of the dict information
            results_json = copy.deepcopy(RESULTS_JSON_OUTPUT)
            # Insert all relevant messages in the result json
            results_json["results"] = siemplify_messages
            return results_json

        # Legacy: should use siemplify result when possible.
        return messages_list

    def save_attachments_to_local_path(self, msg, save_to_path, download_from_eml, unique_path):
        """
        Save message attachment to local path in file system
        :param msg: {exchangelib.Message} object
        :param save_to_path: {str} Path on the server where to download the email attachments
        :param download_from_eml: {bool} Specify whether download attachments also from attached EML files or no
        :param unique_path: {bool} Specify whether download attachments to unique path or no
        :return: {list} List of AttachmentData objects
        """
        files_data = []

        for attachment in msg.attachments:
            if isinstance(attachment, FileAttachment):
                files_data.append(self.save_attachment(save_to_path, attachment.name, attachment.content, unique_path))

                if download_from_eml and attachment.content_type in EML_TYPES:
                    # Download attachments from attached emls
                    attachment_content = get_unicode_str(attachment.content)
                    eml_msg = email.message_from_bytes(attachment_content) if isinstance(attachment_content, bytes) \
                        else email.message_from_string(attachment_content)

                    # Extract attachments from eml
                    attachments = eml_msg.get_payload()

                    for attachment in attachments:
                        # Extract filename from attachment
                        filename = None if isinstance(attachment, str) else attachment.get_filename()

                        # Some emails can return an empty attachment
                        # possibly if there are a signature.
                        # Validate that the attachment has a filename
                        if filename:
                            # Handle 'UTF-8' issues
                            fname, charset = decode_header(filename)[0]
                            if charset:
                                filename = fname.decode(charset)

                            # save attachment to path
                            attachment_content = attachment.get_payload(decode=True)
                            if not attachment_content:
                                # this can happen when attachment is email.message.Message, so we need to convert object to bytes
                                attachment_content = bytes(attachment)

                            files_data.append(self.save_attachment(save_to_path, filename,
                                                                   attachment_content, unique_path))

            elif isinstance(attachment, ItemAttachment):
                attachment_content = attachment.item.mime_content
                files_data.append(self.save_attachment(save_to_path, attachment.name, attachment_content, unique_path))

                if download_from_eml:
                    files_data.extend(self.save_attachments_to_local_path(attachment.item, save_to_path,
                                                                          download_from_eml, unique_path))

        return files_data

    def save_attachment(self, path, attachment_name, attachment_content, unique_path):
        """
        Save attachment to specified path
        :param path: {str} Path on the server where to download the email attachments
        :param attachment_name: {str} Attachment name
        :param attachment_content: {str} Attachment content
        :param unique_path: {bool} Specify whether download attachments to unique path or no
        :return: {AttachmentData} The AttachmentData object
        """
        attachment_name = self.build_attachment_unique_name(attachment_name) if unique_path else attachment_name
        if '/' in attachment_name:
            attachment_name = attachment_name.replace('/', '_')
        if '\\' in attachment_name:
            attachment_name = attachment_name.replace('\\', '_')

        local_path = os.path.join(path, attachment_name)

        with open(local_path, 'wb') as f:
            f.write(attachment_content)

        return self.parser.get_attachment_data(attachment_name, local_path)

    def build_attachment_unique_name(self, attachment_name):
        """
        Build unique attachment name based on attachment name
        :param attachment_name: {str} Attachment name
        :return: {str} unique attachment name
        """
        name, extension = os.path.splitext(attachment_name)
        return "{}-{}{}".format(name, time(), extension)

    # TODO: Delete unused methods
    @staticmethod
    def decode_message_content(message_string, content_transfer_encoding, content_charset):
        """
        Decode encoded message content.
        :param message_string: {string}  Message content string.
        :param content_transfer_encoding: {string} Message content transfer encoding.
        :param content_charset: {string} Message content charset encoded.
        :return: {string} Decoded message.
        """
        return message_string.decode(content_transfer_encoding).decode(content_charset)

    # TODO: Delete unused methods
    @staticmethod
    def extract_content_charset_from_message(msg):
        """
        Get content charset string from email massage object.
        :param msg: {Message} Email message object.
        :return: {string} Charset content type.
        """
        if msg.get_payload():
            if msg.get_payload()[0].get_charsets():
                content_charset = msg.get_payload()[0].get_content_charset()
                if content_charset in ENCODING_MAPPING:
                    return ENCODING_MAPPING.get(content_charset)
                return content_charset

    def move_mail_from_mailbox(self, mailbox_address, src_folder_name, dst_folder_name="Inbox", only_unread=False,
                               subject_filter=None, message_id=None, time_filter=None):
        """
        Move emails from source folder to destination folder
        :param mailbox_address: {str} The mailbox address to move the email from
        :param src_folder_name: {str} Source folder name, from which found emails would be moved to the target folder
        :param dst_folder_name: {str} Destination folder name, where target emails would be moved
        :param only_unread: {bool} True if only unread, False otherwise.
        :param subject_filter: {str} Subject to filter emails by
        :param message_id: {str} The id of the message to move
        :param time_filter: {datetime} Filter by time
        :return: {tuple} List of MessageData objects and failed mailboxes
        """
        account = self.account if mailbox_address == self.account.primary_smtp_address else self._create_account_obj(
            mailbox_address,
            self.config,
            IMPERSONATION
        )

        all_messages = []

        try:
            folder_object = self.get_folder_object_by_name(dst_folder_name, account)

            if not folder_object:
                raise ExchangeManagerError(
                    "Folder {} was not found in account {}".format(
                        dst_folder_name,
                        self.account.primary_smtp_address
                    )
                )

            messages = self.receive_mail(subject_filter=subject_filter,
                                         only_unread=only_unread,
                                         account=account,
                                         message_id=message_id,
                                         folder_name=src_folder_name,
                                         time_filter=time_filter)

            all_messages.extend(
                [self.parser.get_message_data(
                    self.message_object_to_dict(message, True),
                    True
                ) for message in messages]
            )

            for message in messages:
                message.move(folder_object)

            if messages:
                self.logger.info(
                    "Moved emails from folder={} to folder={} with message_id={}, subject_filter={}, only_unread={}"
                        .format(src_folder_name, dst_folder_name, message_id, subject_filter, only_unread)
                )
            else:
                self.logger.info(
                    "Failed to find emails in folder={} with message_id={}, subject_filter={}, only_unread={}"
                        .format(src_folder_name, message_id, subject_filter, only_unread)
                )

        except Exception as e:
            self.logger.error("Unable to move emails in account={} from folder={} with message_id={}, "
                              "subject_filter={} only_unread={}"
                              .format(account, src_folder_name, message_id, subject_filter, only_unread))
            self.logger.exception(e)

        return all_messages

    def move_mail(self,
                  src_folder_name,
                  dst_folder_name="Inbox",
                  only_unread=False,
                  subject_filter=None,
                  message_id=None,
                  move_in_all_mailboxes=False):
        """
        Move emails from source folder to destination folder
        :param src_folder_name: {str} Source folder name, from which found emails would be moved to the target folder
        :param dst_folder_name: {str} Destination folder name, where target emails would be moved
        :param only_unread: {bool} True if only unread, False otherwise.
        :param subject_filter: {str} Subject to filter emails by
        :param message_id: {str} The id of the message to move
        :param move_in_all_mailboxes: {bool} Whether to move the emails in all mailboxes.
        :return: {tuple} List of MessageData objects and failed mailboxes
        """
        all_messages = []
        accounts, failed_mailboxes = self.get_searchable_mailboxes_accounts(move_in_all_mailboxes)

        for account in accounts:
            try:
                folder_object = self.get_folder_object_by_name(dst_folder_name, account)

                if not folder_object:
                    raise ExchangeManagerError(
                        "Folder {} was not found in account {}".format(
                            dst_folder_name,
                            self.account.primary_smtp_address
                        )
                    )

                messages = self.receive_mail(subject_filter=subject_filter,
                                             only_unread=only_unread,
                                             account=account,
                                             message_id=message_id,
                                             folder_name=src_folder_name)

                all_messages.extend(
                    [self.parser.get_message_data(
                        self.message_object_to_dict(message, move_in_all_mailboxes),
                        move_in_all_mailboxes
                    ) for message in messages]
                )

                for message in messages:
                    message.move(folder_object)

                if messages:
                    self.logger.info(
                        "Moved emails from folder={} to folder={} with message_id={}, subject_filter={}, only_unread={}"
                            .format(src_folder_name, dst_folder_name, message_id, subject_filter, only_unread)
                    )
                else:
                    self.logger.info(
                        "Failed to find emails in folder={} with message_id={}, subject_filter={}, only_unread={}"
                            .format(src_folder_name, message_id, subject_filter, only_unread)
                    )

            except Exception as e:
                self.logger.error("Unable to move emails in account={} from folder={} with message_id={}, "
                                  "subject_filter={} only_unread={}"
                                  .format(account, src_folder_name, message_id, subject_filter, only_unread))
                self.logger.exception(e)

        return all_messages, failed_mailboxes

    def delete_mail(self,
                    folders_names,
                    message_id=None,
                    subject_filter=None,
                    sender_filter=None,
                    recipient_filter=None,
                    delete_all_options=False,
                    delete_from_all_mailboxes=False):
        """
        Delete mail from exchange mailbox
        Get mails from account using exchange api
        :param folders_names: {list} List of folders names to search emails
        :param message_id: {str} The message ID to filter by
        :param subject_filter: {str} Filter by subject, default is None
        :param sender_filter: {str} Filter by sender, default is None
        :param recipient_filter: {str} Filter by recipient, default is None
        :param delete_all_options: {bool} Delete all suitable messages or only the first
        :param delete_from_all_mailboxes: {bool} Whether delete emails from specified mailbox or from all mailboxes
        :return: {tuple} List of MessageData objects and failed mailboxes
        """

        all_messages = []
        accounts, failed_mailboxes = self.get_searchable_mailboxes_accounts(delete_from_all_mailboxes)
        limit = 1 if not delete_all_options else None

        for account in accounts:
            for folder in folders_names:
                try:
                    messages = self.receive_mail(folder_name=folder,
                                                 message_id=message_id,
                                                 subject_filter=subject_filter,
                                                 from_filter=sender_filter,
                                                 recipient_filter=recipient_filter,
                                                 limit=limit,
                                                 account=account)

                    all_messages.extend(
                        [self.parser.get_message_data(
                            self.message_object_to_dict(message, delete_from_all_mailboxes),
                            delete_from_all_mailboxes
                        ) for message in messages]
                    )

                    for message in messages:
                        message.delete()

                    if messages:
                        self.logger.info(
                            "Deleted emails in folder={} with message_id={}, subject_filter={}, sender_filter={},"
                            " recipient_filter={}"
                                .format(folder, message_id, subject_filter, sender_filter, recipient_filter)
                        )
                    else:
                        self.logger.info(
                            "Failed to find emails in folder={} with message_id={}, subject_filter={},"
                            "sender_filter={}, recipient_filter={}"
                                .format(folder, message_id, subject_filter, sender_filter, recipient_filter)
                        )

                except Exception as e:
                    self.logger.error("Couldn't delete emails in folder={} with message_id={}, subject_filter={}, "
                                      "sender_filter={}, recipient_filter={}"
                                      .format(folder, message_id, subject_filter, sender_filter, recipient_filter))
                    self.logger.exception(e)

        return all_messages, failed_mailboxes

    def delete_mail_from_mailbox(self,
                                 mailbox_address,
                                 folders_names,
                                 message_id=None,
                                 subject_filter=None,
                                 sender_filter=None,
                                 time_filter=None,
                                 recipient_filter=None,
                                 delete_all_options=False):
        """
        Delete mail from exchange mailbox
        Get mails from account using exchange api
        :param mailbox_address: {str} The mailbox address to delete the email from
        :param folders_names: {list} List of folders names to search emails
        :param message_id: {str} The message ID to filter by
        :param subject_filter: {str} Filter by subject, default is None
        :param sender_filter: {str} Filter by sender, default is None
        :param time_filter: {datetime} Default is None mus be aware (with time zone)
        :param recipient_filter: {str} Filter by recipient, default is None
        :param delete_all_options: {bool} Delete all suitable messages or only the first
        :return: {list} List of MessageData objects
        """
        # Connect to the given mailbox
        account = self.account if mailbox_address == self.account.primary_smtp_address else self._create_account_obj(
            mailbox_address,
            self.config,
            IMPERSONATION
        )

        all_messages = []
        limit = 1 if not delete_all_options else None

        for folder in folders_names:
            try:
                messages = self.receive_mail(folder_name=folder,
                                             message_id=message_id,
                                             subject_filter=subject_filter,
                                             from_filter=sender_filter,
                                             time_filter=time_filter,
                                             recipient_filter=recipient_filter,
                                             limit=limit,
                                             account=account)

                all_messages.extend(
                    [self.parser.get_message_data(
                        self.message_object_to_dict(message, True),
                        True
                    ) for message in messages]
                )

                for message in messages:
                    message.delete()

                if messages:
                    self.logger.info(
                        "Deleted emails in folder={} with message_id={}, subject_filter={}, sender_filter={},"
                        " recipient_filter={}"
                            .format(folder, message_id, subject_filter, sender_filter, recipient_filter)
                    )
                else:
                    self.logger.info(
                        "Failed to find emails in folder={} with message_id={}, subject_filter={},"
                        "sender_filter={}, recipient_filter={}"
                            .format(folder, message_id, subject_filter, sender_filter, recipient_filter)
                    )

            except Exception as e:
                self.logger.error("Couldn't delete emails in folder={} with message_id={}, subject_filter={}, "
                                  "sender_filter={}, recipient_filter={}"
                                  .format(folder, message_id, subject_filter, sender_filter, recipient_filter))
                self.logger.exception(e)

        return all_messages

    def get_folder_object_by_name(self, folder_name, account=None):
        """
        Retrieve exchangelib folder object by the folder name
        :param folder_name: {str} Folder name to look for
        :param account: {exchangelib.Account} Account to use for the folder search
        :return: {exchangelib.folders.Messages} object
        """
        if not account:
            account = self.account

        folders = list(account.root.glob('**/{0}'.format(folder_name)))
        if folders:
            # Return the first matching folder
            return folders[0]
        else:
            return None

    def is_writable_mail_id_supported(self):
        """
        Return whether the writing of InternetMessageId field in a Message object
        is writable or not, by the Exchange Server build (seems that in Exchange 2010 SP3
        is was not writable, so limit to any versions after 2013)
        :return: {bool} True if InternetMessageId is writable, False otherwise.
        """
        return self.account.protocol.version.build >= EXCHANGE_2013

    def is_supporting_version(self, version):
        """
        Compare Exchange server version with provided version
        :param version: {str} The version to compare with
        :return: {bool} The result of version comparison
        """
        return self.account.protocol.version.build >= version

    def get_searchable_mailboxes_addresses(self, all_mailboxes):
        """
        Get all searchable mailboxes addresses
        :return: {list} List of the searchable mailboxes addresses
        """
        addresses = [] if all_mailboxes else [self.account.primary_smtp_address]

        if all_mailboxes:
            try:
                for mailbox in self.account.protocol.get_searchable_mailboxes():
                    if mailbox.primary_smtp_address:
                        addresses.append(mailbox.primary_smtp_address)

            except Exception as e:
                # Error in exchangelib get_searchable_mailboxes generator - bug in exchangelib
                self.logger.info('Failed to get searchable mailboxes. Reason is - {}'.format(e))
                raise

        return addresses

    def get_searchable_mailboxes_accounts(self, all_mailboxes):
        """
        Get current mailbox account or searchable mailboxes accounts
        :param all_mailboxes: {bool} Whether return current mailbox account or searchable mailboxes accounts
        :return: {tuple} Successful accounts and failed mailboxes ids
        """
        accounts = [] if all_mailboxes else [self.account]
        failed_mailboxes = []

        if all_mailboxes:
            try:
                for mailbox in self.account.protocol.get_searchable_mailboxes():
                    try:
                        if mailbox.primary_smtp_address:
                            accounts.append(self._create_account_obj(
                                mailbox.primary_smtp_address,
                                self.config,
                                IMPERSONATION)
                            )
                    except Exception as e:
                        # No permissions to given mailbox.
                        failed_mailboxes.append(mailbox.guid)
                        self.logger.info('Failed to access mailbox with guid - {}. Reason is - {}'
                                         .format(mailbox.guid, e))

                        pass
            except Exception as e:
                # Error in exchangelib get_searchable_mailboxes generator - bug in exchangelib
                self.logger.info('Failed to get searchable mailboxes. Reason is - {}'.format(e))
                raise

        return accounts, failed_mailboxes

    def get_messages_data(self, message_id, folder_name, add_account=False):
        """
        Get emails from mailboxes with specified filters
        :param message_id: {str} Unique email ID
        :param folder_name: {str} Folder name to search emails
        :param add_account: {bool} Whether include account in result or no.
        :return: {list} List of MessagesData objects
        """
        return self.parser.get_messages_data(
            self.receive_mail(
                message_id=message_id,
                folder_name=folder_name,
                json_results=True,
            ),
            add_account
        )

    def search_mail_in_mailbox(self, mailbox_address, folders_names, message_id=None, subject_filter=None,
                               start_time_filter=None, end_time_filter=None, recipient_filter=None, from_filter=None,
                               body_regex_filter=None, only_unread=False, limit=None, siemplify_result=True):
        """
        Search emails in mailboxes with specified filters
        :param mailbox_address: {str} The mailbox address to delete the email from
        :param folders_names: {list} List of folders names to search emails
        :param message_id: {str} The message ID to filter by
        :param subject_filter: {str} Filter by subject
        :param start_time_filter: {datetime} Filter by start time
        :param end_time_filter: {datetime} Filter by end time
        :param recipient_filter: {str} Filter by recipient
        :param from_filter: {str} Filter by sender
        :param body_regex_filter: {str} Filter by body in regex format
        :param only_unread: {bool} Fetch only unread emails
        :param limit: {int} Max number of emails to return.
        :param siemplify_result: {bool} Specifies if found emails should be transformed to MessageData objects
        :return: {dict} Messages or Json containing all suitable mails
        """
        # Connect to the given mailbox
        account = self.account if mailbox_address == self.account.primary_smtp_address else self._create_account_obj(
            mailbox_address,
            self.config,
            IMPERSONATION
        )
        all_messages = []

        for folder in folders_names:
            try:
                messages = self.receive_mail(message_id=message_id,
                                             subject_filter=subject_filter,
                                             time_filter=start_time_filter,
                                             end_time_filter=end_time_filter,
                                             recipient_filter=recipient_filter,
                                             only_unread=only_unread,
                                             from_filter=from_filter,
                                             body_regex_filter=body_regex_filter,
                                             folder_name=folder,
                                             limit=limit,
                                             account=account)

                if siemplify_result:
                    all_messages.extend(
                        [self.parser.get_message_data(
                            self.message_object_to_dict(message, True),
                            True
                        ) for message in messages]
                    )
                else:
                    all_messages.extend(messages)
            except Exception as e:
                self.logger.error("Failed to search emails in account={}, folder={} with message_id={}, "
                                  "subject_filter={}, sender_filter={}, recipient_filter={}, start_time_filter={}, "
                                  "end_time_filter={}, only_unread={}"
                                  .format(account, folder, message_id, subject_filter, from_filter, recipient_filter,
                                          start_time_filter, end_time_filter, only_unread))
                self.logger.exception(e)

        return all_messages

    def search_mails(self, folders_names, subject_filter=None, time_filter=None, recipient_filter=None,
                     from_filter=None, only_unread=False, limit=None, all_mailboxes=False):
        """
        Search emails in mailboxes with specified filters
        :param folders_names: {list} List of folders names to search emails
        :param subject_filter: {str} Filter by subject
        :param time_filter: {datetime} Filter by time
        :param recipient_filter: {str} Filter by recipient
        :param from_filter: {str} Filter by sender
        :param only_unread: {bool} Fetch only unread emails
        :param limit: {int} Max number of emails to return.
        :param all_mailboxes: {bool} Whether get emails from specified mailboxes or from all mailboxes.
        :return: {dict} Messages or Json containing all suitable mails
        """
        messages_groups = []
        accounts, failed_mailboxes = self.get_searchable_mailboxes_accounts(all_mailboxes)

        for account in accounts:
            for folder in folders_names:
                try:
                    messages_groups.append(
                        self.parser.get_messages_data(
                            self.receive_mail(subject_filter=subject_filter,
                                              time_filter=time_filter,
                                              recipient_filter=recipient_filter,
                                              only_unread=only_unread,
                                              from_filter=from_filter,
                                              folder_name=folder,
                                              limit=limit,
                                              all_mailboxes=all_mailboxes,
                                              json_results=True,
                                              account=account
                                              ),
                            all_mailboxes
                        )

                    )
                except Exception as e:
                    self.logger.error("Failed to search emails in account={}, folder={} with subject_filter={}, "
                                      "sender_filter={}, recipient_filter={}, time_filter={}, only_unread={}"
                                      .format(account, folder, subject_filter, from_filter, recipient_filter,
                                              time_filter, only_unread))
                    self.logger.exception(e)

        return messages_groups

    def get_oof_settings_for_user(self, user_name):
        """
        Get oof settings for user
        :param user_name: {str} User name
        :return: {SiemplifyOOF} SiemplifyOOF object
        """
        # first we should try IMPERSONATION access type, if we fail to get oof_settings we will try DELEGATE
        access_types = [IMPERSONATION, DELEGATE]

        for access_type in access_types:
            try:
                account = self._create_account_obj(user_name, self.config, access_type)
                return self.parser.get_oof_data(account.oof_settings)
            except:
                # if we fail to load with certain access type we should try the next access type
                continue

        raise ExchangeManagerError('Unable to find oof settings for email {}.'.format(user_name))

    def junk_mail(self, mailbox_address, is_junk, move_items, folder_names, message_id=None, subject_filter=None,
                  from_filter=None, recipient_filter=None, mark_all_matching_emails=None, time_filter=None):
        """
        Find messages and mark them as junk/not junk
        :param mailbox_address: {str} The mailbox address to mark message from
        :param is_junk: {bool} Specifies whether mark messages as junk or not junk
        :param move_items: {bool} Specifies whether move messages or no
        :param message_id: {str} The id of the message to mark
        :param folder_names: {list} The list of folders to search for messages
        :param subject_filter: {str} Filter by subject
        :param from_filter: {str} Filter by sender
        :param recipient_filter: {str} Filter by recipient
        :param mark_all_matching_emails: {bool} Mark all suitable messages or only the first
        :param time_filter: {datetime} Filter by time
        :return: {list} List of MessageData objects
        """
        account = self.account if mailbox_address == self.account.primary_smtp_address else self._create_account_obj(
            mailbox_address,
            self.config,
            IMPERSONATION
        )

        all_messages = []
        limit = 1 if not mark_all_matching_emails else None
        operation = JUNK_OPERATIONS.get("junk") if is_junk else JUNK_OPERATIONS.get("not_junk")

        for folder_name in folder_names:
            try:
                messages = self.receive_mail(folder_name=folder_name,
                                             message_id=message_id,
                                             subject_filter=subject_filter,
                                             from_filter=from_filter,
                                             recipient_filter=recipient_filter,
                                             time_filter=time_filter,
                                             limit=limit,
                                             account=account)

                for message in messages:
                    message.mark_as_junk(is_junk, move_items)

                all_messages.extend(
                    [self.parser.get_message_data(self.message_object_to_dict(message, True), True)
                     for message in messages]
                )

                if messages:
                    self.logger.info(
                        f"Marked emails as {operation} in folder={folder_name} with message_id={message_id}, "
                        f"subject_filter={subject_filter}, from_filter={from_filter}, "
                        f"recipient_filter={recipient_filter}"
                    )
                else:
                    self.logger.info(
                        f"Failed to mark emails as {operation} in folder={folder_name} with message_id={message_id}, "
                        f"subject_filter={subject_filter}, from_filter={from_filter}, "
                        f"recipient_filter={recipient_filter}"
                    )

            except Exception as e:
                self.logger.error(f"Couldn't mark emails as {operation} in folder={folder_name} with "
                                  f"message_id={message_id}, subject_filter={subject_filter}, "
                                  "from_filter={from_filter}, recipient_filter={recipient_filter}")
                self.logger.exception(e)

        return all_messages

    def create_account_objects_from_mailboxes(self, mailboxes):
        """
        Create exchange account instances from mailboxes
        :param mailboxes: {list} The list of mailboxes
        :return: {tuple} List of Account objects and list of failed mailboxes
        """
        accounts, failed_mailboxes = [], []

        for mailbox in mailboxes:
            try:
                accounts.append(
                    self.account if mailbox == self.account.primary_smtp_address
                    else self._create_account_obj(mailbox, self.config, IMPERSONATION)
                )
            except Exception as e:
                self.logger.info(f"Failed to access {mailbox} mailbox. Reason is - {e}")
                failed_mailboxes.append(mailbox)

        return accounts, failed_mailboxes

    def get_rules_by_names(self, mailbox, rules_names):
        """
        Get mailbox rules by names
        :param mailbox: {str} The mailbox to get rules
        :param rules_names: {list} The list of rules names
        :return: {list} The list of Rule objects
        """
        rules = [self.parser.build_rule_object(rule) for rule in self.account.get_rules(mailbox)]
        return [rule for rule in rules if rule.name in rules_names] if rules else []

    def add_items_to_rule(self, account, rule_name, condition, action, items, parent_rule_items, rule=None):
        """
        Add provided items to Rule, if rule not found create new rule
        :param account: {Account} The account to perform changes
        :param rule_name: {str} The rule name
        :param condition: {str} The condition of rule
        :param action: {str} The action of rule
        :param items: {list} The list of items to update rule with
        :param parent_rule_items: {list} The list of current account corresponding rule items
        :param rule: {Rule} The Rule object
        :return: {bool} True if successful, exception otherwise
        """
        items = list(set(map(lambda item: item.lower(), parent_rule_items + items)))

        if not rule:
            self.logger.info(f"{rule_name} rule doesn't found in {account.primary_smtp_address} mailbox. "
                             f"New rule will be created")
            account.create_rule(rule_name, condition, action, items)
        else:
            account.update_rule(rule.id, rule_name, condition, action, items)

        return True

    def remove_items_from_rule(self, account, rule_name, condition, action, items, parent_rule_items, rule=None):
        """
        Remove provided items from Rule
        :param account: {Account} The account to perform changes
        :param rule_name: {str} The rule name
        :param condition: {str} The condition of rule
        :param action: {str} The action of rule
        :param items: {list} The list of items to remove from rule
        :param parent_rule_items: {list} The list of current account corresponding rule items
        :param rule: {Rule} The Rule object
        :return: {bool} True if successful, exception otherwise
        """
        items = [item for item in parent_rule_items if item.lower() not in items]

        if not rule:
            self.logger.info(f"{rule_name} rule doesn't found in {account.primary_smtp_address} mailbox.")
            return True

        if not items:
            self.logger.info(f"{rule.name} rule doesn't contain any items in {account.primary_smtp_address} mailbox. "
                             f"It will be deleted.")
            account.delete_rule(rule.id)
        else:
            account.update_rule(rule.id, rule.name, condition, action, items)

        return True

    def delete_rule(self, account, rule_id):
        """
        Delete rule from mailbox
        :param account: {Account} The account to perform changes
        :param rule_id: {str} The rule id
        :return: {bool} True if successful, exception otherwise
        """
        account.delete_rule(rule_id)
        return True
