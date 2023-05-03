import email
import imaplib
from emaildata.text import Text
from emaildata.metadata import MetaData
from emaildata.attachment import Attachment
import hashlib
from urlparse import urlparse
from SiemplifyConnectors import *
from copy import deepcopy
import uuid
import re
import os
from SiemplifyUtils import output_handler
from EmailCommon import FILE_NAME_EVENT_FIELD_PATTERN, FILE_MD5_EVENT_FIELD_PATTERN, URLS_REGEX


# =====================================
#             Configuration           #
# =====================================
SERVER_IP = "imap.gmail.com"
DOMAIN = "Siemplify.co"
USERNAME = "org@siemplify.co"
PASSWORD = "********"


# =====================================
#              CONSTANTS              #
# =====================================
DEVICE_PRODUCT = "Mail"
VENDOR = "Any"
DEFAULT_CASE_NAME = "Monitored Mailbox <{0}>".format(USERNAME)
IMAP_PORT = 143
IMAP_SSL_PORT = 993


# =====================================
#               Classes               #
# =====================================
class ImapMailFetcher(object):
    def __init__(self, server_ip, username, password, ssl=True, port=None):
        if ssl:
            imap_port = port or IMAP_SSL_PORT
            self.conn = imaplib.IMAP4_SSL(server_ip, port=imap_port)
        else:
            imap_port = port or IMAP_PORT
            self.conn = imaplib.IMAP4(server_ip, port=imap_port)
        # Connect using creds
        self.conn.login(username, password)

    @staticmethod
    def set_proxy(proxy_server_address, proxy_username=None,
                  proxy_password=None):
        """
        Configure proxy
        :param proxy_server_address: {str} The proxy server address
        :param proxy_username: {str} Proxy username
        :param proxy_password: {str} Proxy password
        """
        server_url = urlparse(proxy_server_address)

        scheme = server_url.scheme
        hostname = server_url.hostname
        port = server_url.port

        credentials = ""
        if proxy_username and proxy_password:
            credentials = "{0}:{1}@".format(proxy_username, proxy_password)

        proxy_str = "{0}://{1}{2}".format(scheme, credentials, hostname)

        if port:
            proxy_str += ":{0}".format(str(port))

        os.environ[
            'http_proxy'] = proxy_str  # http://<user>:<pass>@<proxy>:<port>
        os.environ[
            'https_proxy'] = proxy_str  # https://<user>:<pass>@<proxy>:<port>
        os.environ['proxy'] = "on"

    def fetch_mails_from_account(self, folder='inbox', only_unread=True):
        messages = []
        self.conn.select(folder)
        if only_unread:
            result, data = self.conn.search(None, "UNSEEN")
        else:
            result, data = self.conn.search(None, "ALL")
        ids = data[0]
        msg_ids_list = ids.split()
        for msg_id in msg_ids_list:
            result, data = self.conn.fetch(msg_id, "(RFC822)")
            raw_email = data[0][1]
            email_message = email.message_from_string(raw_email)
            # Delete Mail from inbox
            #self.conn.store(msg_id, '+FLAGS', '\\Deleted')
            #self.conn.expunge()
            # TODO: Remove if not necessary
            extractor = MetaData(email_message)
            mail_dict = extractor.to_dict()
            messages.append(email_message)
        return messages


class RegexExecuter(object):
    DEFAULT_REGEX_MAP = {"Urls": URLS_REGEX,
                         "Phones": "(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})"}

    def __init__(self, regex_map=None):
        if regex_map:
            self.regex_map = regex_map
        else:
            self.regex_map = self.DEFAULT_REGEX_MAP

    def extract_event_details(self, content):
        resultDictionary = {}
        for key in self.regex_map:
            regex = self.regex_map[key]
            regexObject = re.compile(regex)
            allResults = regexObject.findall(content)
            if allResults:
                resultDictionary[key] = ", ".join([item.strip("<>") for item in allResults])
        return resultDictionary


class EmlFileHandler(object):
    EML_EXTENSION = ".eml"
    def extract_eml_message_from_messages_attachments(self, messages):
            eml_messages = []
            for email_message in messages:
                for content, filename, mimetype, message in Attachment.extract(email_message):
                    if os.path.splitext(filename)[1] == self.EML_EXTENSION:
                        email_message = email.message_from_string(content)
                        # TODO: Remove if not necessary
                        extractor = MetaData(email_message)
                        mail_dict = extractor.to_dict()
                        eml_messages.append(email_message)
            return eml_messages

    def email_to_event_with_attachments(self, email_message):
        extractor = MetaData(email_message)
        mail_dict = extractor.to_dict()
        event_details = {}
        event_details['Subject'] = mail_dict['subject']
        event_details['From'] = mail_dict['sender']
        event_details['To'] = ";".join(mail_dict['to'])
        event_details['managerReceiptTime'] = event_details['StartTime'] = event_details['EndTime'] = mail_dict['timestamp']
        email_body = Text.text(email_message)
        # Clear non ascii chars
        event_details['Body'] = email_body.strip()
        event_details['device_product'] = DEVICE_PRODUCT
        event_details['Name'] = DEFAULT_CASE_NAME
        event_details['MessageId'] = mail_dict['message_id'].strip("<>")
        # Extract mail address suffix for tanent
        event_details['Environment'] = event_details['From'].split(".")[-1]
        # Extract Attachments
        for index, (content, filename, mimetype, message) in enumerate(Attachment.extract(email_message)):
            event_details[FILE_NAME_EVENT_FIELD_PATTERN.format(index + 1)] = filename
            event_details[FILE_MD5_EVENT_FIELD_PATTERN.format(index + 1)] = hashlib.md5(content).hexdigest()
        return event_details


class CaseBuilder(object):
    @classmethod
    def BuildCaseFromResults(cls, event_details, name, vendor, device_product, identifier=None):
        event = deepcopy(event_details)

        case_info = CaseInfo()

        case_info.name = name
        case_info.rule_generator = name
        case_info.start_time = event["StartTime"]
        case_info.end_time = event["EndTime"]
        case_info.identifier = identifier if identifier is not None else str(uuid.uuid4())
        case_info.ticket_id = case_info.identifier
        case_info.priority = 40  # Defaulting to Low - can add logic here to set priority based on event data.
        case_info.device_vendor = vendor
        case_info.device_product = device_product
        case_info.source_system_name = "Custom"
        case_info.display_id = case_info.identifier
        case_info.environment = event_details['Environment']
        case_info.events = [event]

        return case_info

@output_handler
def main():
    output_variables = {}
    log_items = []
    cases = []
    connector_scope = SiemplifyConnectorExecution()

    mail_connector = ImapMailFetcher(SERVER_IP, USERNAME, PASSWORD)
    eml_handler = EmlFileHandler()

    mails = mail_connector.fetch_mails_from_account()
    emls_mail_objs = eml_handler.extract_eml_message_from_messages_attachments(mails)
    for msg in emls_mail_objs:
        event_details = eml_handler.email_to_event_with_attachments(msg)
        # Extract details from message body using regex
        event_details.update(RegexExecuter().extract_event_details(event_details['Body']))
        case = CaseBuilder.BuildCaseFromResults(event_details, DEFAULT_CASE_NAME, VENDOR, DEVICE_PRODUCT,
                                                identifier=event_details['MessageId'])
        case.description = "Auto mail fetcher connector"
        cases.append(case)

    connector_scope.return_package(cases, output_variables, log_items)


if __name__ == '__main__':
    main()
