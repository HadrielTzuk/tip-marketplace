from arrow import get as arrow_get
from enum import Enum
from hashlib import md5 as hashlib_md5
import uuid

ORIGINAL_EMAIL_EVENT_NAME = "Email Received in Monitoring Mailbox"
ATTACHED_EMAIL_EVENT_NAME = "Attached Email File"


class SiemplifyPriorityEnum(Enum):
    INFO = -1
    LOW = 40
    MEDIUM = 60
    HIGH = 80
    CRITICAL = 100


class EmailModel(object):
    """
    Data Model representing Email object
    """
    FWD_KEYS = ('fwd:', 'fw:')
    FWD_BODY_TOKENS = ('---------- Forwarded message ---------',)
    DEFAULT_EVENT_TYPE = "Mailbox Alert"
    DEFAULT_VENDOR = "Mail"
    DEFAULT_PRODUCT = "Mail"
    DEFAULT_SENDER = "Message Has No Sender"
    DEFAULT_RECIPIENT = "Message Has No Recipients"
    DEFAULT_DELIMITER = ";"

    def __init__(self,
                 email_uid=None,
                 message_id=None,
                 mailbox=None,
                 subject=None,
                 original_sender=None,
                 senders=None,
                 original_recipient=None,
                 recipients=None,
                 cc=None,
                 bcc=None,
                 environment=None,
                 email_date=None,
                 email_date_aware=None,
                 body=None,
                 text_body=None,
                 html_body=None,
                 original_message=None,
                 original_message_id=None,
                 reply_to=None,
                 answer=None,
                 attachments=None,
                 urls=None,
                 extra_data=None,
                 attached_emails=None,
                 event_name=None,
                 encoding="utf-8"):
        """
        Base constructor
        :param email_uid: {str} Sequential ID of emails on the IMAP server. Note that IMAP recalculates these after such operations like email deletions and etc. So it's not very reliable
        :param message_id: {str} Unique email ID
        :param mailbox: {str} Email address of the mailbox, from which we have extracted this email
        :param subject: {str} Email subject
        :param senders: {list} List of email senders. It's a list and not str, because there are scenarios for forwarded emails, where it might be important to extract all emails used in the whole chain of forwards.
        :param recipients: {list} List of email recipients
        :param cc: {list} List of email addresses in CC
        :param bcc: {list} List of email addresses in BCC
        :param environment: {str} Name of the environment, monitored while this email extraction
        :param email_date: {datetime} Email timestamp as a datetime
        :param email_date_aware: {datetime} Email aware datetime
        :param text_body: {str} Text representation of the email. Main difference with html_body - conventionally it should not contain HTML tags.
        :param html_body: {str} Email body in HTML format
        :param original_message: {str} Original email as a string
        :param original_message_id: {str} Original email id
        :param reply_to: {str} message_id of original email, on which has responded with current email
        :param answer: {str} Text of the answer to original email
        :param attachments: {list} List of EmailAttachmentModel objects representing email attachments
        :param urls: {dict} Dictionary of urls found in email body (format: unique_url_name, url)
        :param extra_data: {dict} Dictionary with all additional data, which may dynamically appear
        :param attached_emails: {list} By requirements all *.eml and *.msg emails from the attachments should be saved in the case as separate events. Here we may store nested emails
        :param event_name: {str} Alert name
        """
        self.email_uid = email_uid
        self.message_id = message_id
        self.mailbox = mailbox
        self.original_subject = subject
        self.subject = subject
        self.original_recipient = original_recipient
        self.recipients = recipients
        if self.recipients is None:
            self.recipients = list()
        self.original_sender = original_sender
        self.senders = senders
        if self.senders is None:
            self.senders = list()
        self.environment = environment
        self.cc = cc
        if self.cc is None:
            self.cc = list()
        self.bcc = bcc
        if self.bcc is None:
            self.bcc = list()
        self.receivers = [*self.recipients, *self.cc, *self.bcc]
        self.email_date = email_date
        self.email_date_aware = email_date_aware
        self.html_body = html_body
        self.text_body = text_body
        self.text_body = text_body
        self.body = body
        self.original_message = original_message
        self.original_message_id = original_message_id
        self.event_name = event_name
        self.answer = answer
        self.reply_to = reply_to
        self.attachments = attachments
        if not self.attachments:
            self.attachments = list()
        self.urls = urls
        if not self.urls:
            self.urls = dict()
        self.extra_data = extra_data
        if not self.extra_data:
            self.extra_data = dict()
        self.attached_emails = attached_emails
        if not self.attached_emails:
            self.attached_emails = list()
        self.encoding = encoding
        self.extracted_headers = {}

    @property
    def is_forward(self):
        """
        Property indicating if current email has been forwarded or not
        :return: {bool} True - email has been forwarded; False - Otherwise
        """
        if self.subject and self.subject.lower().startswith(self.FWD_KEYS):
            return True
        for token in self.FWD_BODY_TOKENS:
            if self.text_body and token in self.text_body:
                return True
        return False

    @property
    def unixtime_date(self):
        """
        Property returning email timestamp in POSIX format
        :return: {int} Email timestamp in POSIX format
        """
        return arrow_get(self.email_date).timestamp * 1000 if self.email_date else 1

    @property
    def last_email_sender(self):
        """
        Read-only property providing last email from the From list
        :return: {str} Email address of the last sender
        """
        if self.senders and len(self.senders) > 0:
            return self.senders[-1]
        else:
            return None

    @property
    def last_email_recipient(self):
        """
        Read-only property providing last email from the To list
        :return: {str} Email address of the last receiver
        """
        if self.recipients and len(self.recipients) > 0:
            return self.recipients[-1]
        else:
            return None

    def to_dict(self, as_event=False, is_original_mail=False):
        """
        Flushes current email instance to dict. Note that this operation is not backward compatible - you won't be able to recover EmailModel object from this dict.
        :param as_event: {bool} Specifies if data will be used as event
        :param is_original_mail: {bool} Specifies if mail is the original one or no
        :return: {dict} Returns key fields of EmailModel() instance as a dict
        """
        posix_date = self.unixtime_date

        email_dict = {
            "email_uid": self.email_uid,
            "message_id": self.message_id,
            "managerReceiptTime": posix_date,
            "start_time": posix_date,
            "end_time": posix_date,
            "environment": self.environment,
            "event_type": self.DEFAULT_EVENT_TYPE,
            "name": "{0}_{1}".format(self.mailbox, posix_date),
            "vendor": self.DEFAULT_VENDOR,
            "device_product": self.DEFAULT_PRODUCT,
            "subject": self.subject,
            "from": self.__get_sender(),
            "to": self.__get_recipient(),
            "receivers": ','.join(self.receivers),
            "html_body": self.html_body,
            "text_body": self.text_body,
            "body": self.body,
            "reply_to": self.reply_to,
            "original_message": self.original_message,
            "original_message_id": self.original_message_id,
            "event_name": self.event_name,
        }

        if self.cc:
            email_dict["cc"] = self.DEFAULT_DELIMITER.join(self.cc)

        if self.bcc:
            email_dict["bcc"] = self.DEFAULT_DELIMITER.join(self.bcc)

        # Append all URLs as separate email dict items
        for url_name, url in list(self.urls.items()):
            # @TODO check this solution
            email_dict[url_name] = url.decode() if isinstance(url, bytes) else url

        for index, attachment in enumerate(self.attachments, 1):
            file_name = "file_name_{0}".format(index)
            file_md5 = "file_md5_{0}".format(index)

            email_dict[file_name] = attachment.file_name
            email_dict[file_md5] = attachment.md5

        for data_key, data_contents in list(self.extra_data.items()):
            email_dict[data_key] = data_contents

        for header_key, value in list(self.extracted_headers.items()):
            email_dict[header_key] = value

        if self.is_forward:
            email_dict["last_email_sender"] = self.last_email_sender
            email_dict["last_email_recipient"] = self.last_email_recipient

        if as_event:
            email_dict["event_name_mail_type"] = ORIGINAL_EMAIL_EVENT_NAME if is_original_mail else ATTACHED_EMAIL_EVENT_NAME
            email_dict["monitored_mailbox_name"] = self.mailbox

        return email_dict

    def get_trimmed_message_id(self):
        """
        Trims self.message_id, excludes spaces, < and > symbols from it. Otherwise returns new uuid value
        :return: {str} Representing unique email
        """
        return self.message_id.strip(" <>") if self.message_id else str(uuid.uuid4())

    def __get_sender(self):
        if self.last_email_sender:
            return self.last_email_sender

        return self.DEFAULT_SENDER

    def __get_recipient(self):
        if self.is_forward and self.last_email_recipient:
            return self.last_email_recipient
        elif len(self.recipients) > 0:
            return self.DEFAULT_DELIMITER.join(self.recipients)
        else:
            return self.DEFAULT_RECIPIENT


class EmailAttachmentModel(object):
    """
    Data Model representing EmailAttachment object
    """

    def __init__(self, file_name, file_contents):
        """
        Base constructor
        :param file_name: {str} File name including extension
        :param file_contents: {str} Base64 encoded file contents
        """
        self.file_name = file_name
        self.file_contents = file_contents

    @property
    def md5(self):
        """
        Calculates MD5 hash of the file
        :return: {str} String with MD5 hash of the file by it's contents
        """
        return hashlib_md5(self.file_contents).hexdigest()

    def to_dict(self) -> dict:
        """
        Convert EmailAttachmentModel to be represented as dictionary
        :return: {dict} Dictionary of file name as key and file contents as value
        """
        return {self.file_name: self.file_contents}
