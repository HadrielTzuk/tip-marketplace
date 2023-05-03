from TIPCommon import dict_to_flat
from datetime import datetime
import copy
import hashlib
from typing import Dict, List
from constants import TIME_FORMAT


MAX_FILE_SIZE = 15_728_640
DEVICE_PRODUCT = "Graph Mail"
VENDOR = "Microsoft"
ORIGINAL_EMAIL_EVENT_NAME = "Email Received in Monitoring Mailbox"
ATTACHED_EMAIL_EVENT_NAME = "Attached Email File"
EMAIL_LIST_FIELDS = ["toRecipients", "ccRecipients", "bccRecipients", "replyTo"]


class MicrosoftGraphFileAttachment:
    def __init__(self, raw_data, id=None, size=None, contentType=None,
                 name=None, **kwargs):
        self.raw_data = raw_data
        self.id = id
        self.size = size
        self.name = name
        self.content_type = contentType
        self.odata_type = kwargs["@odata.type"]
        self.__content = None

    def as_json(self):
        return self.raw_data

    def md5_hash(self):
        return hashlib.md5(self.content).hexdigest()

    @property
    def content(self):
        return self.__content

    def set_content(self, value: bytes):
        self.__content = value

    @property
    def is_eml(self):
        if self.is_file_attachment:
            return ".eml" in self.name
        return self.content_type == "message/rfc822"

    @property
    def is_ics(self):
        if self.is_file_attachment:
            return ".ics" in self.name
        return self.content_type in ("application/ics", "text/calendar")

    @property
    def is_msg(self):
        if self.is_file_attachment:
            return ".msg" in self.name
        return self.content_type == "application/vnd.ms-outlook"

    # Reference attachments - "#microsoft.graph.referenceAttachment"
    # File attachments - "#microsoft.graph.fileAttachment"
    # Item attachments - "#microsoft.graph.itemAttachment"
    @property
    def is_file_attachment(self):
        return self.odata_type == "#microsoft.graph.fileAttachment"

    @property
    def is_item_attachment(self):
        return self.odata_type == "#microsoft.graph.itemAttachment"

    @property
    def is_to_large(self):
        return self.size > MAX_FILE_SIZE

    def as_event(self):
        event_data = copy.deepcopy(self.raw_data)
        return dict_to_flat(event_data)


class MicrosoftGraphEmail:
    def __init__(self, raw_data, mailbox_name, folder_name, id=None, internetMessageId=None,
                 receivedDateTime=None, body=None, subject=None, hasAttachments=False,
                 internetMessageHeaders=None, parentFolderId=None, **kwargs):
        self.raw_data = raw_data
        self.internet_message_id = internetMessageId
        self.id = id
        self.received_date_time = receivedDateTime
        self.body = body or {}
        self.subject = subject
        self.has_attachments = hasAttachments
        self.internet_message_headers = internetMessageHeaders or []
        self.folder_id = parentFolderId
        self.mailbox_name = mailbox_name
        self.folder_name = folder_name
        self.ics_attachments = []
        self.eml_attachments = []
        self.msg_attachments = []
        self.file_attachments = []

    @property
    def body_content(self):
        return self.body.get("content")

    # We set only Item and File attachments as an actual attachments to be processed for the case
    # It's not clear whether it's a correct strategy, but seems Reference attachments doesn't have
    # Enough data to further process them
    def set_attachments(self, attachments: List[MicrosoftGraphFileAttachment]):
        for att in attachments:
            if att.is_ics:
                self.ics_attachments.append(att)
            elif att.is_eml:
                self.eml_attachments.append(att)
            elif att.is_msg:
                self.msg_attachments.append(att)
            elif att.is_file_attachment and att.content is not None:
                self.file_attachments.append(att)

    def as_json(self):
        return self.raw_data

    def as_alert(self):
        pass

    def create_event(self, additional_info: Dict = None, attachment_data: Dict = None,
                     headers_to_add_to_events: List[str] = tuple()):
        """
        Create an event from an eml content.
        :param additional_info: {dict} Additional event info (parsed urls, e.t.c)
        :param attachment_data {Dict} Passed if event is created for attachment
        :param headers_to_add_to_events {List} which headers to include in the event data
        :return: {dict} event dict.
        """
        event_data = copy.deepcopy(self.raw_data if attachment_data is None else attachment_data)
        for field in EMAIL_LIST_FIELDS:
            if field in event_data:
                for index, email_dict in enumerate(event_data[field]):
                    iterable_unpacked = email_dict.get("emailAddress", {}).items()
                    for field_name, field_value in iterable_unpacked:
                        event_data[f"{field}_emailAddress_{field_name}_{index + 1}"] = field_value
                del event_data[field]

        if headers_to_add_to_events:
            filtered_headers = [
                header_dict for header_dict in self.internet_message_headers if
                header_dict["name"] in headers_to_add_to_events
            ] if headers_to_add_to_events[0] != 'None' else []
            event_data["internetMessageHeaders"] = filtered_headers

        existing_headers = event_data.get("internetMessageHeaders", [])
        if existing_headers:
            headers_formatted = {}
            for header in existing_headers:
                headers_formatted[header["name"]] = (
                        headers_formatted.get(header["name"], []) +
                        [header["value"], ]
                )
            event_data["internetMessageHeaders"] = headers_formatted

        event_data.update(additional_info or {})
        flat_event_data = dict_to_flat(event_data)

        flat_event_data['device_product'] = DEVICE_PRODUCT
        flat_event_data['device_vendor'] = VENDOR
        flat_event_data['event_name'] = ORIGINAL_EMAIL_EVENT_NAME
        flat_event_data['monitored_mailbox_name'] = self.mailbox_name
        flat_event_data['email_folder'] = self.folder_name

        if attachment_data:
            flat_event_data['event_name'] = ATTACHED_EMAIL_EVENT_NAME
            flat_event_data['original_email_id'] = self.id

        return flat_event_data

    @property
    def parsed_time(self):
        return datetime.strptime(self.received_date_time, TIME_FORMAT)

    @property
    def timestamp(self):
        return self.parsed_time.timestamp()


class MicrosoftGraphFolder:
    def __init__(self, id: str, displayName: str):
        self.id = id
        self.display_name = displayName
