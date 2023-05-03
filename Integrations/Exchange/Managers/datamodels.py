from datetime import datetime
from SiemplifyUtils import add_prefix_to_dict
from constants import ENRICHMENT_TABLE_PREFIX
import json
from constants import PARAMETERS_DEFAULT_DELIMITER, ACTION_NAMES
from TIPCommon import dict_to_flat


class BaseModel():
    """
    Base model for inheritance
    """
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data


class MailData(BaseModel):
    def __init__(self, raw_data, message_id, sent_date):
        super(MailData, self).__init__(raw_data)
        self.message_id = message_id
        self.email_date = int(datetime.timestamp(sent_date))

    def to_json(self):
        json_data = {}
        for key, value in self.raw_data.FIELDS._dict.items():
            json_data[key] = getattr(self.raw_data, key)

        json_data['email_date'] = self.email_date
        return json_data


class MessagesData(BaseModel):
    def __init__(self, raw_data, results):
        super(MessagesData, self).__init__(raw_data)
        self.results = results


class MessageData(BaseModel):
    def __init__(self, raw_data, message_id, datetime_received, author, to_recipients, subject, body, attachments_list,
                 account, set_account, sender):
        super(MessageData, self).__init__(raw_data)
        self.message_id = message_id
        self.datetime_received = datetime_received
        self.author = author
        self.to_recipients = to_recipients
        self.subject = subject
        self.body = body
        self.attachments_list = attachments_list
        self.account = account
        self.set_account = set_account
        self.sender = sender

    def to_table(self):
        attachment_names = [file_name for file_name, file_content in list(self.attachments_list.items()) if file_name]

        table_data = {
            'Message_id': self.message_id,
            'Received Date': self.datetime_received,
            'Sender': self.author,
            'Recipients': PARAMETERS_DEFAULT_DELIMITER.join(self.to_recipients),
            'Subject': self.subject,
            'Email body': self.body,
            'Attachment names': PARAMETERS_DEFAULT_DELIMITER.join(attachment_names)
        }

        if self.set_account:
            table_data['Found in mailbox'] = self.account

        return dict_to_flat(table_data)

    def to_shorthand_json(self):
        return {
            'message_id': self.message_id,
            'sender': self.sender,
            'datetime_received': self.datetime_received,
            'to_recipients': self.to_recipients,
            'subject': self.subject
        }


class AttachmentData():
    def __init__(self, attachment_name, downloaded_path):
        self.attachment_name = attachment_name
        self.downloaded_path = downloaded_path

    def to_json(self):
        return {
           "attachment_name": self.attachment_name,
           "downloaded_path": self.downloaded_path
        }



class SiemplifyOOF(BaseModel):
    def __init__(self, raw_data, end, external_audience, external_reply, internal_reply, start, state):
        super(SiemplifyOOF, self).__init__(raw_data)
        self.end = end
        self.external_audience = external_audience
        self.external_reply = external_reply
        self.internal_reply = internal_reply
        self.start = start
        self.state = state

    def to_json(self):
        json_data = {}
        for key, value in self.raw_data.FIELDS._dict.items():
            json_data[key] = getattr(self.raw_data, key)

        return json_data

    def to_csv(self):
        """
        Function that prepares the dict containing user's data
        :return {dict} Dictionary containing user's data
        """
        return {
            "End": self.end,
            "External Audience": self.external_audience,
            "External Reply": self.external_reply,
            "Internal Reply": self.internal_reply,
            "Start": self.start,
            "State": self.state
        }

    def to_table(self):
        """
        Function that prepares the user's data to be used on the table
        :return {list} List containing dict of user's data
        """
        return [self.to_csv()]

    def to_enrichment_data(self):
        enrichment_data = {}

        if self.state:
            enrichment_data['oof_settings'] = self.state
            enrichment_data = add_prefix_to_dict(enrichment_data, ENRICHMENT_TABLE_PREFIX)

        return enrichment_data


class Rule(BaseModel):
    def __init__(self, raw_data, id, name, priority, is_enabled, conditions, actions):
        super(Rule, self).__init__(raw_data)
        self.id = id
        self.name = name
        self.priority = priority
        self.is_enabled = is_enabled
        self.conditions = conditions
        self.actions = actions

    def to_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "priority": self.priority,
            "is_enabled": self.is_enabled,
            "conditions": self.conditions.to_json(),
            "actions": self.actions.to_json()
        }


class Conditions(BaseModel):
    def __init__(self, raw_data, domains, addresses):
        super(Conditions, self).__init__(raw_data)
        self.domains = domains
        self.addresses = addresses

    def to_json(self):
        return {
            "domains": self.domains,
            "addresses": [address.email_address or address.name for address in self.addresses]
        }


class Address(BaseModel):
    def __init__(self, raw_data, name, email_address, routing_type, mailbox_type, item_id):
        super(Address, self).__init__(raw_data)
        self.name = name
        self.email_address = email_address
        self.routing_type = routing_type
        self.mailbox_type = mailbox_type
        self.item_id = item_id


class Actions(BaseModel):
    def __init__(self, raw_data, move_to_folder, delete, permanent_delete):
        super(Actions, self).__init__(raw_data)
        self.move_to_folder = move_to_folder
        self.delete = delete
        self.permanent_delete = permanent_delete

    def to_json(self):
        return [ACTION_NAMES[key] for key, value in self.__dict__.items() if value and ACTION_NAMES.get(key)]
