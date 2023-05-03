import copy
import uuid

from TIPCommon import dict_to_flat

from JiraConstants import MSG_ID_ERROR_MSG, RULE_GENERATOR, PRODUCT, VENDOR, PRIORITY_MAPPING, LOW_PRIORITY
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import convert_string_to_unix_time
from utils import is_empty_value

class BaseModel(object):
    """
    Base model for inheritance
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

    def as_json(self):
        return self.raw_data


class Issue(BaseModel):
    """
    Jira Issue data model
    """

    class Attachment(BaseModel):
        def __init__(self, raw_data, filename=None, author_account_id=None, created=None, size=None, content_link=None):
            super(Issue.Attachment, self).__init__(raw_data)
            self.author_account_id = author_account_id
            self.filename = filename
            self.created = created
            self.size = size
            self.content_link = content_link

    class Comment(BaseModel):
        def __init__(self, raw_data, created=None, updated=None, body=None, id=None):
            super(Issue.Comment, self).__init__(raw_data)
            self.raw_data = raw_data
            self.created = created
            self.updated = updated
            self.body = body
            self.id = id

            try:
                self.updated_ms = convert_string_to_unix_time(self.updated)
            except:
                self.updated_ms = 1

    def __init__(self, raw_data, id=None, expand=None, raw_fields=None, key=None, project_id=None, project_key=None,
                 project_name=None,
                 project_type_key=None, priority=None, attachments=None, created=None, updated=None, comments=None):
        super(Issue, self).__init__(raw_data)
        self.id = id
        self.expand = expand
        self.raw_fields = raw_fields
        self.key = key

        self.project_id = project_id
        self.project_key = project_key
        self.project_name = project_name
        self.project_type_key = project_type_key

        self.priority = priority
        self.created = created
        self.updated = updated

        self.attachments = attachments or []
        self.comments = comments or []

        try:
            self.created_ms = convert_string_to_unix_time(self.created)
        except:
            self.created_ms = 1

        try:
            self.updated_ms = convert_string_to_unix_time(self.updated)
        except:
            self.updated_ms = 1

    def as_event(self):
        """
        Return issue as Siemplify event
        :return: {dict} Siemplify flatted event
        """
        event_details = dict_to_flat(copy.deepcopy(self.raw_fields))
        try:
            # Remove empty keys (empty strings, keep 0 values)
            event_details = {key: value for key, value in event_details.items() if not is_empty_value(value)}
        except:
            pass
        # Add issue key to event details
        event_details.update({'Issue Key': self.key})
        return event_details

    def get_siemplify_priority(self):
        return PRIORITY_MAPPING.get(self.priority, LOW_PRIORITY)

    def get_alert_info(self, ticket_object, environment_common, logger, use_jira_as_env=True):
        """
        Get alert info
        :param ticket_object: {datamodels.Issue} An issue data
        :param logger: {SiemplifyBase.LOGGER} Siemplify logger
        :param environment_common: {EnvironmentHandle} EnvironmentHandle instance
        :param use_jira_as_env: {Boolean}   Use jira project name as a environment
                                            or use default environment name
        :return: {AlertInfo} AlertInfo
        """
        alert_info = AlertInfo()

        # Validate issue key exists
        try:
            ticket_key = ticket_object.key
            if not ticket_key:
                raise Exception
        except Exception as error:
            ticket_key = '{0}-{1}'.format(MSG_ID_ERROR_MSG, str(uuid.uuid4()))
            logger.error(f"Found issue, cannot get its key. {error}")
            logger.exception(error)

        alert_info.name = ticket_key
        # Rule Generator set to Jira-ProjectName
        alert_info.rule_generator = '{0}-{1}'.format(RULE_GENERATOR,
                                                     self.project_name or environment_common.get_environment(
                                                         self.as_event()))

        alert_info.start_time = self.created_ms
        alert_info.end_time = self.updated_ms
        alert_info.ticket_id = alert_info.display_id = alert_info.identifier = ticket_key
        alert_info.device_vendor = VENDOR
        alert_info.device_product = PRODUCT
        alert_info.priority = self.get_siemplify_priority()
        alert_info.environment = self.project_name if use_jira_as_env else environment_common.get_environment(
            self.as_event())
        alert_info.events = [self.as_event()]

        return alert_info


class ServerInfo(BaseModel):
    """
    Jira server info
    """

    def __init__(self, raw_data, base_url=None, version=None, deployment_type=None, build_number=None, server_time=None,
                 build_date=None):
        super(ServerInfo, self).__init__(raw_data)
        self.base_url = base_url
        self.version = version
        self.deployment_type = deployment_type
        self.build_number = build_number
        self.server_time = server_time
        self.build_date = build_date


class User(BaseModel):
    """
    Jira user
    """

    def __init__(self, raw_data, _self_user: str = None,
                 accountId: str = None,
                 accountType: str = None,
                 avatarUrls: dict = None,
                 displayName: str = None,
                 active: bool = None,
                 locale: str = None,
                 emailAddress: str = None):
        super(User, self).__init__(raw_data)
        self.account_id = accountId
        self.account_type = accountType
        self.avatar_urls = avatarUrls
        self.display_name = displayName
        self.active = active
        self.locale = locale
        self.email_address = emailAddress


class RelationType(BaseModel):
    def __init__(self, raw_data, name, inward, outward):
        super(RelationType, self).__init__(raw_data)
        self.name = name
        self.inward = inward
        self.outward = outward

    def to_table(self):
        return {
            "Name": self.name,
            "Inward": self.inward,
            "Outward": self.outward
        }
