# ============================================================================#
# title           :JiraCommon.py
# description     :This Module contain all common Jira operations functionality
# author          :avital@siemplify.co
# date            :29-07-2019
# python_version  :2.7 (except 2.7.13 - ctypes bug)
# libraries       :
# requirements    :
# product_version :1.0
# ============================================================================#

# ============================= IMPORTS ===================================== #
import uuid
import datetime
import json
import os
import pytz
from SiemplifyConnectors import CaseInfo
from SiemplifyUtils import utc_now, convert_datetime_to_unix_time, convert_string_to_unix_time, \
    convert_string_to_datetime
from TIPCommon import dict_to_flat

# ============================== CONSTS ===================================== #

PRODUCT = VENDOR = "Atlassian"
RULE_GENERATOR = DEFAULT_NAME = 'Jira'
MSG_ID_ERROR_MSG = "Can't get issue key"

JIRA_TIME_FORMAT = '%Y/%m/%d %H:%M'
FILE_IDS_HOURS_LIMIT = 24
IDS_FILE = "ids.json"
IDS_LIMIT = 10000
SPLIT_CHAR = ","

CRITICAL_PRIORITY = 100
HIGH_PRIORITY = 80
MEDIUM_PRIORITY = 60
LOW_PRIORITY = 40
PRIORITY_MAPPING = {'High': HIGH_PRIORITY, 'Medium': MEDIUM_PRIORITY, 'Low': LOW_PRIORITY, 'Highest': CRITICAL_PRIORITY}

# ============================= CLASSES ===================================== #


class JiraCommon(object):
    def __init__(self, connector_scope, jira_manager, max_tickets_per_cycle):
        self.connector_scope = connector_scope
        self.jira_manager = jira_manager
        self.logger = connector_scope.LOGGER
        self.max_tickets_per_cycle = max_tickets_per_cycle
        self.ids_file_path = os.path.join(self.connector_scope.run_folder, IDS_FILE)

    @staticmethod
    def validate_timestamp(last_run_timestamp, offset):
        """
        Validate timestamp in range
        :param last_run_timestamp: {datetime} last run timestamp
        :param offset: {datetime} last run timestamp
        :return: {datetime} if first run, return current time minus offset time, else return timestamp from file
        """
        current_time = utc_now()
        # Check if first run
        if current_time - last_run_timestamp > datetime.timedelta(days=offset):
            return current_time - datetime.timedelta(days=offset)
        else:
            return last_run_timestamp

    def get_existing_ids(self):
        """
        Read existing alerts IDs from ids file.
        :return: {list} of the ids
        """
        if not os.path.exists(self.ids_file_path):
            return []

        try:
            with open(self.ids_file_path, 'r') as f:
                return json.loads(f.read())
        except Exception as e:
            self.logger.error("Unable to read ids file: {}".format(str(e)))
            self.logger.exception(e)
            return []

    def write_ids(self, ids):
        """
        Write ids to the ids file
        :param ids: {list} The ids to write to the file
        """
        if not os.path.exists(os.path.dirname(self.ids_file_path)):
            os.makedirs(os.path.dirname(self.ids_file_path))

        # Save last 10,000 pulled tickets
        if len(ids) >= IDS_LIMIT:
            ids = ids[-IDS_LIMIT:]
        try:
            with open(self.ids_file_path, 'w') as f:
                f.write(json.dumps(ids))
        except Exception as e:
            self.logger.error("Failed to write Jira issues ids")
            self.logger.exception(e)

    def get_issues(self, last_run, project_name, labels, assign_users, issue_types, issue_priorities, issue_components, issue_statuses, is_test=False):
        """
        Get tickets from Jira since last success time.
        :param last_run: {datetime} last run timestamp
        :param project_name: {list} jira project name
        :param labels: {list} issue's labels
        :param assign_users: {list} assignee name
        :param issue_types: {list} issue type name
        :param issue_priorities: {list} issue's priority
        :param issue_components: {list} issue's components:
        :param issue_statuses: {list} issue's status
        :param is_test: {boolean} Save all ids list to file if not test.
        :return: {list} of found tickets {Issues Objects}
        """

        server_info = self.jira_manager.get_server_info()
        server_time = server_info.get("serverTime")
        # here we need only server time zone, thus it's ok to get tz from buildDate
        if server_time:
            server_time = convert_string_to_datetime(server_time)
        else:
            server_time = server_info.get("buildDate")
            if server_time:
                server_time = convert_string_to_datetime(server_time)
            else:
                self.logger.error("'serverTime' or 'buildDate' couldn't be found from server info")
                return []
        self.logger.info("JIRA server time: {}".format(server_time.isoformat()))
        # Convert last_run from UTC to JIRA server's timezone, as JIRA doesn't support timezone in the JQL query
        # and searches in the server's timezone.
        self.logger.info("Converting last run {} to server timezone.".format(last_run.isoformat()))
        last_run = last_run.replace(tzinfo=pytz.utc).astimezone(server_time.tzinfo)
        # Jira valid formats include: 'yyyy/MM/dd HH:mm', 'yyyy-MM-dd HH:mm', 'yyyy/MM/dd', 'yyyy-MM-dd'
        self.logger.info("Converted time: {}".format(last_run.isoformat()))
        last_time_jira = last_run.strftime(JIRA_TIME_FORMAT)

        tickets = []
        update_tickets = []

        try:
            # Get tickets base on filters
            # Ticket order - the first ticket is the newest ticket (base on creation time)
            tickets = self.jira_manager.list_issues(project_key_list=project_name, updated_from=last_time_jira,
                                                    assignee_list=assign_users, issue_type_list=issue_types,
                                                    priority_list=issue_priorities, labels_list=labels,
                                                    components_list=issue_components, only_keys=False, status_list=issue_statuses)
            # Sort tickets so the first will be the oldest ticket that was updated
            tickets = sorted(tickets, key=lambda ticket: ticket.fields.updated)

        except Exception as e:
            self.logger.error("Failed to fetch issues keys")
            self.logger.exception(e)

        # Read already existing alerts ids
        old_ids = self.get_existing_ids()

        # Check if ticket is not in old ids
        for ticket in tickets:
            if ticket.key not in old_ids:
                update_tickets.append(ticket)

        self.logger.info("Found {0} issues since {1}.".format(len(update_tickets), str(last_time_jira).encode('utf-8')))
        # Slicing
        update_tickets = update_tickets[:self.max_tickets_per_cycle]
        self.logger.info("Slicing to {0} issues".format(len(update_tickets)))

        # Save all ids list to file
        old_ids.extend([issue.key for issue in update_tickets])
        if not is_test:
            self.write_ids(old_ids)

        return update_tickets

    @staticmethod
    def is_empty_value(value):
        """
        Check whether a value is empty (keep 0 values)
        :param value: The value to check
        :return: True if value is empty, False otherwise
        """
        if not isinstance(value, str):
            return value is None

        return value.isspace() or value == "" or value == "None"

    def create_issue_event(self, ticket_object):
        """
        Create events from issue data
        :param ticket_object: {Issue Object} All ticket data
        :return: event {dict} one event from the issue data
        """
        self.logger.info("Creating Case for Issue {}".format(ticket_object.key))
        event_details = dict_to_flat(ticket_object.raw['fields'])
        try:
            # Remove empty keys (empty strings, keep 0 values)
            event_details = dict([(key, value) for key, value in list(event_details.items()) if not self.is_empty_value(value)])
        except Exception as e:
            self.logger.error("Failed to remove empty fields. Error message: {}".format(str(e)))
            self.logger.exception(e)
            # Add issue key to event details
        event_details.update({'Issue Key': ticket_object.key})

        return event_details

    @staticmethod
    def map_priority(jira_priority):
        """
        Mapping Jira priority to siemplify priority
        :param jira_priority: {string} (Highest, High, Medium, Low)
        :return: {int} (40=low, 60=medium, 80=high, 100=critical)
        """
        return PRIORITY_MAPPING.get(jira_priority, LOW_PRIORITY)

    def create_case_info(self, ticket_object, events, connector_environment, use_jira_as_env=True):
        """
        Get alerts from Issues
        :param ticket_object: {Issue Object} An issue data
        :param events: {list} The events
        :param connector_environment:
        :param use_jira_as_env: {Boolean}   use jira project name as a environment
                                            or use default environment name
        :return: {CaseInfo} case
        """
        case_info = CaseInfo()

        # Validate issue key exists
        try:
            ticket_key = ticket_object.key
        except Exception as e:
            ticket_key = '{0}-{1}'.format(MSG_ID_ERROR_MSG, str(uuid.uuid4()))
            self.logger.error("Found issue, cannot get its key. {0}".format(str(e)))
            self.logger.exception(e)

        # Create the CaseInfo
        try:
            try:
                case_info.name = ticket_object.key
            except Exception as e:
                self.logger.error("{0}. {1}".format(MSG_ID_ERROR_MSG, e))
                case_info.name = DEFAULT_NAME

            try:
                project_name = ticket_object.raw['fields'].get('project', {}).get('name')
            except Exception as e:
                self.logger.error("Failed to get ticket project.")
                self.logger.exception("Error: {0}".format(e))
                project_name = connector_environment

            # Rule Generator set to Jira-ProjectName
            case_info.rule_generator = '{0}-{1}'.format(RULE_GENERATOR, project_name)

            # save time in unix (milliseconds).
            case_info.start_time = convert_string_to_unix_time(ticket_object.raw['fields'].get('created')) if \
                ticket_object.raw['fields'].get('created') else 1
            case_info.end_time = convert_string_to_unix_time(ticket_object.raw['fields'].get('updated')) if \
                ticket_object.raw['fields'].get('updated') else 1

            case_info.identifier = ticket_key
            case_info.ticket_id = case_info.identifier
            # Priority mapped from jira values to siemplify values
            case_info.priority = self.map_priority(ticket_object.raw['fields'].get('priority', {}).get('name', LOW_PRIORITY))
            case_info.device_vendor = VENDOR
            case_info.device_product = PRODUCT
            case_info.display_id = case_info.identifier

            # Connector environment set to the project name
            if use_jira_as_env:
                case_info.environment = project_name
            else:
                case_info.environment = connector_environment

            case_info.events = events

        except KeyError as e:
            raise KeyError("Mandatory key is missing: {}. Skipping Issue.".format(str(str(e).encode('utf-8'))))

        return case_info