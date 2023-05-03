from SiemplifyUtils import output_handler
# ============================================================================#
# title           :JirsConnector.py
# description     :This Module contain all Jira connector functionality
# author          :zivh@siemplify.co
# date            :31-07-2018
# python_version  :2.7
# ============================================================================#

# ============================= IMPORTS ===================================== #
import sys
from emaildata.text import Text
import email
from emaildata.metadata import MetaData
import arrow
import hashlib
from SiemplifyUtils import utc_now, convert_datetime_to_unix_time, dict_to_flat, convert_string_to_unix_time, \
convert_string_to_datetime
from SiemplifyConnectors import CaseInfo, SiemplifyConnectorExecution
from JiraManager import JiraManager
from JiraCommon import JiraCommon

# ============================== CONSTS ===================================== #
DEFAULT_SUBJECT_TEXT = "Message Has No Subject"

PRODUCT = VENDOR = "Atlassian"
DEFAULT_DAYS_BACKWARDS = 10
MAX_TICKETS_PER_CYCLE = 10
DEFAULT_NAME = 'Jira'
MSG_ID_ERROR_MSG = "Can't get issue key"
MAIL_EXTENSIONS = ['.eml']

SPLIT_CHAR = ","

# ============================= CLASSES ===================================== #


class JiraConnectorException(Exception):
    """
    Jira Connector Exception
    """
    pass


class JiraConnector(object):

    def __init__(self, connector_scope, jira_manager):
        self.connector_scope = connector_scope
        self.logger = connector_scope.LOGGER
        self.jira_manager = jira_manager

    def get_email_attachments(self, file_name, email_content):
        """
        get attachments data from mail
        :param email_content: email data
        :return: {dict} attachments info - name and md5 hash
        """
        # Get attachment name and content from email

        attachments = self.jira_manager.extract_attachments_from_mail(file_name, email_content)

        # Arrange the attachments
        divided_attachments = {}

        self.logger.info("Found {0} attachments".format(len(attachments)))

        for index, attachment in enumerate(attachments, 1):
            for attachment_name, attachment_value in list(attachment.items()):
                try:
                    divided_attachments["file_{0}_name".format(index)] = attachment_name
                    divided_attachments["file_{0}_md5".format(index)] = hashlib.md5(attachment_value).hexdigest()
                    self.logger.info("Found attachment: {}".format(attachment_name))
                except Exception as e:
                    self.logger.error("Cannot process attachment {0}".format(index))
                    self.logger.exception(e)

        return divided_attachments

    @staticmethod
    def get_mail_data(email_content):
        """
        Get mails data using message id
        :param email_content: attachment data - type 'eml'
        :return: {mail object}
        """
        msg = email.message_from_string(email_content)
        extractor = MetaData(msg)
        mail_dict = extractor.to_dict()
        mail_dict['body'] = Text.text(msg)
        return mail_dict

    def create_mail_event(self, email, email_content, file_name):
        """
        Create events from email data
        :param email: {dict} All email data
        :return: event {dict} one event from the email data
        """
        event_details = {}
        event_details['subject'] = email.get('subject') or DEFAULT_SUBJECT_TEXT
        event_details['from'] = email.get('sender') if email.get('sender') else ''
        event_details['to'] = ";".join(email.get('to')) if len(email.get('to')) else ''

        # Email date is in UTC time, save time in unix.
        # * 1000 to convert unix time to millisecond.
        event_details['email_time'] = arrow.get(email.get('date', 1)).timestamp * 1000

        event_details['body'] = email.get('body', '')
        event_details['email_uid'] = email.get('email_uid') if email.get('email_uid') else ''
        event_details['vendor'] = event_details['device_product'] = PRODUCT
        event_details['event_name'] = DEFAULT_NAME
        event_details["managerReceiptTime"] = event_details["StartTime"] = event_details["EndTime"] = event_details[
            "generated_time"] = event_details['email_time']

        # Get mail attachments
        try:
            attachments = self.get_email_attachments(file_name, email_content)
            event_details.update(attachments)
        except Exception as e:
            self.logger.error("An error occurred during extracting the attachments.")
            self.logger.exception(e)
        return event_details


@output_handler
def main(is_test=False):
    connector_scope = SiemplifyConnectorExecution()
    output_variables = {}
    log_items = []
    connector_scope.LOGGER.info("=======Starting Jira Connector.=======")

    try:
        # Configurations.
        api_root = connector_scope.parameters.get('Api Root')
        username = connector_scope.parameters.get('Username')
        api_token = connector_scope.parameters.get('Api Token')
        use_jira_as_env = str(connector_scope.parameters.get('Use Jira Project as Environment', 'true')).lower() == 'true'
        jira_manager = JiraManager(api_root, username, api_token)

        first_run_timestamp = int(connector_scope.parameters.get('Days Backwards')) if connector_scope.parameters.get('Days Backwards') else DEFAULT_DAYS_BACKWARDS
        max_tickets_per_cycle = int(connector_scope.parameters.get('Max Tickets Per Cycle')) if connector_scope.parameters.get('Max Tickets Per Cycle') else MAX_TICKETS_PER_CYCLE

        # Filters
        issue_statuses = connector_scope.parameters.get('Issue Statuses').split(SPLIT_CHAR) if connector_scope.parameters.get('Issue Statuses') else None
        project_names = connector_scope.parameters.get('Project Names').split(SPLIT_CHAR) if connector_scope.parameters.get('Project Names') else None
        assignees = connector_scope.parameters.get('Assignees').split(SPLIT_CHAR) if connector_scope.parameters.get('Assignees') else None
        issue_types = connector_scope.parameters.get('Issue Types').split(SPLIT_CHAR) if connector_scope.parameters.get('Issue Types') else None
        issue_priorities = connector_scope.parameters.get('Issue Priorities').split(SPLIT_CHAR) if connector_scope.parameters.get('Issue Priorities') else None
        issue_components = connector_scope.parameters.get('Issue Components').split(SPLIT_CHAR) if connector_scope.parameters.get('Issue Components') else None
        labels = connector_scope.whitelist
        connector_environment = connector_scope.context.connector_info.environment

        jira_common = JiraCommon(connector_scope, jira_manager, max_tickets_per_cycle)
        jira_connector = JiraConnector(connector_scope, jira_manager)

        # Fix first time run
        last_run_time = connector_scope.fetch_timestamp(datetime_format=True)
        last_calculated_run_time = jira_common.validate_timestamp(last_run_time, first_run_timestamp)
        connector_scope.LOGGER.info(
            "Calculating connector last run time. Last run time is: {0}".format(last_calculated_run_time))

        connector_scope.LOGGER.info("Collecting Tickets")

        tickets = jira_common.get_issues(last_calculated_run_time, project_names, labels, assignees, issue_types,
                                            issue_priorities, issue_components, issue_statuses, is_test)

        cases = []
        events = []
        mail_objects_with_attachments = []

        # Test on one incident only
        if is_test:
            tickets = tickets[:1]

        for ticket in tickets:
            try:
                try:
                    # Get ticket attachment, check format (eml) and parse content
                    connector_scope.LOGGER.info("Collecting Attachments from Tickets")
                    # collect emls files from jira attachments
                    mail_objects_with_attachments = jira_manager.get_attachments_from_issue(ticket.key, extensions=MAIL_EXTENSIONS)
                    connector_scope.LOGGER.info("Found {0} Files for issue {1}".format(len(mail_objects_with_attachments),
                                                                                       str(ticket.key)).encode('utf-8'))
                except Exception as e:
                    connector_scope.LOGGER.error("Failed to get attachments from issue {0}".format(ticket.key))
                    connector_scope.LOGGER.exception(e)

                # Create security event with issue data
                issue_event = jira_common.create_issue_event(ticket)
                events.append(issue_event)

                if mail_objects_with_attachments:
                    for mail_object in mail_objects_with_attachments:
                        # Get mail data
                        mail_file_name = mail_object[0]
                        mail_content = mail_object[1]
                        mail_dict = jira_connector.get_mail_data(mail_content)

                        if mail_dict:
                            # Create security event with mail data
                            mail_event = jira_connector.create_mail_event(mail_dict, mail_content, mail_file_name)
                            new_mail = {}
                            # Decode values
                            for key, val in list(mail_event.items()):
                                try:
                                    new_mail.update({key.decode("utf-8"): val.decode("utf-8")})
                                except Exception as e:
                                    connector_scope.LOGGER.error("Failed to decode mail. Continue to next one.")
                                    connector_scope.LOGGER.exception(e)
                                    continue
                            events.append(new_mail)

                else:
                    connector_scope.LOGGER.info("No attachments were found for issue {0}".format(ticket.key))

                # Create case info
                # Create list of two events (1- with issue details, 2-with mail details)
                case = jira_common.create_case_info(ticket, events, connector_environment, use_jira_as_env)
                # Ingest the case to siemplify
                cases.append(case)

            except Exception as e:
                connector_scope.LOGGER.error("Failed to create CaseInfo")
                connector_scope.LOGGER.error("Error Message: {}".format(str(e)))
                connector_scope.LOGGER.exception(e)
                if is_test:
                    raise

        connector_scope.LOGGER.info("Completed processing emails from issues.")

        # Get last successful execution time.
        if cases:
            # Sort the cases by the end time of each case.
            cases = sorted(cases, key=lambda case: case.end_time)
            # Last execution time is set to the newest message time
            new_last_run_time = cases[-1].end_time
        else:
            # last_calculated_run_time is datetime object. Convert it to milliseconds timestamp.
            new_last_run_time = convert_datetime_to_unix_time(last_calculated_run_time)

        connector_scope.LOGGER.info("Create {} cases.".format(len(cases)))

        if not is_test:
            # update last execution time
            connector_scope.save_timestamp(new_timestamp=new_last_run_time)
            # Return data
            connector_scope.return_package(cases, output_variables, log_items)
        else:
            # Return data
            connector_scope.return_test_result(True, {})

        connector_scope.LOGGER.info("=======Jira Connector Finish.=======")

    except Exception as e:
        connector_scope.LOGGER.error(str(e))
        connector_scope.LOGGER.exception(e)
        if is_test:
            raise


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print("Main execution started")
        main()
    else:
        print("Test execution started")
        main(is_test=True)
