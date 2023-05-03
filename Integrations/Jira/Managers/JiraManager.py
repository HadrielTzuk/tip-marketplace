# ============================================================================#
# title           :JiraManager.py
# description     :This Module contain all Jira operations functionality
# author          :avital@siemplify.co
# date            :16-01-2018
# python_version  :3.7
# libraries       :jira, requests
# product_version :1.0
# ============================================================================#

from typing import List, Optional, Union

import requests
import urllib3

import datamodels

from jira import JIRA, JIRAError
import json
from datetime import datetime
import os
import email
from email.header import decode_header
from JiraParser import JiraParser
from exceptions import JiraManagerError, JiraGDPRError, JiraRelationTypeError
from utils import get_file_path_extension, remove_empty_kwargs, filter_old_alerts
from SiemplifyUtils import convert_string_to_datetime
from utils import filter_items

# ============================== CONSTS ===================================== #

MAX_RESULTS = 50
BAD_REQUEST = 400
UNAUTHORIZED = 401
NOT_FOUND = 404

DATETIME_STR_FORMAT = "%Y/%m/%d %H:%M"
EXTENSIONS = ['.eml']
GDPR_ERROR = 'GDPR'  # European Union
RGPD_ERROR = 'RGPD'  # France & Spain
AVG_ERROR = 'AVG'  # Netherlands
RODO_ERROR = 'RODO'  # Poland
DSGVO_ERROR = 'DSGVO'  # Germany
GDPR_ERRORS = [GDPR_ERROR, RGPD_ERROR, AVG_ERROR, RODO_ERROR, DSGVO_ERROR]


class JiraManager(object):

    def __init__(self, server_addr, username, api_token, verify_ssl=False, logger=None):
        """
        Connect to a JIRA instnace
        """
        try:
            # Connect to JIRA instance with given credentials
            self.jira = JIRA(server=server_addr,
                             basic_auth=(username, api_token),
                             options={
                                 "verify": verify_ssl
                             },
                             max_retries=0)
            self.jira.myself()
        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Bad credentials
                raise JiraManagerError(
                    "Unable to authenticate with {server}, check given credentials.".format(
                        server=server_addr))

            # Unknown JIRAError
            raise JiraManagerError(
                "Unable to connect to {server}: {error} {text}".format(
                    server=server_addr,
                    error=error,
                    text=error.text)
            )

        except Exception as error:
            raise JiraManagerError(
                "Unable to connect to {server}: {error}".format(
                    server=server_addr,
                    error=error)
            )

        self.parser = JiraParser()
        self.logger = logger

    def create_issue(self, project_key, summary, issue_type, description=None, components: List = None,
                     labels: List = None, custom_fields={}):
        """
        Create a new issue in a given project key
        :param project_key: {string} project key in which the issue is created
        :param summary: {string} issue summary
        :param description: {string} issue description
        :param issue_type: {string} issue type name
        :param components: {List} List of components to add to the issue. For example: [{"id": 10000}]
        :param labels: {List} List of labels to add to the issue. For example: ["bugfix", "blitz_test"]
        :param custom_fields: {dict} Custom fields to apply to the issue
        :return: {int} The new issue's key
        """
        try:
            project = self.jira.project(project_key)
            fields_dict = remove_empty_kwargs(
                project=project.id,
                summary=summary,
                description=description,
                issuetype=self.get_issue_type_by_name(issue_type, project.id).raw,
                components=components,
                labels=labels
            )
            fields_dict.update(custom_fields)
            new_issue = self.jira.create_issue(fields=fields_dict)
            return new_issue.key

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to create an issue.")

            elif error.status_code == BAD_REQUEST:
                # Bad request - invalid params provided
                errors = json.loads(error.response.text)['errors']
                if 'issuetype' in errors:
                    raise JiraManagerError(
                        "Bad issue type, issue was not created.")

            # Unknown error
            raise JiraManagerError(error.text)

    def get_issue_type_by_name(self, issue_type_name, project_id):
        """
        Return the issue type object of the provided issue name.
        :param issue_type_name: {str} Name of the issue type. For example: "Task"
        :param project_id: {str} Project ID. for example: "TPS"
        :return: {IssueType} Jira SKD object of type: IssueType
        """
        project = self.get_project_by_id(project_key=project_id)
        for issue_type in project.issueTypes:
            if issue_type.name == issue_type_name:
                return issue_type
        raise JiraManagerError(
            "The issue type '{}' was not found in the provided project.".format(issue_type_name))

    def get_project_by_id(self, project_key):
        """
        Return the project object of the provided project key.
        :param project_key: {str} Project key. for example: "TPS"
        :return: {Project} Jira SKD object of type: Project
        """
        try:
            return self.jira.project(id=project_key)
        except JIRAError as error:
            if error.status_code == NOT_FOUND:
                # Bad request - invalid params provided
                error_response = error.response.json().get('errorMessages')
                raise JiraManagerError(error_response[0] if error_response[0] else "Project not found.")
            raise JiraManagerError(error.text)

    @staticmethod
    def fix_format(filter_values):
        """
        Fix JQL query parameters
        :param filter_values: {[str] or str} - Filter values to create Jira query from
        :return: {str} String of formatted JQL query
        """
        if isinstance(filter_values, list):
            # Fix format - instead of ['name', 'name'] should be "'name', 'name'"
            filter_values = ", ".join("'{}'".format(filter_val) for filter_val in filter_values)
        else:
            # Fix formats - instead of 'name,name' should be "'name', 'name'"
            filter_values = ", ".join(
                "'{}'".format(filter_val) for filter_val in filter_values.split(","))
        return filter_values

    def list_issues(self, project_key_list=None, assignee_list=None, issue_type_list=None,
                    priority_list=None, status_list=None, summary=None,
                    description=None, reporter=None, created_from=None,
                    updated_from=None, labels_list=None, components_list=None,
                    only_keys=True, existing_ids: Optional[List[str]] = None, order_by: Optional[str] = None,
                    asc: Optional[bool] = False, limit: Optional[int] = None) -> List[Union[str, datamodels.Issue]]:
        """
        List issues by filters. More than one filter can be applied.
        :param project_key_list: {list} Project key in which the issue is created
        :param summary: {string} Summary that is contained in issues text
        :param description: {string} Description that is contained in issues description
        :param issue_type_list: {[str]} Issue type name list. Values can be Epic, Task, Bug..
        :param assignee_list: {[str]} Assignees list of the issues. Can be user's full name, ID, or email address.
        :param priority_list: {[str]} Issue's priority. Values can be Low, Lowest, High, Highest, Medium
        :param status_list: {[str]]} Issue's status list. Values can be TO DO, IN PROGRESS, DONE, DEV TO DO, OPEN, TO DO
        :param reporter: {str} Reporter's name of the issues.
        :param created_from: {str} Issue creation date (format: YYYY/MM/DD)
        :param updated_from: {str} Issue last update date (format: YYYY/MM/DD)
        :param labels_list: {[str]} Search for issues tagged with a label or list of labels.
        :param components_list: {[str]} Search for issues that belong to a particular component(s) of a project.
                You can search by component name or component ID (i.e. the number that JIRA automatically allocates to a component).
        :param only_keys: {boolean} True if to return only issue keys
        :param order_by: {str} Attribute to order by the results.
        :param existing_ids: {[str]} If provided, issues will be filtered by existing ids.
        :param asc: {bool} Applicable only if order_by attribute is provided. True if results should be ordered in ascending order,
        otherwise False.
        :param limit: {int} Max results to return. If not provided, all issues will be returned.
        :return: {[datamodels.Issue] or [str]} List of Issue datamodels if only_keys=False. Otherwise, list of issue keys will be returned
        """
        try:
            query = []

            # Build query
            if project_key_list:
                project_key = self.fix_format(project_key_list)
                query.append("project in ({project})".format(project=project_key))

            if assignee_list:
                assignee = self.fix_format(assignee_list)
                query.append("assignee in ({assignee})".format(assignee=assignee))

            if issue_type_list:
                issue_types = self.fix_format(issue_type_list)
                query.append("issueType in ({issue_type})".format(issue_type=issue_types))

            if priority_list:
                priority = self.fix_format(priority_list)
                query.append("priority in ({priority})".format(priority=priority))

            if status_list:
                status = self.fix_format(status_list)
                query.append("status in ({status})".format(status=status))

            if summary:
                query.append("summary ~'{summary}'".format(summary=summary))

            if description:
                query.append("description ~'{description}'".format(description=description))

            if reporter:
                query.append("reporter = '{reporter}'".format(reporter=reporter))

            if created_from:
                query.append("created >= '{created_from}'".format(created_from=created_from))

            if updated_from:
                query.append("updated >= '{updated_from}'".format(updated_from=updated_from))

            if labels_list:
                labels = self.fix_format(labels_list)
                query.append(("labels in ({0})".format(labels)))

            if components_list:
                components = self.fix_format(components_list)
                query.append(("component in ({0})".format(components)))

            query = " AND ".join(query)

            if order_by:
                query += " ORDER BY {} {}".format(order_by, 'ASC' if bool(asc) else "DESC")

            # Fetch all issues by chunks of MAX_RESULTS - due to a bug in the jira package
            issues = []
            fetched_issues = self.parser.build_issue_obj_list(
                issue.raw for issue in self.jira.search_issues(query, maxResults=MAX_RESULTS))
            start_offset = 0

            while fetched_issues:

                if limit is not None and len(issues) >= limit:
                    if self.logger:
                        self.logger.info(f"Reached limit of {limit}. Stop paginating for more issues..")
                    break

                if existing_ids:
                    fetched_issues = filter_old_alerts(self.logger, fetched_issues, existing_ids)

                issues.extend(fetched_issues)

                if self.logger:
                    self.logger.info(
                        f"Fetching more issues. Start offset {start_offset}. Fetched total of {len(issues)}")

                start_offset += MAX_RESULTS

                fetched_issues = self.parser.build_issue_obj_list(
                    issue.raw for issue in self.jira.search_issues(query, startAt=start_offset, maxResults=MAX_RESULTS))

            issues = issues[:limit] if limit is not None else issues
            return [issue.key for issue in issues] if only_keys else issues

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to search for issues.")

            # Unknown error
            raise JiraManagerError(error.text)

    def assign_issue(self, issue_key, assignee):
        """
        Assign an issue
        :param issue_key: {string} issue key
        :param assignee: {string} assignee's username
        """
        try:
            issue = self.jira.issue(issue_key)
            self.jira.assign_issue(issue, assignee)

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to assign an issue.")

            # The reason for this exception is that some parameters was deprecated in Jira API according to the GDPR
            # You can find more details in here:
            # https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-user-privacy-api-migration-guide/
            if any(gdpr_error in str(error) for gdpr_error in GDPR_ERRORS):
                raise JiraGDPRError(
                    "The query parameter not in GDPR strict mode.")

            # Unknown error
            raise JiraManagerError(error.text)

    def link_issues(self, outward_issue_id, inward_issue_id, relation_type):
        """
        Function that links issues
        :param outward_issue_id: {string} Outward Issue ID
        :param inward_issue_id: {list} List of Inward Issues IDs
        :param relation_type: {string} Relation Type
        """      
        try:  
            _response = self.jira.create_issue_link(type=relation_type, inwardIssue=inward_issue_id, outwardIssue=outward_issue_id)

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to assign an issue.")

            # The reason for this exception is that some parameters was deprecated in Jira API according to the GDPR
            # You can find more details in here:
            # https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-user-privacy-api-migration-guide/
            if GDPR_ERROR in str(error):
                raise JiraGDPRError(
                    "The query parameter not in GDPR strict mode.")

            if "No issue link type with name" in error.text:
                raise JiraRelationTypeError(error.text)

            # Unknown error
            raise JiraManagerError(error.text)        

    def get_users_contains_username(self, username):
        """
        Get all available users that contains username in their names from Jira service
        :return: {[datemodels.User]} List of Jira users
        """

        try:
            start_at = 0

            users = []
            response = self.jira.search_users(username, startAt=start_at)
            request_users = [vars(user) for user in response.iterable]

            while not response.isLast or request_users:
                users_list = self.parser.build_user_obj_list(request_users)
                start_at += len(users_list)
                users.extend(users_list)
                response = self.jira.search_users(username, startAt=start_at)
                request_users = [vars(user) for user in response.iterable]

            return users

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to assign an issue.")

            # The reason for this exception is that some parameters was deprecated in Jira API according to the GDPR
            # You can find more details in here:
            # https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-user-privacy-api-migration-guide/
            if any(gdpr_error in str(error) for gdpr_error in GDPR_ERRORS):
                raise JiraGDPRError(
                    "The query parameter not in GDPR strict mode.")

            # Unknown error
            raise JiraManagerError(error.text)

    def get_issue_by_key(self, issue_key, fields_value=None) -> datamodels.Issue:
        """
        Get issue details by issue id
        :param issue_key: {string} issue key
        :param fields_value: {string} issue fields to include in the results like attachment
        :return: {datamodels.Issue} Issue data model
        """
        raw_issue = self.jira.issue(issue_key, fields=fields_value).raw
        issue = self.parser.build_issue_obj(raw_issue)
        return issue

    def get_project_components(self, project: str) -> List:
        """
        Returns all components in a project.
        :param project: {str} The project name/id
        :return: List of project's components
        """
        try:
            components = self.jira.project_components(project=project)
            return components

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to search project's components.")

            # Unknown error
            raise JiraManagerError(error.text)

    def get_issue_status_id(self, status_name, issue):
        statuses = self.jira.transitions(issue)
        for status in statuses:
            if status_name == status.get('name'):
                return status['id']

    def update_issue(self, issue_key, summary=None, description=None,
                     issue_type=None, status=None, components: List = None,
                     labels: List = None, custom_fields=None):
        """
        Update an issue
        :param issue_key: {string} issue key
        :param summary: {string} issue summary
        :param description: {string} issue description
        :param issue_type: {string} issue type name
        :param components: {List} List of components to add to the issue. For example: [{"id": 10000}]
        :param labels: {List} List of labels to add to the issue. For example: ["bugfix", "blitz_test"]
        :param custom_fields: {dict} Custom fields to apply to the issue
        """
        try:
            project_id = self.get_project_id_by_issue_key(issue_key=issue_key)
            fields = {}

            if summary:
                fields['summary'] = summary
            if description:
                fields['description'] = description
            if issue_type:
                fields['issuetype'] = self.get_issue_type_by_name(issue_type, project_id).raw
            if components:
                fields['components'] = components
            if labels:
                fields['labels'] = labels
            if custom_fields:
                fields.update(custom_fields)

            issue = self.jira.issue(issue_key)
            if status:
                status_id = self.get_issue_status_id(status, issue)
                if status_id:
                    self.jira.transition_issue(issue, status_id)
                else:
                    raise JiraManagerError("Bad status, issue status was not updated.")

            issue.update(fields=fields)

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to update an issue.")

            elif error.status_code == BAD_REQUEST:
                # Bad request - invalid params provided
                errors = json.loads(error.response.text)['errors']
                if 'issuetype' in errors:
                    raise JiraManagerError(
                        "Bad issue type, issue was not created.")

            # Unknown error
            raise JiraManagerError(error.text)

    def get_project_id_by_issue_key(self, issue_key):
        """
        Return project key of the provided issue.
        :param issue_key: {str} Key of the issue. For example: 'TPS-20'.
        :return: {str} Project key. For example: 'TPS'.
        """
        issue = self.get_issue_by_key(issue_key)
        return issue.project_id

    def delete_issue(self, issue_key):
        """
        Delete an issue
        :param issue_key: {string} issue key
        """
        try:
            self.jira.issue(issue_key).delete()

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to delete an issue.")

            # Unknown error
            raise JiraManagerError(error.text)

    def add_comment(self, issue_key, comment):
        """
        Add a new comment to a given issue
        :param issue_key: {string} issue key
        :param comment: {string} comment content
        :return: {int} The new comment's ID
        """
        try:
            new_comment = self.jira.add_comment(issue_key, comment)
            return new_comment.id

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to create an issue
                raise JiraManagerError(
                    "Credentials are invalid or no permission to add a comment.")

            # Unknown error
            raise JiraManagerError(error.text)

    def get_issue_comments_since_time(self, issue_key, last_modification_unix_time_ms):
        """
        Get issue comments that were updated after certain modification time.
        :param issue_key: {str} The issue key to get comments from
        :param last_modification_unix_time_ms: {int} Last modification unix time in milliseconds
        :return: {[Issue.Comment]} List of issue comments datamodels of comments that were updated after last_modification_unix_time_ms
            parameter
        """
        issue = self.parser.build_issue_obj(self.jira.issue(issue_key, fields='comment').raw)
        return [comment for comment in issue.comments if comment.updated_ms >= last_modification_unix_time_ms]

    @staticmethod
    def extract_attachments_from_mail(file_name, email_content):
        """
        Get attachment name and content from email
        Download attachments from attached emls
        :param file_name: {str} Email file name
        :param email_content: {bytes} Email data
        :return: {list} list of tuples (file name, content)
        """
        collected_attachments = []
        if get_file_path_extension(file_name) == '.eml':
            # Return a message object structure from a string.
            msg = email.message_from_string(email_content.decode("utf-8"))
            attachments = msg.get_payload()

            for attachment in attachments:
                try:
                    # Extract filename from attachment
                    filename = attachment.get_filename()
                except:
                    filename = None
                # Some emails can return an empty attachment
                # possibly if there are a signature.
                # Validate that the attachment has a filename
                if filename:
                    # Handle 'UTF-8' issues
                    fname, charset = decode_header(filename)[0]
                    if charset:
                        filename = fname.decode(charset)
                    # Get attachment content
                    file_content = attachment.get_payload(decode=True)
                    if not file_content:
                        # this can happen when attachment is email.message.Message, so we need to convert object to bytes
                        file_content = bytes(attachment)
                    collected_attachments.append((filename, file_content))

        return collected_attachments

    def get_attachments_from_issue(self, issue_key: str, extensions: Optional[List[str]] = None):
        """
        Get attachments from an issue.
        :param issue_key: {str} Issue key
        :param extensions: {list} Which attachments to include (by extensions). If not provided, all attachments will be returned
        :return: {[({str}, {bytes})]} List of tuples. Each tuples consists of file name as string and file content as bytes
        """
        issue_attachments = []
        issue_with_attachment_field = self.jira.issue(issue_key, fields='attachment')
        attachments_list = issue_with_attachment_field.fields.attachment

        if attachments_list:
            for attachment in attachments_list:
                if not extensions or get_file_path_extension(attachment.filename) in extensions:
                    file_name = attachment.filename
                    file_content = attachment.get()
                    issue_attachments.append((file_name, file_content))

        return issue_attachments

    def upload_attachment(self, issue_key: str, file_path: str):
        """
        Upload an attachment to an issue
        :param issue_key: {str} The issue key
        :param file_path: {str} The path to the file to upload
        :return: Exception if failed to upload attachment.
        """
        if not os.path.exists(file_path):
            raise JiraManagerError(
                "File {} doesn't exist or not accessible due to restricted permissions".format(file_path))
        self.jira.add_attachment(issue=issue_key, attachment=file_path)

    def get_server_info(self) -> datamodels.ServerInfo:
        """
        Get JIRA Server info
        :return: {datamodels.ServerInfo} The server info
        """
        server_info = self.jira.server_info()
        return self.parser.build_server_info_obj(server_info)

    def get_server_time(self) -> datetime:
        """
        Get server time
        :return: {datetime.datetime} Server time
        """
        server_info = self.get_server_info()
        server_time = server_info.server_time or server_info.build_date
        if not server_time:
            raise Exception(f"'serverTime' or 'buildDate' couldn't be found from server info")

        return convert_string_to_datetime(server_time)

    @staticmethod
    def save_attachment_to_local_path(local_attachment_path, attachment_content):
        """
        Save message attachment to local path
        :param local_attachment_path: {str} Local path of attachment to save
        :param attachment_content: {bytes} Attachment content
        :return: {str} Path to the saved attachment
        """
        with open(local_attachment_path, 'wb') as f:
            f.write(attachment_content)
        return local_attachment_path

    @staticmethod
    def convert_datetime_to_jira_format(datetime_obj):
        """
        Convert Datetime object to Jira Datetime format
        :param datetime_obj: {datetime} datetime object
        :return: {string} Jira datetime format
        # Jira valid formats include: 'yyyy/MM/dd HH:mm', 'yyyy-MM-dd HH:mm', 'yyyy/MM/dd', 'yyyy-MM-dd'
        """
        return datetime.strftime(datetime_obj, DATETIME_STR_FORMAT)

    def get_relation_types(self, filter_key, filter_logic, filter_value, limit):
        """
        Get relation types
        :param filter_key: {str} Filter key to use for results filtering
        :param filter_logic: {str} Filter logic
        :param filter_value: {str} Filter value
        :param limit: {str} Limit for results
        :return: {list} List of RelationTypes objects
        """
        try:
            relation_types = self.jira.issue_link_types()

            return filter_items(
                items=[self.parser.build_relation_type_object(relation_type.raw) for relation_type in relation_types],
                filter_key=filter_key,
                filter_logic=filter_logic,
                filter_value=filter_value,
                limit=limit
            )

        except JIRAError as error:
            if error.status_code == UNAUTHORIZED:
                # Unauthorized request to get relation types
                raise JiraManagerError("Credentials are invalid or no permission to assign an issue.")

            # The reason for this exception is that some parameters was deprecated in Jira API according to the GDPR
            # You can find more details in here:
            # https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-user-privacy-api-migration-guide/
            if GDPR_ERROR in str(error):
                raise JiraGDPRError("The query parameter not in GDPR strict mode.")

            # Unknown error
            raise JiraManagerError(error.text)
