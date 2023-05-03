# ============================================================================#
# title            :JiraRestManager.py
# description      :This Module contain all Jira operations functionality
# author           :avital@siemplify.co
# date             :24-02-2019
# python_version   :2.7
# libreries        :requests
# requirments      :
# product_version  :1.0
# api_documentation:https://developer.atlassian.com/cloud/jira/platform/rest/v2/
# ============================================================================#

# ============================= IMPORTS ===================================== #
from typing import List

import urllib3
import requests

from dateutil.parser import parse
import datetime
import os
import email
from email.header import decode_header
from JiraParser import JiraParser
from exceptions import JiraRelationTypeError
from urllib.parse import urljoin
from JiraConstants import ENDPOINTS
from utils import filter_items

# ============================== CONSTS ===================================== #

MAX_RESULTS = 50
BAD_REQUEST = 400
UNAUTHORIZED = 401

DATETIME_STR_FORMAT = "%Y/%m/%d %H:%M"
EXTENSIONS = ['.eml']
PAGE_SIZE = 50


# ============================= CLASSES ===================================== #

class JiraRestManagerError(Exception):
    """
    General Exception for Jira manager
    """
    pass


class JiraRestManager(object):

    def __init__(self, server_addr, username, api_token, api_version=2,
                 use_ssl=True):
        self.server_address = server_addr
        self.api_version = api_version
        self.session = requests.Session()
        self.session.verify = use_ssl
        self.session.auth = (username, api_token)

        self.parser = JiraParser()
        self.test_connectivity()

    def test_connectivity(self):
        """
        Test connectivity to Jira
        :return: {bool} True if successful, exception otherwise
        """
        url = "{}/rest/api/{}/myself".format(self.server_address,
                                             self.api_version
                                             )

        response = self.session.get(url)

        self.validate_response(response, "Unable to connect to Jira")

        return True

    def create_issue(self, project_key, summary, issue_type, description=None, assignee=None, components: List = None,
                     labels: List = None, custom_fields=None):
        """
        Create a new issue in a given project key
        :param project_key: {string} project key in which the issue is created
        :param summary: {string} issue summary
        :param description: {string} issue description
        :param issue_type: {string} issue type name
        :param assignee: {string} Username or email of the user to assign this ticket for
        :param components: {List} List of components to add to the issue. For example: [{"id": 10000}]
        :param labels: {List} List of labels to add to the issue. For example: ["bugfix", "blitz_test"]
        :param custom_fields: {dict} Custom fields to apply to the issue
        :return: {str} The new issue's key
        """
        project = self.get_project_by_key(project_key)
        payload = {
            "fields": {
                "project": self.get_project_by_key(project_key),
                "summary": summary,
                "description": description,
                "issuetype": self.get_issue_type_by_name(issue_type, project.get('id'))
            }
        }

        if components:
            payload['fields']['components'] = components
        if labels:
            payload['fields']['labels'] = labels
        if assignee:
            payload['fields']['assignee'] = {"id": assignee}
        if custom_fields:
            payload['fields'].update(custom_fields)

        url = "{}/rest/api/{}/issue".format(self.server_address,
                                            self.api_version
                                            )

        response = self.session.post(url, json=payload)

        self.validate_response(response, "Unable to create issue")

        return response.json().get("key")

    def get_project_by_key(self, project_key):
        """
        Get project details by issue id
        :param project_key: {string} project key
        :return: {dict} project details
        """
        url = "{}/rest/api/{}/project/{}".format(self.server_address,
                                                 self.api_version,
                                                 project_key)

        response = self.session.get(url)

        self.validate_response(response,
                               "Unable to get project {}".format(project_key)
                               )

        return response.json()

    def link_issues(self, outward_issue_id, inward_issue_id, relation_type):
        """
        Function that links issues
        :param outward_issue_id: {string} Outward Issue ID
        :param inward_issue_id: {list} List of Inward Issues IDs
        :param relation_type: {string} Relation Type
        """
        url = "{}/rest/api/{}/issueLink".format(self.server_address,self.api_version)

        params = {
            "type": {
                "name": relation_type
            },
            "inwardIssue": {
                "key": inward_issue_id
            },
            "outwardIssue": {
                "key": outward_issue_id
            }
        }

        response = self.session.post(url, params=params)
        self.validate_response(response,
                               f"Unable to get Outward Issue ID: {outward_issue_id} with Inward Issue ID {inward_issue_id}."
                               )

    @staticmethod
    def fix_format(filter_values):
        if isinstance(filter_values, list):
            # Fix format - instead of ['name', 'name'] should be "'name', 'name'"
            filter_values = ", ".join(
                "'{}'".format(filter_val) for filter_val in filter_values)
        else:
            # Fix formats - instead of 'name,name' should be "'name', 'name'"
            filter_values = ", ".join(
                "'{}'".format(filter_val) for filter_val in
                filter_values.split(","))
        return filter_values

    def list_issues(self, project_key_list=None, assignee_list=None,
                    issue_type_list=None,
                    priority_list=None, status_list=None, summary=None,
                    description=None, reporter=None, created_from=None,
                    updated_from=None, labels_list=None, components_list=None,
                    only_keys=True):
        """
        List issues by filters. More than one filter can be applied.
        :param project_key_list: {list} project key in which the issue is created
        :param summary: {string} issue summary
        :param description: {string} issue description
        :param issue_type_list: {list} issue type name
        :param assignee_list: {list} assignee name
        :param priority_list: {list} issue's priority
        :param status_list: {list} issue's status
        :param reporter: {string} reporter name
        :param created_from: {string} issue creation date (format: YYYY/MM/DD)
        :param updated_from: {string} issue last update date (format: YYYY/MM/DD)
        :param only_keys: {boolean} return only issue keys
        :return: {list} The issues' keys if only_keys or the full issues'
            details
        """
        query = []

        # Construct query
        if project_key_list:
            # Fix format - instead of ['name', 'name'] should be "'name', 'name'"
            project_key = self.fix_format(project_key_list)
            query.append(
                "Project in ({project})".format(project=project_key))
        if assignee_list:
            assignee = self.fix_format(assignee_list)
            query.append(
                "Assignee in ({assignee})".format(assignee=assignee))
        if issue_type_list:
            # for issue_t in issue_type_list:
            #     issue_t = self.jira.issue_type_by_name(issue_t)
            #     issue_types.append(issue_t.id)
            issue_types = self.fix_format(issue_type_list)
            query.append("Issuetype in ({issue_type})".format(
                issue_type=issue_types))
        if priority_list:
            priority = self.fix_format(priority_list)
            query.append(
                "Priority in ({priority})".format(priority=priority))
        if status_list:
            status = self.fix_format(status_list)
            query.append("Status in({status})".format(status=status))
        if summary:
            query.append("Summary~'{summary}'".format(summary=summary))
        if description:
            query.append("Description~'{description}'".format(
                description=description))
        if reporter:
            query.append("Reporter='{reporter}'".format(reporter=reporter))
        if created_from:
            query.append("Created >='{created_from}'".format(
                created_from=created_from))
        if updated_from:
            query.append("Updated >='{updated_from}'".format(
                updated_from=updated_from))
        if labels_list:
            labels = self.fix_format(labels_list)
            query.append(("Labels in ({0})".format(labels)))
        if components_list:
            components = self.fix_format(components_list)
            query.append(("Component in ({0})".format(components)))

        query = " AND ".join(query)

        issues = self.search_issues(query)

        if only_keys:
            return [issue.get("key") for issue in issues]
        else:
            return issues

    def search_issues(self, query, max_results=None):
        """
        Search issues by a given query
        :param query: {str} The query to run
        :param max_results: {int} Max number of results to return
        :return: {list} The found issues
        """
        url = "{}/rest/api/{}/search".format(self.server_address,
                                             self.api_version
                                             )
        start_at = 0

        response = self.session.post(url, json={
            "startAt": start_at,
            "maxResults": max_results,
            "jql": query,
        })

        issues = response.json().get("issues", [])

        while response.json().get("isLast", False):
            if max_results and len(issues) >= max_results:
                break

            start_at = start_at + PAGE_SIZE
            response = self.session.post(url, json={
                "startAt": start_at,
                "maxResults": max_results,
                "jql": query,
            })

            issues.extend(response.json().get("issues", []))

            self.validate_response(response, "Unable to search for issues")

        return issues[:max_results] if max_results else issues

    def get_all_users(self):
        """
        Get all available users from Jira service
        :return: {[datemodels.User]} List of Jira users
        """
        url = "{}/rest/api/{}/users/search".format(self.server_address,
                                                   self.api_version)
        payload = {
            "startAt": 0,
        }

        users = []
        response = self.session.get(url, params=payload)

        while response.json():
            users_list = self.parser.build_user_obj_list(response.json())
            payload['startAt'] += len(users_list)
            users.extend(users_list)
            response = self.session.get(url, params=payload)

        return users

    def assign_issue(self, issue_key, assignee_account_id):
        """
        Assign an issue
        :param issue_key: {string} issue key
        :param assignee_account_id: {string} assignee's accountId
        :return: {bool} True if successful, exception otherwise
        """
        url = "{}/rest/api/{}/issue/{}/assignee".format(self.server_address,
                                                        self.api_version,
                                                        issue_key)

        response = self.session.put(url, json={
            "accountId": assignee_account_id
        })

        self.validate_response(response,
                               "Unable to assign user to issue {}".format(
                                   issue_key)
                               )

        return True

    def get_issue_by_key(self, issue_key, fields_value=None):
        """
        Get issue details by issue id
        :param issue_key: {string} issue key
        :param fields_value: {string} issue fields to include in the results like attachment
        :return: {dict} issue details
        """
        url = "{}/rest/api/{}/issue/{}".format(self.server_address,
                                               self.api_version,
                                               issue_key)

        response = self.session.get(url, params={
            "fields": fields_value if fields_value else None,
        })

        self.validate_response(response,
                               "Unable to get issue {}".format(issue_key)
                               )

        return self.parser.build_issue_obj(response.json())

    def get_issue_status_id(self, status_name, issue_key):
        """
        Get an issue status id by a status name
        :param status_name: {str} The name of the status
        :param issue_key: {str} The key of the issue
        :return: {int} The id of the found status
        """
        url = "{}/rest/api/{}/issue/{}/transitions".format(self.server_address,
                                                           self.api_version,
                                                           issue_key)

        response = self.session.get(url)
        self.validate_response(response,
                               "Unable to get issue {} transitions".format(
                                   issue_key)
                               )

        statuses = response.json().get("transitions")
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
        param custom_fields: {dict} Custom fields to apply to the issue
        :return: {bool} True if successful, exception otherwise
        """
        project_id = self.get_project_id_by_issue_key(issue_key=issue_key)
        payload = {
            "fields": {}
        }

        if summary:
            payload["fields"]['summary'] = summary
        if description:
            payload["fields"]['description'] = description
        if issue_type:
            payload["fields"]['issuetype'] = self.get_issue_type_by_name(
                issue_type, project_id)
        if components:
            payload["fields"]['components'] = components
        if labels:
            payload["fields"]['labels'] = labels
        if custom_fields:
            payload['fields'].update(custom_fields)

        if status:
            self.transition_issue(issue_key, status)

        url = "{}/rest/api/{}/issue/{}".format(self.server_address,
                                               self.api_version,
                                               issue_key)

        response = self.session.put(url, json=payload)
        self.validate_response(response,
                               "Unable to update issue {}".format(issue_key))

        return True

    def get_project_id_by_issue_key(self, issue_key):
        """
        Return project key of the provided issue.
        :param issue_key: {str} Key of the issue. For example: 'TPS-20'.
        :return: {str} Project key. For example: 'TPS'.
        """
        issue = self.get_issue_by_key(issue_key)
        return issue.project_id

    def transition_issue(self, issue_key, status):
        """
        Transition an issue to a given status
        :param issue_key: {str} The key of the issue
        :param status: {str} The name of the status to transition to
        :return: {bool} True if successful, exception otherwise
        """
        status_id = self.get_issue_status_id(status, issue_key)

        if status_id:
            url = "{}/rest/api/{}/issue/{}/transitions".format(
                self.server_address,
                self.api_version,
                issue_key)

            response = self.session.post(url, json={
                "transition": {
                    "id": status_id
                }
            })

            self.validate_response(response,
                                   "Unable to transition issue {} to status {}".format(
                                       issue_key,
                                       status)
                                   )

            return True

        raise JiraRestManagerError(
            "The transition '{}' was not found or you can not move to it from the current status. ".format(status))

    def get_issue_type_by_name(self, issue_type_name, project_id):
        """
        Get an issue type by its name
        :param issue_type_name: {str} The name of the issue type
        :param project_id: {str} The id of the project.
        :return: {dict} The issue type found
        """
        url = "{}/rest/api/{}/issuetype/project".format(self.server_address,
                                                        self.api_version
                                                        )

        params = {
            "projectId": project_id
        }

        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to get issue types")

        for issue_type in response.json():
            if issue_type.get("name") == issue_type_name:
                return issue_type

        raise JiraRestManagerError(
            "Issue type {} was not found.".format(issue_type_name))

    def delete_issue(self, issue_key):
        """
        Delete an issue
        :param issue_key: {string} issue key
        :return: {bool} True if successful, exception otherwise
        """
        url = "{}/rest/api/{}/issue/{}".format(self.server_address,
                                               self.api_version,
                                               issue_key
                                               )

        response = self.session.delete(url)
        self.validate_response(response,
                               "Unable to delete issue {}".format(issue_key)
                               )

        return True

    def add_comment(self, issue_key, comment):
        """
        Add a new comment to a given issue
        :param issue_key: {string} issue key
        :param comment: {string} comment content
        :return: {int} The new comment's ID
        """
        url = "{}/rest/api/{}/issue/{}/comment".format(self.server_address,
                                                       self.api_version,
                                                       issue_key
                                                       )

        response = self.session.post(url, json={
            "body": comment
        })
        self.validate_response(
            response,
            "Unable to add comment to issue {}".format(issue_key)
        )

        return response.json().get("id")

    def get_issue_comments_since_time(self, issue_key, last_modification_utc):
        """
        Get issue comment since a given timestamp
        :param issue_key: {str} The key of the issue
        :param last_modification_utc: {string} {str} The timestamp to search
            comments since
        :return: {list} List of the comments found
        """
        issue = self.get_issue_by_key(issue_key)
        comments = []
        issue_comments = issue.get('fields', {}).get('comment', [])

        for comment in issue_comments:
            if parse(comment.get('created')) >= last_modification_utc:
                comments.append(comment.get('body'))
        return comments

    @staticmethod
    def extract_attachments_from_mail(file_name, email_content):
        """
        Get attachment name and content from email
        Download attachments from attached emls
        :param email_content: email data
        :return: {list} list of tuples (file name, content)
        """
        collected_attachments = []
        if os.path.splitext(file_name)[-1] == '.eml':
            # Return a message object structure from a string.
            msg = email.message_from_string(email_content)
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
                    collected_attachments.append((filename, file_content))

        return collected_attachments

    def get_attachments_from_issue(self, issue_key, extensions=[]):
        """
        Get attachment from issue and parse the email file.
        :param issue_key: {string} issue key
        :param extensions: {list} which attachments to include (by extensions)
        :return: {list} list of attachment tuples
        """
        issue_attachments = []
        issue_with_attachment_field = self.get_issue_by_key(issue_key,
                                                            fields_value='attachment')
        attachments_list = issue_with_attachment_field.get("fields", {}).get(
            "attachment", [])
        for attachment in attachments_list:
            # Filter by extensions
            if not extensions or \
                    os.path.splitext(attachment.get("filename"))[
                        1] in extensions:
                file_name = attachment.get("filename")
                file_content = self.download_attachment(
                    attachment.get("content"))
                issue_attachments.append((file_name, file_content))

        return issue_attachments

    def download_attachment(self, attachment_url):
        """
        Download a JIRA attachment from a given url
        :param attachment_url: {str} The urlto the attachment download
        :return: {str} The content of the attachment
        """
        response = self.session.get(attachment_url)
        self.validate_response(response,
                               "Unable to get attachment for {}".format(
                                   attachment_url))
        return response.content

    def upload_attachment(self, issue_key, file_path):
        """
        Upload an attachment to an issue
        :param issue_key: {str} The issue key
        :param file_path: {str} The path to the file to upload
        :return: {bool} True if successful, exception otherwise.
        """
        if not os.path.exists(file_path):
            raise JiraRestManagerError(
                "File {} doesn't exist.".format(file_path))

        with open(file_path, 'rb') as attachment:
            filename = os.path.basename(file_path)

            url = "{}/rest/api/{}/issue/{}/attachments".format(
                self.server_address,
                self.api_version,
                issue_key
            )

            response = self.session.post(
                url,
                files={
                    'file': (filename, attachment)
                },
                headers=
                {
                    'content-type': None,
                    'X-Atlassian-Token': 'nocheck'
                }
            )

            self.validate_response(
                response,
                "Unable to add attachment to issue {}".format(issue_key)
            )

            return True

    def get_relation_types(self, filter_key, filter_logic, filter_value, limit):
        """
        Get relation types
        :param filter_key: {str} Filter key to use for results filtering
        :param filter_logic: {str} Filter logic
        :param filter_value: {str} Filter value
        :param limit: {str} Limit for results
        :return: {list} List of RelationTypes objects
        """
        url = self._get_full_url("get_relation_types", api_version=self.api_version)
        response = self.session.get(url)
        self.validate_response(response)

        return filter_items(
            items=self.parser.build_relation_type_objects(response.json()),
            filter_key=filter_key,
            filter_logic=filter_logic,
            filter_value=filter_value,
            limit=limit
        )

    def _get_full_url(self, url_id, **kwargs):
        """
        Get full url from url identifier.
        :param url_id: {str} The id of url
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full url
        """
        return urljoin(self.server_address, ENDPOINTS[url_id].format(**kwargs))

    @staticmethod
    def save_attachment_to_local_path(path, attachment_name,
                                      attachment_content):
        """
        Save message attachment to local path
        :param path: {string} Path to the directory to save the attachment at
        :param attachment_name: {string} file name
        :param attachment_content: file content
        :return: {str} path to the downloaded files
        """
        if not os.path.exists(path):
            os.makedirs(path)

        local_path = os.path.join(path, attachment_name)
        with open(local_path, 'wb') as f:
            f.write(attachment_content)
        return local_path

    @staticmethod
    def convert_datetime_to_jira_format(datetime_obj):
        """
        Convert Datetime object to Jira Datetime format
        :param datetime_obj: {datetime} datetime object
        :return: {string} Jira datetime format
        # Jira valid formats include: 'yyyy/MM/dd HH:mm', 'yyyy-MM-dd HH:mm', 'yyyy/MM/dd', 'yyyy-MM-dd'
        """
        return datetime.datetime.strftime(datetime_obj, DATETIME_STR_FORMAT)

    @staticmethod
    def validate_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            if "No issue link type with name" in error.text:
                raise JiraRelationTypeError(error.text)
            raise JiraRestManagerError(
                "{error_msg}: {error} {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=response.content
                )
            )
