# =====================================
#              IMPORTS                #
# =====================================
import base64
import json
from collections import OrderedDict
import requests
import os

# =====================================
#             CONSTANTS               #
# =====================================
API_ROOT = "https://api.github.com"
HEADERS = {"Content-Type": "application/json"}

RENAMED_IDE_ITEMS_KEY = "Renamed IDE items"
NEW_PARAM_KEY = "New Parameters"
MISSING_PARAM_KEY = "Missing Parameters"
RENAMED_SCRIPT_RESULT_KEY = "Renamed ScriptResultName"
MANDATORY_CHANGE_KEY = "TurnedIntoIsMandatoryTrue Parameters"

DEF_EXTENSIONS = (".action", ".actiondef", ".def", ".connectordef", ".jobdef")
ACTION_DEF_EXTENSIONS = (".action", ".actiondef")


# =====================================
#              CLASSES                #
# =====================================
class GitHubManagerError(Exception):
    """
    General Exception for GitHub manager
    """
    pass


class GitHubManager(object):
    """
    Responsible for all GitHub operations functionality
    """

    def __init__(self, api_root, api_token, repo_name, repo_owner, branch_to_compare=None, verify_ssl=False):
        self.api_root = api_root
        self.repo_name = repo_name
        self.repo_owner = repo_owner
        self.branch_to_compare = branch_to_compare
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.session.headers["Authorization"] = "token {}".format(api_token)

    def get_integrations_list(self):
        """
        Get the whole list of integrations from the repository.
        :return: {list} integration name
        """
        url = "{root}/repos/{owner}/{repo}/git/trees/{branch}:Integrations".format(root=self.api_root,
                                                                                   owner=self.repo_owner,
                                                                                   repo=self.repo_name,
                                                                                   branch=self.branch_to_compare)
        response = self.session.get(url)
        self.validate_response(response)
        integrations_tree = response.json().get('tree')
        integrations_list = []
        for integration in integrations_tree:
            integrations_list.append(integration.get('path'))

        return integrations_list

    def get_file_content(self, file_sha):
        """
        The content in the response will always be Base64 encoded.
        This API supports blobs up to 100 megabytes in size.
        :param file_sha: {string} File sha as represented in GitHub.
        :return: {string} File content.
        """
        url = "{root}/repos/{owner}/{repo}/git/blobs/{sha}".format(root=self.api_root, owner=self.repo_owner,
                                                                   repo=self.repo_name, sha=file_sha)
        response = self.session.get(url)
        self.validate_response(response)
        encoded_file_content = response.json().get('content')
        file_content = base64.b64decode(encoded_file_content)
        return file_content

    def get_integration_def_files_sha(self, branch, integration_name, commit_file_name):
        """
        Get the whole list of integrations from the repository.
        :return: {list of dicts} integration name: integration sha
        """

        url = "{root}/repos/{owner}/{repo}/git/trees/{branch}:Integrations/{integration_name}".format(
            root=self.api_root,
            owner=self.repo_owner,
            repo=self.repo_name,
            branch=branch, integration_name=integration_name)
        response = self.session.get(url)
        self.validate_response(response)
        integration_tree = response.json().get('tree')
        for integration_sub in integration_tree:
            if '.def' in integration_sub.get('path'):
                def_full_path = "Integrations/{0}/{1}".format(integration_name, integration_sub.get('path'))
                if def_full_path == commit_file_name:
                    return integration_sub.get('sha')

            if integration_sub.get('path') == 'ActionsDefinitions' or integration_sub.get(
                    'path') == 'Connectors' or integration_sub.get('path') == 'Jobs':
                response = self.session.get(integration_sub.get('url'))
                self.validate_response(response)
                for def_filename in response.json().get('tree'):
                    def_full_path = "Integrations/{0}/{1}/{2}".format(integration_name, integration_sub.get('path'),
                                                                      def_filename.get('path'))
                    if def_full_path == commit_file_name:
                        return def_filename.get('sha')

    def validate_version_update(self, commits_per_integration):
        """
        Validate Integration version is valid (upgraded)
        :return: {list} of integrations names that have incorrect version
        """
        not_updated_integrations = []
        integrations_in_branch = self.get_integrations_list()

        for integration_name, integrations_commits in commits_per_integration.items():
            integration_def = 'Integrations/{0}/Integration-{0}.def'.format(integration_name)
            # Validate integration def file exist
            def_sha = [s[integration_def] for s in integrations_commits if integration_def in s]
            if def_sha and integration_name in integrations_in_branch:
                pr_version = json.loads(self.get_file_content(def_sha[0])).get('Version')
                compare_def_sha = self.get_integration_def_files_sha(branch=self.branch_to_compare,
                                                                     integration_name=integration_name,
                                                                     commit_file_name=integration_def)
                compare_def_file_version = json.loads(self.get_file_content(compare_def_sha)).get('Version')
                if float(pr_version) <= float(compare_def_file_version):
                    not_updated_integrations.append(integration_name)

            elif def_sha and integration_name not in integrations_in_branch:
                # handle adding new integration (no matching folder in the branch to compare)
                continue

            else:
                # Missing integration def - nothing update although files changed
                not_updated_integrations.append(integration_name)

        return not_updated_integrations

    @staticmethod
    def validate_params(current_file, original_file, param_key, ide_key, changes, commit_filename):
        """
        check if there are changes in params
        :param current_file: current_file
        :param original_file: original_file
        :param param_key: {string} key to search
        :param commit_filename: {string} the filename that modified
        :param ide_key: {string} ide key (e.g. parameters)
        :param changes: {dict} all changes
        """
        # check for missing params
        missing_params = []
        new_params = []
        mandatory_changed_params = []

        for param_info in original_file.get(ide_key):
            value_to_search = param_info.get(param_key)
            if not any(d.get(param_key, None) == value_to_search for d in current_file.get(ide_key)):
                missing_params.append(value_to_search)

        # check for new param
        for param_info in current_file.get(ide_key):
            value_to_search = param_info.get(param_key)
            # check if exist in original file
            original_param_list = [d for d in original_file.get(ide_key) if d.get(param_key, None) == value_to_search]
            if not original_param_list:
                new_params.append(value_to_search)
            else:
                # Check for Mandatory key
                # Relevant only for connector/action/job def file
                if not commit_filename.endswith(".def"):
                    if param_info.get('IsMandatory') != original_param_list[0].get('IsMandatory') and param_info.get(
                            'IsMandatory'):
                        mandatory_changed_params.append(value_to_search)

        if new_params:
            # check if change approved
            changes[NEW_PARAM_KEY] = {commit_filename: new_params}

        if missing_params:
            changes[MISSING_PARAM_KEY] = {commit_filename: missing_params}

        if mandatory_changed_params:
            changes[MANDATORY_CHANGE_KEY] = {commit_filename: mandatory_changed_params}

    @staticmethod
    def get_not_approved_changes(changes, approved_changes):
        """
        check if each change approved - if exist in approved changes list
        :param changes: {dict} all changes detected
        :param approved_changes: {dict} a;; approved changed
        :return: {dict} all changes that not approved
        """
        not_approved_changes = {}

        for key, value in changes.items():
            if key in approved_changes.keys():
                for filename, file_changes in value.items():
                    if filename in approved_changes.get(key, {}).keys():
                        if isinstance(file_changes, list):
                            for file_change in file_changes:
                                if file_change not in approved_changes.get(key, {}).get(filename):
                                    # check if already have changes in this file
                                    if not not_approved_changes.get(key):
                                        not_approved_changes.update({key: {filename: [file_change]}})
                                    elif not_approved_changes.get(key, {}).get(filename):
                                        not_approved_changes[key][filename].append(file_change)
                                    else:
                                        not_approved_changes[key].update({filename: [file_change]})
                        if isinstance(file_changes, dict):
                            if file_changes.get('NEW Name') != approved_changes.get(key, {}).get(filename, {}).get(
                                    'NEW Name') or file_changes.get('OLD Name') != approved_changes.get(key, {}).get(
                                filename, {}).get('OLD Name'):
                                # check if already have changes in this file
                                if not not_approved_changes.get(key):
                                    not_approved_changes.update({key: {filename: file_changes}})
                                else:
                                    not_approved_changes[key].update({filename: file_changes})

                    else:
                        # check if exist
                        if not_approved_changes.get(key):
                            not_approved_changes[key].update({filename: file_changes})
                        else:
                            not_approved_changes.update({key: {filename: file_changes}})
            else:
                not_approved_changes.update({key: value})

        return not_approved_changes

    @staticmethod
    def validate_ide_items(current_file, original_file, commit_filename, ide_key, changes, changes_key):
        """
        check if there are changes in ide items - e.g. action name, action result value
        :param current_file: current_file
        :param original_file: original_file
        :param commit_filename: {string} the filename that modified
        :param ide_key: {string} ide key (e.g. parameters)
        :param changes: {dict} all changes
        :param changes_key: {string} key in changes dict (e.g. ResultValue)
        """
        if current_file.get(ide_key) != original_file.get(ide_key):
            change = {commit_filename: {"OLD Name": original_file.get(ide_key),
                                        "NEW Name": current_file.get(ide_key)}}
            changes[changes_key].update(change)

    def validate_def_file(self, commit_filename, commit_sha, integration_name, changes):
        """
        check for all changes perform on file - compare the modified file to the file existing in specific branch
        :param commit_filename: {string} the filename that modified
        :param commit_sha: {string} sha of the modified file in PR
        :param integration_name: {string} integration name
        :param changes: {dict} all changes
        :return: {dict} all changes
        """
        original_def_sha = self.get_integration_def_files_sha(branch=self.branch_to_compare,
                                                              integration_name=integration_name,
                                                              commit_file_name=commit_filename)
        # pr file
        current_file = json.loads(self.get_file_content(commit_sha), object_pairs_hook=OrderedDict)
        # branch file
        original_file = json.loads(self.get_file_content(original_def_sha), object_pairs_hook=OrderedDict)

        # get detected changes - ide item name, parameters names, param addition, ScriptResultName
        # this is integration .def file
        if commit_filename.endswith(".def"):
            # ide item name handle
            self.validate_ide_items(current_file, original_file, commit_filename, 'Identifier', changes,
                                    RENAMED_IDE_ITEMS_KEY)

            # parameters handle
            self.validate_params(current_file, original_file, 'PropertyName', 'IntegrationProperties', changes,
                                 commit_filename)

        # Connector/action/job def file
        else:
            self.validate_ide_items(current_file, original_file, commit_filename, 'Name',
                                    changes, RENAMED_IDE_ITEMS_KEY)

            self.validate_ide_items(current_file, original_file, commit_filename, 'ScriptResultName', changes,
                                    RENAMED_SCRIPT_RESULT_KEY)

            # params handle - new and missing
            self.validate_params(current_file, original_file, 'Name', 'Parameters', changes, commit_filename)

        return changes

    def changes_validator(self, commits_per_integration):
        """
        Get detected changes - ide item name, parameters names, param addition, ScriptResultName
        :param: commits_per_integration {dict} commits dict per integration
        :return: {dict} changes
        """
        integrations_in_branch = self.get_integrations_list()

        changes = {RENAMED_IDE_ITEMS_KEY: {},
                   NEW_PARAM_KEY: {},
                   MISSING_PARAM_KEY: {},
                   RENAMED_SCRIPT_RESULT_KEY: {},
                   MANDATORY_CHANGE_KEY: {}}

        for integration_name, integrations_commits in commits_per_integration.items():
            if integration_name not in integrations_in_branch:
                # handle adding new integration (no matching folder in the branch to compare)
                continue

            for commit_dict in integrations_commits:
                for commit_filename, commit_sha in commit_dict.items():
                    if commit_filename.endswith(DEF_EXTENSIONS):
                        self.validate_def_file(commit_filename, commit_sha, integration_name, changes)
        # Remove empty values
        return dict([(vkey, vdata) for vkey, vdata in changes.items() if (vdata)])

    def get_pull_request_files(self, pull_number):
        """
        Get all modified files in PR
        :param pull_number: {string} pull request number
        """
        url = "{root}/repos/{owner}/{repo}/pulls/{pull_number}/files".format(root=self.api_root, owner=self.repo_owner,
                                                                             repo=self.repo_name,
                                                                             pull_number=pull_number)
        response = self.session.get(url)
        self.validate_response(response)
        return response.json()

    @staticmethod
    def get_files_per_integration(changed_files):
        """
        build files per integration
        :param: changed_files {list} modified files in PR
        :return: {dict} files per integration
        """
        commits_per_integration = {}
        for change_file in changed_files:
            filename = change_file.get('filename')
            file_sha = change_file.get('sha')
            if filename.split('/')[0] == 'Integrations':
                integration_name = filename.split('/')[1]
                if integration_name in commits_per_integration.keys():
                    commits_per_integration[integration_name].append({filename: file_sha})
                else:
                    commits_per_integration[integration_name] = [{filename: file_sha}]
        return commits_per_integration

    def get_pull_request_commits(self, pull_number):
        """
        Get all commits in PR
        :param pull_number: {string} pull request number
        """
        url = "{root}/repos/{owner}/{repo}/pulls/{pull_number}/commits".format(root=self.api_root,
                                                                               owner=self.repo_owner,
                                                                               repo=self.repo_name,
                                                                               pull_number=pull_number)
        response = self.session.get(url)
        self.validate_response(response)
        return response.json()

    def get_changed_integrations_in_pull_request(self, pull_number):
        """
        Create list of all integrations that have been changed
        :param pull_number: {string} pull request number
        :return: {list} integrations names
        """
        changed_files = self.get_pull_request_files(pull_number)
        integration_names = []

        for changed_file in changed_files:
            # create integration list
            changed_filename = changed_file.get("filename", "")

            if changed_filename.split('/')[0] == 'Integrations':
                integration_name = changed_filename.split('/')[1].split("/")[0]

                if integration_name not in integration_names:
                    integration_names.append(integration_name)

        return integration_names

    def validate_json_example(self, files_per_integration):
        """
        validate json example is ok
        :param files_per_integration: {dict} commits dict per integration
        :return: Tuple of lists (json_example_warning, json_example_format_errors, json_format_errors)
        """
        json_format_errors = []
        json_example_format_errors = []
        json_example_warning = []

        # Validate json format
        for integration_name, integration_files in files_per_integration.items():
            for integration_file in integration_files:
                filename = integration_file.keys()[0]
                if filename.endswith(ACTION_DEF_EXTENSIONS):
                    try:
                        action_config = json.loads(self.get_file_content(integration_file[filename]), object_pairs_hook=OrderedDict)
                        try:
                            # validate json example format
                            if action_config.get("DynamicResultsMetadata"):
                                if action_config.get('DynamicResultsMetadata')[0].get('ResultExample'):
                                    json.loads(action_config.get('DynamicResultsMetadata')[0].get('ResultExample'))
                                else:
                                    # we use (empty string) as the example, when we dont have lab creds to get an example.
                                    # refer to empty string examples as warnings
                                    json_example_warning.append('{0}-{1}'.format(integration_name, filename))

                            else:
                                if filename.startswith('Ping'):
                                    continue
                                # script not have DynamicResultsMetadata
                                print('WARNING! Please note - {0}-{1} NOT have DynamicResultsMetadata field'.format(
                                    integration_name, filename))
                                continue
                        except Exception as e:
                            json_example_format_errors.append(
                                "Integration: {0}. File: {1} \nError: {2}".format(integration_name, filename,
                                                                                  str(e)))

                    except:
                        json_format_errors.append("Integration: {0}. File: {1}".format(integration_name, filename))

        return json_example_warning, json_example_format_errors, json_format_errors

    def validate_json(self, files_per_integration):
        json_format_errors = []
        is_custom_enabled_errors = []

        # Validate json format
        for integration_name, integration_files in files_per_integration.items():
            for integration_file in integration_files:
                filename = integration_file.keys()[0]
                if filename.endswith(DEF_EXTENSIONS):
                    # action_config = json.loads(self.get_file_content(file_sha), object_pairs_hook=OrderedDict)
                    json_data = {}
                    try:
                        json_data = json.loads(self.get_file_content(integration_file[filename]))
                    except:
                        json_format_errors.append('{0}-{1}'.format(integration_name, filename))

                    # Validations on json content
                    if json_data:
                        # Validations for actions connectors and jobs
                        if filename.split(".")[-1] not in ["def"]:
                            # Verify in all objects that IsCustom=False and IsEnabled=True
                            try:
                                if json_data["IsCustom"] or not json_data["IsEnabled"]:
                                    is_custom_enabled_errors.append('{0}-{1}'.format(integration_name, filename))
                            except KeyError:
                                print("Json missing key in Integration: {0}, File: {1}".format(integration_name, filename))

        return json_format_errors, is_custom_enabled_errors

    @staticmethod
    def validate_response(response):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            raise GitHubManagerError(
                "{error} {text}".format(
                    error=error,
                    text=response.json().get("error", response.content)
                )
            )
