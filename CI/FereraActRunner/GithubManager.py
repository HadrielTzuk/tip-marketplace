# =====================================
#              IMPORTS                #
# =====================================
import base64
import json
import requests
import sys

# =====================================
#             CONSTANTS               #
# =====================================
HEADERS = {"Content-Type": "application/json"}
API_ROOT = "https://api.github.com"


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

    def __init__(self, api_root, api_token, repo_name, repo_owner, verify_ssl=False):
        self.api_root = api_root
        self.repo_name = repo_name
        self.repo_owner = repo_owner
        self.session = requests.session()
        self.session.verify = verify_ssl
        self.session.headers["Authorization"] = "token {}".format(api_token)

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

    def get_pull_request_commits(self, pull_number):
        url = "{root}/repos/{owner}/{repo}/pulls/{pull_number}/commits".format(root=self.api_root, owner=self.repo_owner,
                                                                   repo=self.repo_name, pull_number=pull_number)
        response = self.session.get(url)
        self.validate_response(response)
        return response.json()

    def get_pull_request_files(self, pull_number):
        url = "{root}/repos/{owner}/{repo}/pulls/{pull_number}/files".format(root=self.api_root, owner=self.repo_owner,
                                                                   repo=self.repo_name, pull_number=pull_number)
        response = self.session.get(url)
        self.validate_response(response)
        return response.json()

    def get_changed_integrations_in_pull_request(self, pull_number):
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