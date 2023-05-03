import os
import datetime
import time

import requests
import json
import glob

MARKETPLACE_INTEGRATIONS_PATH = "../../Integrations"
GIT_RN_PATH = "Integrations/{}/RN.json"

class GithubManager(object):
    def __init__(self, org, repo, username, password):
        self.session = requests.Session()
        self.base_api = f"https://api.github.com/repos/{org}/{repo}"
        self.session.auth = (username, password)

    def get_last_commit_for_file(self, file_path):
        url = self.base_api + "/commits"
        params = {"path": file_path, "page": 1, "per_page": 1}
        res = self.session.get(url, params=params)
        res.raise_for_status()
        return res.json()


def main():
    git_manage = GithubManager("Siemplify", "SiemplifyMarketPlace", "OrGabay", "******")
    for integration_name in os.listdir(MARKETPLACE_INTEGRATIONS_PATH):
        print("Processing Integration: {}".format(integration_name))
        integration_path = os.path.join(MARKETPLACE_INTEGRATIONS_PATH, integration_name)
        integration_def_file_name_seacrh_results = glob.glob(os.path.join(integration_path, "*.def"))
        if integration_def_file_name_seacrh_results:
            integration_def_file_name = integration_def_file_name_seacrh_results[0]
        else:
            print("Cannot find def file for {}".format(integration_name))
            continue
        integration_def_path = os.path.join(integration_path, integration_def_file_name)
        with open(integration_def_path, 'r') as integration_file:
            try:
                integration_def = json.loads(integration_file.read())
            except Exception as e:
                raise Exception("Error loading integration def: {}".format(integration_def_path))

        release_notes_path = os.path.join(integration_path, "RN.json")
        if os.path.exists(release_notes_path):
            with open(release_notes_path, 'r') as rn_file:
                try:
                    rn_def = json.loads(rn_file.read())
                except Exception as e:
                    raise Exception("Error loading release notes def: {}, {}".format(release_notes_path, e))
            if len(rn_def) > 0:
                commit = git_manage.get_last_commit_for_file(GIT_RN_PATH.format(integration_name))
                commit_date = commit[0]["commit"]["committer"]["date"]
                commit_datetime = datetime.datetime.strptime(commit_date, "%Y-%m-%dT%H:%M:%SZ")
                commit_timestamp = int(time.mktime(commit_datetime.timetuple()))
                rn_def[-1]["PublishTime"] = commit_timestamp
                with open(release_notes_path, 'w') as rn_file:
                    rn_file.write(json.dumps(rn_def, indent=4, sort_keys=True))


if __name__ == '__main__':
    main()