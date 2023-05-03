from GitHubManager import GitHubManager, API_ROOT
import sys
import json
import os

APPROVED_CHANGES_PATH = os.path.join(*[os.path.dirname(os.path.abspath(__file__)), "RegressionApproved.json"])


def main():
    repo_name, owner, branch_to_compare, pr_number, git_token = sys.argv[1:]
    print("{0} --- {1} --- {2} --- {3} --- {4}".format(repo_name, owner, branch_to_compare, pr_number, git_token))
    g = GitHubManager(API_ROOT, git_token, repo_owner=owner, repo_name=repo_name, branch_to_compare=branch_to_compare)

    approved_changes = {}
    if os.path.exists(APPROVED_CHANGES_PATH):
        with open(APPROVED_CHANGES_PATH, "r") as f:
            approved_changes = json.loads(f.read())
    else:
        print("WARNING! Approved changes file NOT found.")

    pr_files = g.get_pull_request_files(pr_number)
    files_per_integration = g.get_files_per_integration(pr_files)

    all_changes = g.changes_validator(files_per_integration)
    not_approved_changes = g.get_not_approved_changes(all_changes, approved_changes)

    # if there are changes that not approved - notify & fail the script
    if not_approved_changes:
        print("Detected Regression Issues: \n")
        print(json.dumps(not_approved_changes))
        raise(Exception("There are Regression issues in the Marketplace repo"))
    else:
        print("NOT found Regression issues in Marketplace")


if __name__ == "__main__":
    main()
