from GitHubManager import GitHubManager, API_ROOT
import sys


def main():
    repo_name, owner, branch_to_compare, pr_number, git_token = sys.argv[1:]
    print("{0} --- {1} --- {2} --- {3} --- {4}".format(repo_name, owner, branch_to_compare, pr_number, git_token))
    g = GitHubManager(API_ROOT, git_token, repo_owner=owner, repo_name=repo_name, branch_to_compare=branch_to_compare)

    pr_files = g.get_pull_request_files(pr_number)
    files_per_integration = g.get_files_per_integration(pr_files)
    not_updated_integrations = g.validate_version_update(files_per_integration)
    if not_updated_integrations:
        print("Versions NOT update on the following Integrations:")
        print("\n".join(not_updated_integrations))
        raise Exception("There are Integrations with wrong version!")


if __name__ == "__main__":
    main()
