from GitHubManager import GitHubManager, API_ROOT
import sys


def main():
    repo_name, owner, branch_to_compare, pr_number, git_token = sys.argv[1:]
    print "{0} --- {1} --- {2} --- {3} --- {4}".format(repo_name, owner, branch_to_compare, pr_number, git_token)
    g = GitHubManager(API_ROOT, git_token, repo_owner=owner, repo_name=repo_name, branch_to_compare=branch_to_compare)

    fail_script = False
    pr_files = g.get_pull_request_files(pr_number)
    files_per_integration = g.get_files_per_integration(pr_files)
    json_example_warning, json_example_format_errors, json_format_errors = g.validate_json_example(files_per_integration)

    if json_example_warning:
        print "\nWARNING! Please note that the following paths are MISSING DynamicResultsMetadata value"
        print "\n".join(json_example_warning)

    if json_example_format_errors:
        print "\nJson Examples errors on the following paths:"
        print "\n".join(json_example_format_errors)
        fail_script = True

    if json_format_errors:
        print "\nJson errors on the following paths:"
        print "\n".join(json_format_errors)
        fail_script = True

    if fail_script:
        raise Exception("There are corrupted Jason's in the Marketplace repo")

    else:
        print "\nAll marketplace json examples are good!!!"


if __name__ == "__main__":
    main()


