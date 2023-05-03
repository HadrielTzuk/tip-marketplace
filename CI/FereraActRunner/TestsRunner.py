import re
import os
import sys
import copy
import collections
import argparse
import json
import pytest

from GithubManager import GitHubManager, API_ROOT
import datetime


CONFIG_FILE = "config.json"
INTEGRATIONS_CONFIG_FILE = "integrations_config.json"
REPORTS_DIR = os.path.join("Reports")
INI_FILE = "pytest.ini"

TOTAL_TESTS_PATTERN = r"([0-9]*) tests ran in"
PASSED_TESTS_PATTERN = r"([0-9]*) passed"
FAILED_TESTS_PATTERN = r"([0-9]*) failed"
ERRORS_TESTS_PATTERN = r"([0-9]*) errors"
SKIPPED_TESTS_PATTERN = r"([0-9]*) skipped"


def parse_args():
    parser = argparse.ArgumentParser(description='Description of your program')
    parser.add_argument('-m', '--marketplace-folder', help='Marketplace location (without Integrations folder)',
                        default=r"C:\Siemplify_Server\Marketplace")
    parser.add_argument('-a', '--api_root', help='Siemplify Server API root')
    parser.add_argument('-u', '--username', help='Siemplify Admin username')
    parser.add_argument('-p', '--password', help='Siemplify Admin password')
    parser.add_argument('-e', '--environment', help='Siemplify environment to use for tests.')
    parser.add_argument('-r', '--marketplace-repo', help='Siemplify marketplace repository name')
    parser.add_argument('-o', '--repo-owner', help='Siemplify marketplace repository owner name')
    parser.add_argument('-g', '--github-token', help='Github token')
    parser.add_argument('-n', '--pull-request-number', help='Pull request number')
    parser.add_argument('-f', '--ferera-act-root-path', help='Ferera Act root directory')
    parser.add_argument('-s', '--skip-integration-installation', help='Whether to skip the integration installation',
                        default=False, action='store_true')

    return parser.parse_args()


def reconfigure(ferera_act_root_path, old_config, args):
    new_config = {
        "skip_integration_installation": args.skip_integration_installation,
        "api_root": args.api_root,
        "username": args.username,
        "password": args.password,
        "environment": args.environment
    }

    new_config = {k: v for k, v in new_config.iteritems() if v is not None}
    updated_config = copy.deepcopy(old_config)
    updated_config.update(new_config)

    # Override default config
    with open(os.path.join(ferera_act_root_path, CONFIG_FILE), 'w') as config:
        config.write(json.dumps(updated_config, indent=4))

    return updated_config


def main():
    args = parse_args()
    os.chdir(args.ferera_act_root_path)

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # pull_number = System.PullRequest.PullRequestNumber
    github_manager = GitHubManager(API_ROOT, args.github_token, repo_owner=args.repo_owner, repo_name=args.marketplace_repo)

    changed_integrations = github_manager.get_changed_integrations_in_pull_request(args.pull_request_number)

    if not os.path.exists(os.path.join(args.ferera_act_root_path, REPORTS_DIR)):
        os.makedirs(os.path.join(args.ferera_act_root_path, REPORTS_DIR))

    # Load older config
    with open(os.path.join(args.ferera_act_root_path, CONFIG_FILE), 'r') as config:
        old_config = json.loads(config.read(), object_pairs_hook=collections.OrderedDict)

    # Load integration config
    with open(os.path.join(args.ferera_act_root_path, INTEGRATIONS_CONFIG_FILE), 'r') as config:
        integrations_config = json.loads(config.read(), object_pairs_hook=collections.OrderedDict)

    reconfigure(args.ferera_act_root_path, old_config, args)

    short_summary_of_tests_status = ''
    json_summary_report = {}
    is_failed = False

    if not changed_integrations:
        print "FERERA-ACT: No integrations were changed."

    reports_folder = os.path.join(*[args.ferera_act_root_path, REPORTS_DIR, timestamp])

    if not os.path.exists(reports_folder):
        os.makedirs(reports_folder)

    for integration_name in changed_integrations:
        print "\nFERERA-ACT: ======= {} =======".format(integration_name)
        integration_config = integrations_config.get(integration_name, {})

        # Verify integration tests are enabled
        if integration_config.get("enabled"):
            print "FERERA-ACT: Tests are enabled."
            # Construct integration folder in marketplace
            # integration_folder_path = os.path.join(args.marketplace_folder, "Integrations", integration_name)
            integration_folder_path = os.path.join(args.ferera_act_root_path, integration_name)

            # Configure report for integration test
            report_name = "{}_Tests_Report.html".format(integration_name)

            report_path = os.path.relpath(os.path.join(reports_folder, report_name))
            report_arg = '--html={}'.format(report_path)


            print "FERERA-ACT: Reports location: {}".format(report_path)

            # Run tests
            print "FERERA-ACT: Running tests."
            result = pytest.main(
                [integration_folder_path, '-vs', report_arg, '--self-contained-html', '--rootdir', args.ferera_act_root_path, '-c',
                 os.path.join(args.ferera_act_root_path, INI_FILE)])

            print "FERERA-ACT: Pytest has finished."

            # Create additional reports
            try:
                with open(str(report_path)) as f:
                    html = f.read()
                    total_tests = int(re.search(TOTAL_TESTS_PATTERN, html).groups()[0])
                    passed_tests = int(re.search(PASSED_TESTS_PATTERN, html).groups()[0])
                    failed_tests = int(re.search(FAILED_TESTS_PATTERN, html).groups()[0])
                    skipped_tests = int(re.search(SKIPPED_TESTS_PATTERN, html).groups()[0])
                    error_tests = int(re.search(ERRORS_TESTS_PATTERN, html).groups()[0])

                    if failed_tests or error_tests:
                        is_failed = True

                    short_summary_of_tests_status += '{}: Total - {}, Passed - {}, Failed - {}, Skipped - {}, Errors - {}\n'.format(
                        integration_name,
                        total_tests,
                        passed_tests,
                        failed_tests,
                        skipped_tests,
                        error_tests
                    )

                    json_summary_report[integration_name] = {
                        "passed":  passed_tests,
                        "total": total_tests,
                        "failed": failed_tests,
                        "errors": error_tests,
                        "skipped": skipped_tests,
                        "report_failed": False,
                        "integration_enabled": True,
                        "reason": "Completed."
                    }

                    print json.dumps(json_summary_report[integration_name], indent=4)
                    print "FERERA-ACT: Tests are DONE."

            except Exception as e:
                is_failed = True

                short_summary_of_tests_status += '{}: Failed to gather results from report.'.format(integration_name)
                json_summary_report[integration_name] = {
                    "passed": 0,
                    "total": 0,
                    "failed": 0,
                    "errors": 0,
                    "skipped": 0,
                    "integration_enabled": True,
                    "report_failed": True,
                    "reason": str(e)
                }
                print json.dumps(json_summary_report[integration_name], indent=4)
                print "FERERA-ACT: Tests result collection FAILED."

        else:
            print "FERERA-ACT: Tests are disabled."
            # Integration is disabled
            short_summary_of_tests_status += '{}: Disabled. Reason: {} \n'.format(integration_name, integration_config.get("reason"))
            json_summary_report[integration_name] = {
                "passed": 0,
                "total": 0,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "report_failed": False,
                "integration_enabled": False,
                "reason": integration_config.get("reason")
            }

    # Write short summary of test status
    summary_path = os.path.join(*[args.ferera_act_root_path, REPORTS_DIR, timestamp, 'short_summary_tests_report.txt'])
    with open(summary_path, "w") as summary:
        summary.write(short_summary_of_tests_status)

    # Write json short summary of test status
    json_summary_path = os.path.join(*[args.ferera_act_root_path, REPORTS_DIR, timestamp, 'json_summary_report.json'])
    with open(json_summary_path, "w") as summary:
        summary.write(json.dumps(json_summary_report, indent=4))

    # Return the old config back
    with open(os.path.join(args.ferera_act_root_path, CONFIG_FILE), 'w') as config:
        config.write(json.dumps(old_config, indent=4))

    if short_summary_of_tests_status:
        print "\n\nFERERA-ACT: ====== RESULTS ======\n"
        print short_summary_of_tests_status

    if is_failed:
        raise Exception("Some tests have failed. Please look at the report: {}".format(json_summary_path))


if __name__ == "__main__":
    main()
