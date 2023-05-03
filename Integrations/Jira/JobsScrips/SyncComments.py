from datetime import timezone

import requests
import urllib3
from JiraConstants import SYNC_COMMENTS_SCRIPT, DEFAULT_DAYS_BACKWARDS, DEFAULT_SIEMPLIFY_COMMENT_PREFIX, DEFAULT_JIRA_COMMENT_PREFIX, \
    JIRA_TAG, CASE_STATUS_OPEN, MIN_DAYS_BACKWARDS, PRODUCT, JIRA_TIME_FORMAT
from JiraManager import JiraManager
from exceptions import JiraManagerError
from utils import load_csv_to_list
from TIPCommon import get_last_success_time

from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import convert_unixtime_to_datetime, unix_now, output_handler, convert_datetime_to_unix_time


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SYNC_COMMENTS_SCRIPT
    siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

    api_root = siemplify.extract_job_param(param_name='API Root', is_mandatory=True, print_value=True)
    username = siemplify.extract_job_param(param_name='Username', is_mandatory=True, print_value=True)
    api_token = siemplify.extract_job_param(param_name='API Token', is_mandatory=True, print_value=False)
    project_names = siemplify.extract_job_param(param_name='Project Names', is_mandatory=False, print_value=True)

    try:
        days_backwards = siemplify.extract_job_param(param_name='Days Backwards', input_type=int, default_value=DEFAULT_DAYS_BACKWARDS,
                                                     is_mandatory=False, print_value=True)
        siemplify_comment_prefix = siemplify.extract_job_param(param_name='Siemplify Comment Prefix', is_mandatory=True, print_value=True,
                                                               default_value=DEFAULT_SIEMPLIFY_COMMENT_PREFIX)
        jira_comment_prefix = siemplify.extract_job_param(param_name='Jira Comment Prefix', is_mandatory=True,
                                                          default_value=DEFAULT_JIRA_COMMENT_PREFIX, print_value=True)
        project_names = load_csv_to_list(project_names, "Project Names")
        fetch_time = get_last_success_time(siemplify, offset_with_metric={'days': days_backwards}, print_value=False)
        fetch_time_ms = convert_datetime_to_unix_time(fetch_time)
        siemplify.LOGGER.info('Last fetch time. Date time:{}. Unix:{}'.format(fetch_time, fetch_time_ms))
        new_timestamp = unix_now()

        if days_backwards < MIN_DAYS_BACKWARDS:
            raise Exception("\"Days Backwards\" parameter must be greater or equal than {}".format(MIN_DAYS_BACKWARDS))

        jira_manager = JiraManager(api_root, username, api_token, logger=siemplify.LOGGER)

        siemplify.LOGGER.info('--- Start synchronizing Issues Comments from Siemplify to Jira ---')

        fetched_open_cases_ids = siemplify.get_cases_by_filter(statuses=[CASE_STATUS_OPEN], tags=[JIRA_TAG])
        siemplify.LOGGER.info('Found {} open cases with tag {}'.format(len(fetched_open_cases_ids), JIRA_TAG))

        for case_id in fetched_open_cases_ids:
            case = siemplify._get_case_by_id(case_id)
            case_identifier = case.get("identifier")
            case_comments = siemplify.get_case_comments(case_identifier)

            for comment in case_comments:
                comment_time = convert_unixtime_to_datetime(comment.get("modification_time_unix_time_in_ms"))

                # Filter already created comments and comments that already were processed by the job
                if comment_time < fetch_time or comment.get("comment", jira_comment_prefix).startswith(jira_comment_prefix):
                    continue

                # Update all cases related to issue of Jira
                for alert in case.get('cyber_alerts', []):
                    issue_key = alert.get('additional_data') if alert.get('reporting_product') != PRODUCT \
                        else alert.get('additional_properties', {}).get('AlertName')
                    issue_project = alert.get("security_events", [])[0].get("additional_properties", {}).get("project_name")

                    if issue_project not in project_names:
                        siemplify.LOGGER.info(f"Alert with issue key {issue_key} of project {issue_project} is not in projects:"
                                              f" {', '.join(project_names)}")
                        continue

                    if issue_key:
                        # Add the comment to Jira ticket
                        try:
                            comment_text = "{0} {1}".format(siemplify_comment_prefix, comment.get("comment"))
                            siemplify.LOGGER.info(f"Adding jira comment with id {comment.get('id')} to issue {issue_key}")
                            jira_manager.add_comment(issue_key, comment_text)
                            siemplify.LOGGER.info("Successfully added comment to issue {}".format(issue_key))
                        except Exception as error:
                            siemplify.LOGGER.error(f"Failed to add comment to issue {issue_key}, error: {error}")
                            siemplify.LOGGER.exception(error)
                    else:
                        siemplify.LOGGER.info(f"Cannot find issue key. Comments from case {case_identifier} not added to issue")

        siemplify.LOGGER.info(" --- Finish synchronize comments from Siemplify cases to Jira issues --- ")
        siemplify.LOGGER.info('--- Start synchronize Issues Comments from Jira to Siemplify ---')

        # Adjust fetch time to JIRA server's timezone
        jira_server_time = jira_manager.get_server_time()
        siemplify.LOGGER.info("JIRA server time: {}".format(jira_server_time.isoformat()))
        fetch_time_jira_timezone_adjusted = fetch_time.replace(tzinfo=timezone.utc).astimezone(jira_server_time.tzinfo)
        siemplify.LOGGER.info("Adjusted last fetch time to server time: {}".format(fetch_time_jira_timezone_adjusted.isoformat()))

        jira_last_time_format = fetch_time_jira_timezone_adjusted.strftime(JIRA_TIME_FORMAT)
        # Fetch modified issues since last fetch time
        last_modified_issues = jira_manager.list_issues(
            updated_from=jira_last_time_format,
            project_key_list=project_names
        )
        siemplify.LOGGER.info(f'Found {len(last_modified_issues)} issues that modified since '
                              f'{fetch_time_jira_timezone_adjusted.isoformat()} (Server Timezone)')

        for issue_key in last_modified_issues:
            comments_to_add = jira_manager.get_issue_comments_since_time(issue_key, fetch_time_ms)
            siemplify.LOGGER.info(f"{issue_key} has {len(comments_to_add)} comments since {fetch_time.isoformat()}")

            # Filter jira issue comments that were added by siemplify
            comments_to_add = [comment for comment in comments_to_add if
                               comment.body and siemplify_comment_prefix not in comment.body]

            if not comments_to_add:
                siemplify.LOGGER.info(f"No new comments found in issue: {issue_key}")
                continue

            siemplify.LOGGER.info(f"Found {len(comments_to_add)} new comments of issue {issue_key} to add to siemplify")

            try:
                # Find corresponding Siemplify cases to add comment
                cases_ids_for_issue = siemplify.get_cases_by_filter(ticked_ids_free_search=issue_key, tags=[JIRA_TAG],
                                                                    statuses=[CASE_STATUS_OPEN])
                if not cases_ids_for_issue:
                    siemplify.LOGGER.info(f"No open siemplify cases were found for issue key {issue_key} and tag {JIRA_TAG}")
                    continue

                for case_id in cases_ids_for_issue:
                    if comments_to_add:
                        for comment in comments_to_add:
                            try:
                                siemplify.LOGGER.info(f"Adding jira comment with id {comment.id} to case with id {case_id}")
                                comment_text = "{0} {1}".format(jira_comment_prefix, comment.body)
                                siemplify.add_comment(comment_text, case_id, None)
                                siemplify.LOGGER.info(f"Successfully added comment to case")
                            except Exception as error:
                                siemplify.LOGGER.error(f"Failed to add jira comment with id {comment.id} to case with id {case_id}")
                                siemplify.LOGGER.exception(error)

            except Exception as error:
                siemplify.LOGGER.error(f"Failed to sync jira issue key {issue_key} comments with corresponding siemplify case")
                siemplify.LOGGER.exception(error)

        siemplify.save_timestamp(new_timestamp=new_timestamp)
        siemplify.LOGGER.info(" --- Finish synchronize comments from Jira issues to cases --- ")
        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except (JiraManagerError, Exception) as error:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {error}')
        siemplify.LOGGER.exception(error)
        raise


if __name__ == '__main__':
    main()
