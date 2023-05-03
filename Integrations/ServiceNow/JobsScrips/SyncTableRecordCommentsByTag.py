from TIPCommon import extract_action_param
from constants import (
    INTEGRATION_NAME,
    SYNC_COMMENTS_BY_TAG,
    SERVICE_NOW_TAG,
    RECORDS_TAG,
    TAG_SEPARATOR,
    CASE_STATUS_OPEN,
    SIEMPLIFY_COMMENT_PREFIX,
    SN_COMMENT_PREFIX
)
from ServiceNowManager import ServiceNowManager, ServiceNowRecordNotFoundException
from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler, convert_datetime_to_unix_time, unix_now


def get_comment_body(comment):
    """
    Get comment body
    :param comment: {Comment or dict}
    :return: {str} pure comment body
    """
    if isinstance(comment, dict):
        return clean_prefix(comment.get('comment'))

    return clean_prefix(comment.value)


def clean_prefix(comment_body):
    """
    Clean comment prefixes
    :param comment_body: {str} comment with prefix
    :return: {str}
    """
    if comment_body.startswith(SIEMPLIFY_COMMENT_PREFIX):
        clean_body = comment_body.split(SIEMPLIFY_COMMENT_PREFIX, 1)
    elif comment_body.startswith(SN_COMMENT_PREFIX):
        clean_body = comment_body.split(SN_COMMENT_PREFIX, 1)
    else:
        clean_body = comment_body

    return ''.join(clean_body)


def get_new_comments_to_add(case_comments, sn_comments):
    """
    Extract new comments from Servicenow and Siemplify
    :param case_comments: {list} List of Siemplify comments
    :param sn_comments: {sn_comments} List of Servicenow comments
    :return: {tuple} Of comments from case and comments from servicenow
    """
    new_comments_from_sn = sn_comments.copy()
    new_comments_from_case = case_comments.copy()

    for case_comment in case_comments:
        if case_comment in new_comments_from_sn:
            new_comments_from_sn.remove(case_comment)

    for sn_comment in sn_comments:
        if sn_comment in new_comments_from_case:
            new_comments_from_case.remove(sn_comment)

    return new_comments_from_case, new_comments_from_sn


def comments_mapper(comments):
    """
    Map comments bodies
    :param comments {list} List of comments
    """
    return [get_comment_body(comment) for comment in comments]


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SYNC_COMMENTS_BY_TAG
    siemplify.LOGGER.info('--------------- JOB STARTED ---------------')

    api_root = extract_action_param(siemplify=siemplify, param_name='API Root', is_mandatory=True, print_value=True)
    username = extract_action_param(siemplify=siemplify, param_name='Username', is_mandatory=True, print_value=True)
    password = extract_action_param(siemplify=siemplify, param_name='Password', is_mandatory=True)
    verify_ssl = extract_action_param(siemplify=siemplify, param_name='Verify SSL', is_mandatory=True,
                                      default_value=True, input_type=bool, print_value=True)
    table_name = extract_action_param(siemplify=siemplify, param_name='Table Name', is_mandatory=True, print_value=True)

    try:

        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=table_name, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER)

        cases_id = siemplify.get_cases_by_filter(tags=[SERVICE_NOW_TAG.format(table_name=table_name)],
                                                 statuses=[CASE_STATUS_OPEN])

        open_cases = {str(case_id): get_full_case_details(siemplify, case_id) for case_id in cases_id}

        siemplify.LOGGER.info(
            'Found {} open cases with tag {}.'.format(len(open_cases), SERVICE_NOW_TAG.format(table_name=table_name)))

        siemplify.LOGGER.info('--- Start synchronize comments ServiceNow <-> Siemplify ---')

        for case_id, case in open_cases.items():
            siemplify.LOGGER.info('Started processing case: {0}'.format(case_id))
            case_tags = [item.get("tag") for item in case.get("tags", []) if RECORDS_TAG in item.get("tag")]
            record_ids = [tag.split(TAG_SEPARATOR)[1].strip() for tag in case_tags]
            if record_ids:
                record_id = record_ids[0]
                try:
                    ticket_sys_id = service_now_manager.get_ticket_id(ticket_number=record_id, table_name=table_name)
                    ticket_comments = service_now_manager.get_ticket_comments(
                        [ticket_sys_id],
                        fields=['element_id', 'value'],
                        table_name=table_name
                    )
                    case_comments = siemplify.get_case_comments(case_id)
                    raw_case_comments = comments_mapper(case_comments)
                    raw_sn_comments = comments_mapper(ticket_comments)
                    new_comments_from_case, new_comments_from_sn = get_new_comments_to_add(raw_case_comments,
                                                                                           raw_sn_comments)
                    if not new_comments_from_case and not new_comments_from_sn:
                        continue

                    # Sync ServiceNow with Siemplify
                    if new_comments_from_case:
                        siemplify.LOGGER.info(
                            'Found {} comments to add in ServiceNow.'.format(len(new_comments_from_case)))

                    for si_comment in new_comments_from_case:
                        try:
                            comment_with_prefix = '{}{}'.format(SIEMPLIFY_COMMENT_PREFIX, si_comment)
                            service_now_manager.add_work_note_to_incident(record_id, comment_with_prefix, table_name)
                            siemplify.LOGGER.info('Added comment to ticket {0}'.format(record_id))
                        except ServiceNowRecordNotFoundException as e:
                            siemplify.LOGGER.error(e)
                        except Exception as e:
                            siemplify.LOGGER.error(
                                'Failed to add comment to ticket {}, Reason: {}'.format(record_id, e))
                            siemplify.LOGGER.exception(e)

                    # Sync Siemplify with ServiceNow
                    if new_comments_from_sn:
                        siemplify.LOGGER.info('Found {} comments to add in Siemplify.'.format(len(new_comments_from_sn)))

                    for sn_comment in new_comments_from_sn:
                        try:
                            comment_with_prefix = '{}{}'.format(SN_COMMENT_PREFIX, sn_comment)
                            siemplify.add_comment(comment_with_prefix, case_id, None)
                            siemplify.LOGGER.info('Added comment to case with id: {0}'.format(case_id))
                        except Exception as e:
                            siemplify.LOGGER.error('Failed to add comment to case {0}, Reason: {1}'.format(case_id, e))
                            siemplify.LOGGER.exception(e)

                except Exception as e:
                    siemplify.LOGGER.error('Error processing case with id {}. Ticket ID: {}.'.format(case_id, record_id))
                    siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info('Finished processing case: {0}'.format(case_id))

        siemplify.LOGGER.info('--- Finish synchronize comments ServiceNow <-> Siemplify ---')
        siemplify.LOGGER.info('--------------- JOB FINISHED ---------------')

    except Exception as error:
        siemplify.LOGGER.error(f'Got exception on main handler. Error: {error}')
        siemplify.LOGGER.exception(error)
        raise


def get_full_case_details(siemplify, case_id):
    address = "{0}/{1}/{2}{3}".format(siemplify.sdk_config.api_root_uri, "external/v1/cases/GetCaseFullDetails",
                                      case_id, "?format=snake")
    response = siemplify.session.get(address)
    siemplify.validate_siemplify_error(response)
    return response.json()


if __name__ == '__main__':
    main()
