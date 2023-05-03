import datetime
import sys
import re
import json
from random import randint
from SiemplifyAction import SiemplifyAction
from ArcSightLoggerManager import ArcSightLoggerManager
from SiemplifyUtils import output_handler, utc_now
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from TIPCommon import extract_configuration_param, extract_action_param, dict_to_flat, construct_csv

from constants import (
    INTEGRATION_NAME,
    SEND_QUERY_SCRIPT_NAME,
    DEFAULT_TIME_FRAME,
    QUERY_STATUS_COMPLETED,
    QUERY_STATUS_RUNNING,
    QUERY_STATUS_STARTING,
    QUERY_STATUS_ERROR,
    DEFAULT_TIME_FRAME,
    TIME_UNIT_MAPPER,
    PAGE_LIMIT
)


@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = SEND_QUERY_SCRIPT_NAME
    mode = u"Main" if is_first_run else u"QueryState"
    siemplify.LOGGER.info(u"----------------- {} - Param Init -----------------".format(mode))

    # Configuration
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Server Address",
                                           input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    # Parameters
    query = extract_action_param(siemplify, param_name=u"Query", is_mandatory=True)
    events_limit = extract_action_param(siemplify, param_name=u"Max Events to Return", default_value=PAGE_LIMIT,
                                        input_type=int)
    time_frame = extract_action_param(siemplify, param_name=u'Time Frame', default_value=DEFAULT_TIME_FRAME)
    fields_to_fetch = extract_action_param(siemplify, param_name=u"Fields to Fetch")
    include_raw_event_data = extract_action_param(siemplify, param_name=u"Include Raw Event Data", default_value=True,
                                                  input_type=bool)
    local_search_only = extract_action_param(siemplify, param_name=u"Local Search Only", default_value=False,
                                                  input_type=bool)
    discover_fields = extract_action_param(siemplify, param_name=u"Discover Fields", default_value=True,
                                                  input_type=bool)
    sort_string = extract_action_param(siemplify, param_name=u"Sort", default_value=u"ascending")

    siemplify.LOGGER.info(u"----------------- {} - Started -----------------".format(mode))

    try:
        if is_first_run:
            output_message, result_value, status = start_operation(siemplify, api_root, username, password, verify_ssl,
                                                                   query, time_frame, local_search_only, discover_fields)
        else:
            session_id, encrypted_token = json.loads(siemplify.parameters[u"additional_data"])
            fields = [f.strip() for f in fields_to_fetch.split(u',') if f.strip()] if fields_to_fetch else []
            output_message, result_value, status = query_operation_status(siemplify, api_root, username, password,
                                                                          encrypted_token, verify_ssl, session_id, query,
                                                                          include_raw_event_data, sort_string, fields,
                                                                          events_limit)

    except Exception as e:
        output_message = u"Error executing action \"Send Query\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        result_value = u'False'
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info(u'----------------- {} - Finished -----------------'.format(mode))
    siemplify.LOGGER.info(
        u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


def start_operation(siemplify, api_root, username, password, verify_ssl, query, time_frame, local_search_only,
                    discover_fields):
    """
    Main SendQuery action
    :param siemplify: SiemplifyAction object
    :param api_root: Server address of the ArcSight Logger instance
    :param username: Username of ArcSight Logger account
    :param password: Password of the ArcSight Logger account
    :param verify_ssl: Sets session verification
    :param query: The query to send to ArcSight Logger event search
    :param time_frame: The time frame to fetch events
    :param local_search_only: If True, ArcSight Logger event search is local only
    :param discover_fields: If True, discover fields in the found events
    :return: {output_message, json result, execution state}
    """
    search_session_id = randint(1, 99999999999999999)
    time_delta = datetime.timedelta(**extract_unit_and_value_from_time_frame(logger=siemplify.LOGGER,
                                                                             time_frame=time_frame))
    current_time = utc_now()
    time_offset = current_time - time_delta
    current_time_string = current_time.isoformat()[:-9] + current_time.isoformat()[26:]
    time_offset_string = time_offset.isoformat()[:-9] + time_offset.isoformat()[26:]
    arcsight_logger_manager = ArcSightLoggerManager(api_root, username, password, verify_ssl,
                                                    siemplify_logger=siemplify.LOGGER)
    try:
        arcsight_logger_manager.login()
        auth_token = arcsight_logger_manager.send_query(search_session_id, query, time_offset_string,
                                                        current_time_string, local_search_only, discover_fields)
        encrypted_token = ArcSightLoggerManager.encrypt_token_json(json.dumps({u'auth_token': auth_token}), password)
        output_message = u'Successfully initialized query. Continuing executing action \"Send Query\".'
    except Exception as e:
        output_message = unicode(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        arcsight_logger_manager.logout()
        return output_message, u"false", EXECUTION_STATE_COMPLETED

    return output_message, json.dumps((search_session_id, encrypted_token)), EXECUTION_STATE_INPROGRESS


def query_operation_status(siemplify, api_root, username, password, encrypted_token, verify_ssl, session_id, query,
                           include_raw_event_data, sort_string, fields_to_fetch, events_limit):
    """
    Main SendQuery action
    :param siemplify: SiemplifyAction object
    :param api_root: Server address of the ArcSight Logger instance
    :param username: Username of ArcSight Logger account
    :param password: Password of the ArcSight Logger account
    :param encrypted_token: Encrypted Auth Token for current session
    :param verify_ssl: Sets session verification
    :param session_id: Search session ID
    :param query: The query to send to ArcSight Logger event search
    :param include_raw_event_data: If True, raw event data is included in the response
    :param sort_string: Sort method to use
    :param fields_to_fetch: Fields to fetch from ArcSight Logger
    :param events_limit: The amount of events to return
    :return: {output message, json result, execution state}
    """
    result_value = u'false'
    output_message = u''
    token_json = json.loads(ArcSightLoggerManager.decrypt_token_json(encrypted_token, password))
    auth_token = token_json.get(u'auth_token')
    arcsight_logger_manager = ArcSightLoggerManager(api_root, username, password, auth_token, verify_ssl,
                                                    siemplify_logger=siemplify.LOGGER)
    arcsight_logger_manager.login()
    query_status = arcsight_logger_manager.get_query_status(session_id)
    if query_status.status == QUERY_STATUS_COMPLETED:
        results = arcsight_logger_manager.get_events_from_query(session_id, include_raw_event_data, fields_to_fetch,
                                                                sort_string, events_limit)
        if results and query_status.hit > 0:
            if fields_to_fetch:
                results = [{k: v for k, v in d.iteritems() if k in fields_to_fetch} for d in results]

            flat_results = map(dict_to_flat, results)
            csv_output = construct_csv(flat_results)
            siemplify.result.add_data_table(u'Results', csv_output)
            siemplify.result.add_result_json(results)
            result_value = u'true'
            output_message = u'Successfully returned events for query \"{}\" from the ArcSight Logger'.format(query)
        else:
            output_message = u'Events were not found for query \"{}\" in ArcSight Logger'.format(query)

    elif query_status.status == QUERY_STATUS_STARTING or query_status.status == QUERY_STATUS_RUNNING:
        output_message = u'Starting processing query \"{}\" in ArcSight Logger'.format(query)
        return output_message, json.dumps((session_id, encrypted_token)), EXECUTION_STATE_INPROGRESS
    elif query_status.status == QUERY_STATUS_ERROR:
        output_message = u'Unable to execute query \"{}\" in ArcSight Logger'.format(query)

    arcsight_logger_manager.logout()
    return output_message, result_value, EXECUTION_STATE_COMPLETED


def extract_unit_and_value_from_time_frame(logger, time_frame):
    try:
        value, unit = re.findall(r'(\d*)(\w)', time_frame)[0]
        value = int(value)
        return {TIME_UNIT_MAPPER[unit]: int(value)}
    except Exception as e:
        logger.warn(u'Unable to extract provided time frame "{}". Using default time frame instead "{}"'.format(
            time_frame, DEFAULT_TIME_FRAME))
        value, unit = re.findall(r'(\d*)(\w)', DEFAULT_TIME_FRAME)[0]
        return {TIME_UNIT_MAPPER[unit]: int(value)}


if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == u'True'
    main(is_first_run)