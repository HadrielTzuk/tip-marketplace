from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from RSAManager import RSAManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    RUN_GENERAL_QUERY_ACTION,
    DEFAULT_HOURS_BACKWARDS,
    DEFAULT_EVENTS_LIMIT
)

TITLE = 'Result PCAP'
FILE_NAME = 'result_pcap.pcap'
TABLE_NAME = 'Result Events'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = RUN_GENERAL_QUERY_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configuration
    broker_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Broker API Root")
    broker_username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Broker API Username")
    broker_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Broker API Password")
    concentrator_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                        param_name="Concentrator API Root")
    concentrator_username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                        param_name="Concentrator API Username")
    concentrator_password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                        param_name="Concentrator API Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)

    # Parameters
    query = extract_action_param(siemplify, param_name="Query", is_mandatory=True, print_value=True)
    hours_backwards = extract_action_param(siemplify, param_name="Max Hours Backwards",
                                           default_value=DEFAULT_HOURS_BACKWARDS, input_type=int)
    events_limit = extract_action_param(siemplify, param_name="Max Events To Return",
                                        default_value=DEFAULT_EVENTS_LIMIT, input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = ''
    events = []

    try:
        rsa_manager = RSAManager(broker_api_root=broker_api_root, broker_username=broker_username,
                                 broker_password=broker_password, concentrator_api_root=concentrator_api_root,
                                 concentrator_username=concentrator_username,
                                 concentrator_password=concentrator_password, size=events_limit, verify_ssl=verify_ssl)

        session_ids = rsa_manager.get_session_ids_for_query(hours_backwards, query)

        if session_ids:
            # Get PCAP file.
            pcap_content = rsa_manager.get_pcap_of_session_id(','.join(session_ids))
            siemplify.result.add_attachment(TITLE, FILE_NAME, pcap_content)
            # Get Events.
            for session_id in session_ids:
                try:
                    events.append(rsa_manager.get_metadata_from_session_id(session_id))
                except Exception as err:
                    error_massage = "Error retrieving event for session ID: {0}, ERROR: {1}".format(
                        session_id,
                        err.message
                    )
                    siemplify.LOGGER.error(error_massage)
                    siemplify.LOGGER.exception(err)

            if events:
                siemplify.result.add_data_table(TABLE_NAME, construct_csv([event.to_csv() for event in events]))
                result_value = [event.to_json() for event in events]

        if result_value:
            output_message = 'Found results for query - "{0}"'.format(query)
        else:
            output_message = 'No results found for query - "{0}"'.format(query)

        siemplify.result.add_result_json(events)

    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(RUN_GENERAL_QUERY_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
