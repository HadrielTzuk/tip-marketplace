from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, \
    convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CBEnterpriseEDRManager import CBEnterpriseEDRManager, CBEnterpriseEDRUnauthorizedError
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"CBEnterpriseEDR"
SCRIPT_NAME = u"Get Events Associated With Process by Process Guid"
SUPPORTED_ENTITIES = [EntityTypes.PROCESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    org_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Organization Key",
                                          is_mandatory=True, input_type=unicode)
    api_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API ID",
                                         is_mandatory=True, input_type=unicode)
    api_secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                 param_name=u"API Secret Key",
                                                 is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    process_guids = extract_action_param(siemplify, param_name=u"Process GUID", is_mandatory=True,
                                       input_type=unicode, print_value=True)

    event_types = extract_action_param(siemplify, param_name=u"Search Criteria", is_mandatory=False,
                                 input_type=unicode, print_value=True)

    query = extract_action_param(siemplify, param_name=u"Query", is_mandatory=True,
                                 input_type=unicode, print_value=True)

    timeframe = extract_action_param(siemplify, param_name=u"Time Frame", is_mandatory=False,
                                     input_type=int, print_value=True)

    record_limit = extract_action_param(siemplify, param_name=u"Record limit", is_mandatory=True,
                                        input_type=int, print_value=True)

    sort_by = extract_action_param(siemplify, param_name=u"Sort By", is_mandatory=False,
                                   input_type=unicode, print_value=True)

    sort_order = extract_action_param(siemplify, param_name=u"Sort Order", is_mandatory=False,
                                      input_type=unicode, default_value=u"ASC", print_value=True)

    if event_types:
        event_types = [event_type.strip() for event_type in event_types.split(u",")]

    process_guids = [process_guid.strip() for process_guid in process_guids.split(u",")]

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    json_results = {}
    failed_entities = []
    missing_entities = []
    output_message = u""

    try:
        cb_edr_manager = CBEnterpriseEDRManager(api_root, org_key, api_id, api_secret_key, verify_ssl)

        for process_guid in process_guids:
            try:
                siemplify.LOGGER.info(u"Started processing process: {}".format(process_guid))

                siemplify.LOGGER.info(u"Initializing events search for process {}".format(process_guid))
                events = cb_edr_manager.events_search(
                    process_guid=process_guid,
                    event_types=event_types,
                    query=query,
                    sort_by=sort_by,
                    sort_order=sort_order,
                    timeframe=timeframe,
                    limit=record_limit
                )

                json_results[process_guid] = [event.raw_data for event in events]

                if events:
                    siemplify.LOGGER.info(u"Found {} results for {}".format(len(events), process_guid))
                    siemplify.result.add_data_table(u"Found events for process {}".format(process_guid),
                                                    construct_csv([event.to_csv() for event in events]))
                    successful_entities.append(process_guid)

                else:
                    siemplify.LOGGER.info(u"No results were found for {}".format(process_guid))
                    missing_entities.append(process_guid)

                siemplify.LOGGER.info(u"Finished processing process {0}".format(process_guid))

            except CBEnterpriseEDRUnauthorizedError as e:
                # Unauthorized - invalid credentials were passed. Terminate action
                siemplify.LOGGER.error(u"Failed to execute action! Error is {}".format(e))
                siemplify.end(u"Failed to execute action! Error is {}".format(e), u"false",
                              EXECUTION_STATE_FAILED)

            except Exception as e:
                failed_entities.append(process_guid)
                siemplify.LOGGER.error(u"An error occurred on process {0}".format(process_guid))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Found events for the following process guids:\n   {}".format(
                u"\n   ".join(successful_entities)
            )
            result_value = u"true"

        else:
            output_message += u"No search results were returned."
            result_value = u"false"

        if missing_entities:
            output_message += u"\n\nNo events were returned for the following entities:\n   {}".format(
                u"\n   ".join(missing_entities)
            )

        if failed_entities:
            output_message += u"\n\nFailed to get results because of the errors running search for the following process guids:\n   {}".format(
                u"\n   ".join(failed_entities)
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute action! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to execute action! Error is {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u"__main__":
    main()
