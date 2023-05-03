from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler, \
    convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CBEnterpriseEDRManager import CBEnterpriseEDRManager, CBEnterpriseEDRUnauthorizedError
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"CBEnterpriseEDR"
SCRIPT_NAME = u"Process Search"
SUPPORTED_ENTITIES = [EntityTypes.HOSTNAME]


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

    query = extract_action_param(siemplify, param_name=u"Query", is_mandatory=False,
                                 input_type=unicode,
                                 print_value=True)

    timeframe = extract_action_param(siemplify, param_name=u"Time Frame", is_mandatory=False,
                                     input_type=int,
                                     print_value=True)

    record_limit = extract_action_param(siemplify, param_name=u"Record limit", is_mandatory=True,
                                        input_type=int,
                                        print_value=True)

    sort_by = extract_action_param(siemplify, param_name=u"Sort By", is_mandatory=False,
                                   input_type=unicode,
                                   print_value=True)

    sort_order = extract_action_param(siemplify, param_name=u"Sort Order", is_mandatory=False,
                                      input_type=unicode, default_value=u"ASC",
                                      print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    json_results = {}
    failed_entities = []
    missing_entities = []
    output_message = u""

    try:
        cb_edr_manager = CBEnterpriseEDRManager(api_root, org_key, api_id, api_secret_key, verify_ssl)

        for entity in siemplify.target_entities:
            if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                    convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                status = EXECUTION_STATE_TIMEDOUT
                break

            try:
                if entity.entity_type not in SUPPORTED_ENTITIES:
                    siemplify.LOGGER.info(u"Entity {} is of unsupported type. Skipping.".format(entity.identifier))
                    continue

                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))

                siemplify.LOGGER.info(u"Initializing process search for entity {}".format(entity.identifier))
                processes = cb_edr_manager.process_search(
                    query=query,
                    device_name=entity.identifier,
                    sort_by=sort_by,
                    sort_order=sort_order,
                    timeframe=timeframe,
                    limit=record_limit
                )

                json_results[entity.identifier] = [process.raw_data for process in processes]

                if processes:
                    siemplify.LOGGER.info(u"Found {} results for {}".format(len(processes), entity.identifier))
                    siemplify.result.add_data_table(u"Process search results for {}".format(entity.identifier),
                                                    construct_csv([process.to_csv() for process in processes]))
                    successful_entities.append(entity)

                else:
                    siemplify.LOGGER.info(u"No results were found for {}".format(entity.identifier))
                    missing_entities.append(entity)

                siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))

            except CBEnterpriseEDRUnauthorizedError as e:
                # Unauthorized - invalid credentials were passed. Terminate action
                siemplify.LOGGER.error(u"Failed to execute Process Search action! Error is {}".format(e))
                siemplify.end(u"Failed to execute Process Search action! Error is {}".format(e), u"false",
                              EXECUTION_STATE_FAILED)

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Found process information for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )
            siemplify.update_entities(successful_entities)
            result_value = u"true"

        else:
            output_message += u"No search results were returned."
            result_value = u"false"

        if missing_entities:
            output_message += u"\n\nNo search results were returned for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"\n\nFailed to get results because of the errors running search for the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute Process Search action! Error is {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Failed to execute Process Search action! Error is {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == u"__main__":
    main()
