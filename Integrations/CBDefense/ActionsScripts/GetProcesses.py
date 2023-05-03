from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import convert_dict_to_json_result_dict
from CarbonBlackDefenseManager import CBDefenseManager
from TIPCommon import dict_to_flat, extract_configuration_param, extract_action_param, construct_csv


INTEGRATION_NAME = "CBDefense"
SCRIPT_NAME = "Get Processes"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          is_mandatory=True)

    timeframe = extract_action_param(siemplify, param_name='Timeframe', print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    failed_entities = []
    json_results = {}
    output_message = u""
    result_value = "true"

    try:
        siemplify.LOGGER.info("Connecting to Carbon Black Defense.")
        cb_defense = CBDefenseManager(api_root, api_key)
        cb_defense.test_connectivity()

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

                siemplify.LOGGER.info("Started processing entity: {}".format(entity.identifier))

                siemplify.LOGGER.info(f"Fetching processes for {entity.identifier}.")
                processes = []

                if entity.entity_type == EntityTypes.ADDRESS:
                    processes = cb_defense.get_processes_by_ip(entity.identifier, timeframe)

                elif entity.entity_type == EntityTypes.HOSTNAME:
                    processes = cb_defense.get_processes_by_hostname(entity.identifier, timeframe)

                if processes:
                    siemplify.LOGGER.info(f"{len(processes)} processes were found for {entity.identifier}.")

                    json_results[entity.identifier] = [process.raw_data for process in processes]

                    # Attach as csv
                    siemplify.LOGGER.info("Adding processes CSV table.")
                    csv_output = construct_csv([process.as_csv() for process in processes])
                    siemplify.result.add_entity_table(entity.identifier, csv_output)

                    successful_entities.append(entity)

                else:
                    siemplify.LOGGER.info(f"No processes were found for {entity.identifier}.")
                    missing_entities.append(entity)

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Carbon Black Defense - Processes were found for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )

        else:
            output_message += u"No processes were found.\n\n"

        if missing_entities:
            output_message += u"No processes were found for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if failed_entities:
            output_message += u"Failed to fetch processes for the following entities:\n   {}\n\n".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error("General error occurred while running action {}. Error: {}".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = "An error occurred while running action. Error: {}".format(e)

    siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
