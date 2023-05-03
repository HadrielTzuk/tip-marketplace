from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict, convert_unixtime_to_datetime, unix_now
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, construct_csv
from CBResponseManagerLoader import CBResponseManagerLoader

INTEGRATION_NAME = u"CBResponse"
SCRIPT_NAME = u"CBResponse - Enrich Process"
ENTITY_TABLE_HEADER = u"Processes"
PREFIX = u"CB_RESPONSE"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED
    output_message = u""
    failed_entities = []
    successful_entities = []
    json_results = {}
    all_processes = []

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          input_type=unicode)
    version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Version",
                                          input_type=float)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    process_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.PROCESS]
    host_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME]
    try:
        manager = CBResponseManagerLoader.load_manager(version, api_root, api_key, siemplify.LOGGER)
        if process_entities:
            for entity in process_entities:
                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                    siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                    status = EXECUTION_STATE_TIMEDOUT
                    break
                try:
                    processes = manager.get_process_by_name(entity.identifier)
                    if processes:
                        for index, process in enumerate(processes):
                            all_processes.append(process)
                            entity.additional_properties.update(process.to_csv(u"{}_{}".format(PREFIX, str(index))))
                        entity.is_enriched = True
                        json_results[entity.identifier] = [process.to_json() for process in processes]

                        output_message += u"The following entity was fetched: {} \n".format(entity.identifier)
                        successful_entities.append(entity)
                        siemplify.LOGGER.info(u"Finished processing entity:{}".format(entity.identifier))
                    else:
                        siemplify.LOGGER.warn(u"No processes were found: {}".format(entity.identifier))
                except Exception as e:
                    output_message += u"Unable to fetch entity {} \n".format(entity.identifier)
                    failed_entities.append(entity)
                    siemplify.LOGGER.error(u"Failed processing entity:{}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)

            for host_entity in host_entities:
                processes_for_host = [process for process
                                      in all_processes if process.is_hostname_equal(host_entity)]
                if processes_for_host:
                    siemplify.result.add_entity_table(ENTITY_TABLE_HEADER,
                                                      construct_csv([process.to_csv() for process in processes_for_host]))

            if successful_entities:
                siemplify.update_entities(successful_entities)
                siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            else:
                siemplify.LOGGER.info(u"\n No entities were processed.")
                output_message += u"No entities were processed."
        else:
            output_message = u"No suitable entities found.\n"

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
