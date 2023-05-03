from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from CBResponseManagerLoader import CBResponseManagerLoader
from SiemplifyUtils import convert_dict_to_json_result_dict, unix_now, convert_unixtime_to_datetime
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

# =====================================
#             CONSTANTS               #
# =====================================
INTEGRATION_NAME = u"CBResponse"
SCRIPT_NAME = u"CBResponse - Hosts By Process"
SUPPORTED_ENTITY_TYPES = [EntityTypes.PROCESS]



@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = u"true"
    json_result = {}
    failed_entities = []
    successful_entities = []
    output_message = u""
    status = EXECUTION_STATE_COMPLETED

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           input_type=unicode)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Key",
                                          input_type=unicode)

    version = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Version",
                                          input_type=float)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = CBResponseManagerLoader.load_manager(version, api_root, api_key, siemplify.LOGGER)

        target_entities = [entity for entity in siemplify.target_entities if
                           entity.entity_type in SUPPORTED_ENTITY_TYPES]

        if target_entities:
            for entity in target_entities:
                siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
                if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                    siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                    status = EXECUTION_STATE_TIMEDOUT
                    break
                try:
                    sensors = manager.get_sensors_by_process(entity.identifier)
                    if not sensors:
                        siemplify.LOGGER.warn(u"No sensor data was found for entity: {}".format(entity.identifier))
                        continue

                    sensors_json = [sensor.to_json() for sensor in sensors]
                    json_result[entity.identifier] = sensors_json

                    # Attach as csv
                    siemplify.result.add_entity_table(entity.identifier,
                                                      construct_csv([sensor.to_json() for sensor in sensors]))

                    output_message += u"Carbon Black Response - hosts was found for the following entity:{} \n".format(
                        entity.identifier)

                    successful_entities.append(entity)
                    siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))
                    pass
                except Exception as e:
                    output_message += u"Unable to fetch host {}: \n{}\n".format(entity.identifier, e.message)

                    failed_entities.append(entity)
                    siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                    siemplify.LOGGER.exception(e)

            if successful_entities:
                siemplify.update_entities(successful_entities)
                siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_result))
            else:
                siemplify.LOGGER.info(u"\n No entities were processed.")
                output_message = u"No entities were processed."
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
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
