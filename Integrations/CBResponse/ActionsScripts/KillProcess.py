from SiemplifyUtils import output_handler, unix_now, convert_unixtime_to_datetime
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from CBResponseManagerLoader import CBResponseManagerLoader
import itertools

SCRIPT_NAME = u"CBResponse - KillProcess"
INTEGRATION_NAME = u"CBResponse"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    output_message = u""
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED
    failed_entities = []
    successful_entities = []

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
        # If no exception occur - then connection is successful
        manager = CBResponseManagerLoader.load_manager(version, api_root, api_key, siemplify.LOGGER)

        processes = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.PROCESS]
        hostnames = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.HOSTNAME]

        combinations = list(itertools.product(hostnames, processes))
        siemplify.LOGGER.info(u"Generated {} combinations.".format(len(combinations)))

        if combinations:
            for combination in combinations:
                hostname, process = combination
                siemplify.LOGGER.info(u"Processing process {}, hostname {}.".format(process.identifier,
                                                                                    hostname.identifier))
                if unix_now() >= siemplify.execution_deadline_unix_time_ms:
                    siemplify.LOGGER.error(u"Timed out. execution deadline ({}) has passed".format(
                        convert_unixtime_to_datetime(siemplify.execution_deadline_unix_time_ms)))
                    status = EXECUTION_STATE_TIMEDOUT
                    break
                try:
                    sensor = manager.get_sensor_by_hostname(hostname.identifier)
                    if not sensor:
                        siemplify.LOGGER.info(u"No sensor data was found for process {}, hostname {}.".
                                              format(process.identifier, hostname.identifier))
                        continue
                    siemplify.LOGGER.info(u"Killing process {} on host {}.".format(process.identifier,
                                                                                   hostname.identifier))
                    manager.kill_process(sensor.sensor_document_id, process.identifier)
                    output_message += u"The following process has been killed:{} \n".format(process.identifier)
                    successful_entities.append(combination)
                    siemplify.LOGGER.info(u"Finished processing process {} on host {}".format(process.identifier,
                                                                                              hostname.identifier))

                except Exception as e:
                    siemplify.LOGGER.error(u"Unable to kill process {} on host {}.".format(
                        process.identifier, hostname.identifier))
                    failed_entities.append(combination)
                    siemplify.LOGGER.error(u"An error occurred on entity {0}".format(process.identifier))
                    siemplify.LOGGER.exception(e)

            if not successful_entities:
                siemplify.LOGGER.info(u"\n No entities were processed.")
                output_message = u"No entities were processed."
        else:
            output_message = u"No suitable combinations found.\n"

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