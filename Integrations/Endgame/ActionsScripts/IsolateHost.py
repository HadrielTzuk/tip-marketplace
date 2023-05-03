from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import unix_now, convert_unixtime_to_datetime, output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from EndgameManager import EndgameManager, EndgameNotFoundError, ISOLATION_REQUESTED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv

INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"Get Endpoints"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]
WINDOWS_OS = u"windows"
MAC_OS = u"macos"
SUPPORTED_OS = [WINDOWS_OS, MAC_OS]
TASK_NAME = u"hostIsolationIsolateRequest"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           is_mandatory=True, input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    is_insight = extract_action_param(siemplify, param_name=u"Create Insight", is_mandatory=False,
                                      input_type=bool,
                                      default_value=False,
                                      print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    missing_entities = []
    no_sensors_entities = []
    failed_entities = []
    error_entities = []
    output_message = u""
    result_value = "true"

    try:
        endgame_manager = EndgameManager(api_root, username, password, verify_ssl)

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
                matching_endpoints = []

                if entity.entity_type == EntityTypes.HOSTNAME:
                    try:
                        siemplify.LOGGER.info(u"Fetching endpoint for hostname {}".format(entity.identifier))
                        matching_endpoints = endgame_manager.get_endpoint_by_hostname(entity.identifier)
                    except EndgameNotFoundError as e:
                        # Endpoint was not found in Endgame - skip entity
                        missing_entities.append(entity)
                        siemplify.LOGGER.info(unicode(e))
                        siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                        continue

                if entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info(u"Fetching endpoint for address {}".format(entity.identifier))
                        matching_endpoints = endgame_manager.get_endpoint_by_ip(entity.identifier)
                    except EndgameNotFoundError as e:
                        # Endpoint was not found in Endgame - skip entity
                        missing_entities.append(entity)
                        siemplify.LOGGER.info(unicode(e))
                        siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                        continue

                if len(matching_endpoints) > 1:
                    siemplify.LOGGER.info(
                        u"Multiple endpoints matching entity {} were found. First will be used.".format(
                            entity.identifier)
                    )

                # Take the first matching endpoint
                endpoint = matching_endpoints[0]

                if endpoint.core_os.lower() not in SUPPORTED_OS:
                    siemplify.LOGGER.info(u"Endpoint OS is not supported. Skipping.".format(entity.identifier))
                    continue

                task_id = endgame_manager.get_task_id(TASK_NAME, endpoint.core_os.lower())
                sensor_ids = [sensor.id for sensor in endpoint.sensors] if endpoint.sensors else []

                if not sensor_ids:
                    siemplify.LOGGER.info(u"No sensors found for the endpoint. Skipping")
                    no_sensors_entities.append(entity)
                    continue

                endgame_manager.initialize_isolation_task(task_id, sensor_ids, isolate=True)

                if endgame_manager.get_endpoint_by_id(endpoint.id).isolation_request_status == ISOLATION_REQUESTED:
                    siemplify.LOGGER.info(u"Successfully initiated isolation of {0} endpoint with Endgame".format(entity.identifier))
                    successful_entities.append(entity)

                    if is_insight:
                        siemplify.add_entity_insight(
                            entity,
                            u"Host isolation was initiated using Endgame",
                            triggered_by=INTEGRATION_NAME
                        )

                else:
                    siemplify.LOGGER.info(u"Failed to initiate isolation of {0}.".format(entity.identifier))
                    failed_entities.append(entity)

            except Exception as e:
                error_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Successfully initiated isolation of the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in successful_entities])
            )
        else:
            output_message += u"No entities were isolated."

        if missing_entities:
            output_message += u"\n\nThe following entities didn't match an any endpoint and were skipped:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in missing_entities])
            )

        if no_sensors_entities:
            output_message += u"\n\nNo sensors were found for the following entities and therefore were skipped:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in no_sensors_entities])
            )

        if failed_entities:
            output_message += u"\n\nFailed to initiate isolation of the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in failed_entities])
            )

        if error_entities:
            output_message += u"\n\nError occurred while initiating isolation of the following entities:\n   {}".format(
                u"\n   ".join([entity.identifier for entity in error_entities])
            )

    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = "false"
        output_message = u"Action didn't complete due to error: {}".format(e)

    finally:
        try:
            endgame_manager.logout()
        except Exception as e:
            siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
            siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
