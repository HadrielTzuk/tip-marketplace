from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from EndgameManager import EndgameManager, EndgameNotFoundError
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import sys
import json


INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"Kill Process"
INVESTIGATION_NAME = u"Siemplify Kill Process"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]


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

    process_name = extract_action_param(siemplify, param_name=u"Process Name", is_mandatory=True,
                                        input_type=unicode, print_value=True)

    pid = extract_action_param(siemplify, param_name=u"PID", is_mandatory=False,
                                        input_type=int, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    successful_entities = []
    task_ids = {}
    missing_entities = []
    inactive_entities = []
    failed_entities = []
    status = EXECUTION_STATE_COMPLETED
    result_value = u"false"
    output_message = u""

    try:
        endgame_manager = EndgameManager(api_root, username=username, password=password, use_ssl=verify_ssl)

        for entity in siemplify.target_entities:
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
                        missing_entities.append(entity.identifier)
                        siemplify.LOGGER.info(unicode(e))
                        siemplify.LOGGER.info(u"Skipping entity {}".format(entity.identifier))
                        continue

                if entity.entity_type == EntityTypes.ADDRESS:
                    try:
                        siemplify.LOGGER.info(u"Fetching endpoint for address {}".format(entity.identifier))
                        matching_endpoints = endgame_manager.get_endpoint_by_ip(entity.identifier)
                    except EndgameNotFoundError as e:
                        # Endpoint was not found in Endgame - skip entity
                        missing_entities.append(entity.identifier)
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

                if not endpoint.is_active:
                    siemplify.LOGGER.info(u"Endpoint {} is inactive. Skipping".format(entity.identifier))
                    inactive_entities.append(entity.identifier)
                    continue

                if endpoint.sensors:
                    sensor_ids = [sensor.id for sensor in endpoint.sensors]

                    task_description_id = endgame_manager.get_task_id(u"killProcessRequest", endpoint.core_os.lower())
                    task = endgame_manager.create_kill_process_task(
                        process_name=process_name,
                        pid=pid
                    )

                    task_bulk_id = endgame_manager.initialize_task(
                        task_id=task_description_id,
                        sensor_ids=sensor_ids,
                        task=task,
                        core_os=endpoint.core_os
                    )

                    siemplify.LOGGER.info(
                        u"Successfully created task {0} for {1}".format(task_bulk_id, entity.identifier)
                    )

                    task_ids[entity.identifier] = task_bulk_id
                    successful_entities.append(entity.identifier)

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Successfully initiated process killing on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            )

            status = EXECUTION_STATE_INPROGRESS

        else:
            # No sensor ids were found
            output_message = u"No suitable endpoints were found. Unable to initiate task."
            result_value = u"false"
            status = EXECUTION_STATE_FAILED

        if missing_entities:
            output_message += u"\n\nThe following entities didn't match any endpoint and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in missing_entities])
            )

        if inactive_entities:
            output_message += u"\n\nThe following endpoints are not active and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in inactive_entities])
            )

        if failed_entities:
            output_message += u"\n\nError occurred while initiating process killing on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in failed_entities])
            )

        if successful_entities:
            output_message += u"\n\nWaiting for tasks to complete."

        result_value = json.dumps({
            u"task_ids": task_ids,
            u"successful_entities": successful_entities,
            u"missing_entities": missing_entities,
            u"inactive_entities": inactive_entities,
            u"failed_entities": failed_entities
        })


    except Exception as e:
        siemplify.LOGGER.error(u"Action didn't complete due to error: {}".format(e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
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


def async_action():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)

    siemplify.LOGGER.info(u"================= Async - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           is_mandatory=True, input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    process_name = extract_action_param(siemplify, param_name=u"Process Name", is_mandatory=True,
                                        input_type=unicode, print_value=True)

    siemplify.LOGGER.info(u"----------------- Async - Started -----------------")

    result_value = u"false"
    output_message = u""
    error_entities = []
    failed_entities = []
    successful_entities = []
    status = EXECUTION_STATE_COMPLETED

    action_details = json.loads(siemplify.parameters[u"additional_data"])
    task_ids = action_details[u"task_ids"]
    missing_entities = action_details[u"missing_entities"]
    inactive_entities = action_details[u"inactive_entities"]
    init_failed_entities = action_details[u"failed_entities"]

    try:
        endgame_manager = EndgameManager(api_root, username=username, password=password, use_ssl=verify_ssl)

        # Check if tasks have all completed
        for bulk_task_id in task_ids.values():
            try:
                if not endgame_manager.is_task_complete(bulk_task_id):
                    siemplify.LOGGER.info(u"Tasks have not completed yet. Waiting")
                    output_message = u"Tasks have not completed yet. Waiting"
                    result_value = siemplify.parameters[u"additional_data"]
                    status = EXECUTION_STATE_INPROGRESS
                    siemplify.end(output_message, result_value, status)

            except Exception as e:
                siemplify.LOGGER.info(u"Failed to check status of task {}".format(bulk_task_id))
                siemplify.LOGGER.exception(e)
                output_message = u"An error occurred while running action. Failed to check status of task {}".format(bulk_task_id)
                status = EXECUTION_STATE_FAILED
                siemplify.end(output_message, u'false', status)

        siemplify.LOGGER.info(u"All tasks have completed.")

        result_value = u"true"
        status = EXECUTION_STATE_COMPLETED

        for entity_identifier, bulk_task_id in task_ids.items():
            try:
                if endgame_manager.is_task_failed(bulk_task_id):
                    try:
                        collection_id = endgame_manager.get_collection_id_by_bulk_task_id(bulk_task_id)
                        collection = endgame_manager.get_collection_by_id(collection_id)

                        local_msg = collection.get(u"local_msg")
                        system_msg = collection.get(u"system_msg")

                        siemplify.LOGGER.error(
                            u"Kill process task failed on entity {}. Local message: {}. System message: {}".format(
                                entity_identifier,
                                local_msg,
                                system_msg)
                        )
                        failed_entities.append((entity_identifier, local_msg, system_msg))
                    except Exception as e:
                        error_entities.append(entity_identifier)
                        siemplify.LOGGER.error(
                            u"Failed to discover task failure reason for entity {}".format(entity_identifier)
                        )
                        siemplify.LOGGER.exception(e)

                else:
                    siemplify.LOGGER.info(
                        u"Kill process task {} of entity {} completed successfully.".format(
                            bulk_task_id,
                            entity_identifier)
                    )
                    successful_entities.append(entity_identifier)

            except Exception as e:
                error_entities.append(entity_identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity_identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = u"Successfully killed process {} on the following entities:\n   {}".format(
                process_name,
                u"\n   ".join([entity for entity in successful_entities])
            )

        else:
            result_value = u"false"

        if failed_entities:
            output_message += u"\n\nKill process task has failed on the following entities:\n   {}".format(
                u"\n   ".join([u"{}: Local Message: {}, System Message: {}".format(entity, local_msg, system_msg) for (entity, local_msg, system_msg) in failed_entities])
            )

        if missing_entities:
            output_message += u"\n\nThe following entities didn't match any endpoint and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in missing_entities])
            )

        if inactive_entities:
            output_message += u"\n\nThe following endpoints are not active and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in inactive_entities])
            )

        if init_failed_entities:
            output_message += u"\n\nError occurred while initiating process killing on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in init_failed_entities])
            )

        if error_entities:
            output_message += u"\n\nError occurred while running kill process task on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in error_entities])
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

    siemplify.LOGGER.info(u"----------------- Async - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        async_action()
