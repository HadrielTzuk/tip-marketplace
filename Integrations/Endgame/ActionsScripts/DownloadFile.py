from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from EndgameManager import EndgameManager, EndgameNotFoundError
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import sys
import base64
import json
import ntpath
import os

INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"Download File"
INVESTIGATION_NAME = u"Siemplify Download File"
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

    full_file_path = extract_action_param(siemplify, param_name=u"Full File Path", is_mandatory=True,
                                          input_type=unicode, print_value=True)

    expected_sha256 = extract_action_param(siemplify, param_name=u"Expected SHA-256 Hash", is_mandatory=False,
                                           input_type=unicode, print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    successful_entities = []
    inactive_entities = []
    task_ids = {}
    missing_entities = []
    failed_entities = []
    status = EXECUTION_STATE_COMPLETED
    result_value = "false"
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

                    task_description_id = endgame_manager.get_task_id(u"downloadFileRequest", endpoint.core_os.lower())
                    task = endgame_manager.create_download_file_task(
                        existing_path=full_file_path,
                        expected_sha256=expected_sha256
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
            output_message += u"Successfully initiated file download on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            )

            if missing_entities:
                output_message += u"\n\nThe following entities didn't match any endpoint and were skipped:\n   {}".format(
                    u"\n   ".join([entity for entity in missing_entities])
                )

            if inactive_entities:
                output_message += u"\n\nThe following endpoints are not active and were skipped:\n   {}".format(
                    u"\n   ".join([entity for entity in inactive_entities])
                )

            if failed_entities:
                output_message += u"\n\nError occurred while initiating file download on the following entities:\n   {}".format(
                    u"\n   ".join([entity for entity in failed_entities])
                )

            output_message += u"\n\nWaiting for tasks to complete."

            result_value = json.dumps({
                u"task_ids": task_ids,
                u"successful_entities": successful_entities,
                u"missing_entities": missing_entities,
                u"inactive_entities": inactive_entities,
                u"failed_entities": failed_entities
            })

            status = EXECUTION_STATE_INPROGRESS

        else:
            # No sensor ids were found
            output_message = u"No suitable endpoints were found. Unable to initiate task."
            result_value = "false"
            status = EXECUTION_STATE_FAILED

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

    destination_folder = extract_action_param(siemplify, param_name=u"Full Download Folder Path", is_mandatory=True,
                                              input_type=unicode, print_value=True)

    siemplify.LOGGER.info(u"----------------- Async - Started -----------------")

    result_value = u"false"
    output_message = u""
    json_results = {}
    error_entities = []
    failed_entities = []
    known_failed_entities = []
    successful_entities = []
    status = EXECUTION_STATE_COMPLETED

    action_details = json.loads(siemplify.parameters["additional_data"])
    task_ids = action_details["task_ids"]
    missing_entities = action_details["missing_entities"]
    inactive_entities = action_details["inactive_entities"]
    init_failed_entities = action_details["failed_entities"]

    try:
        if not os.path.exists(destination_folder):
            siemplify.LOGGER.info(u"{} doesn't exist. Creating directory".format(destination_folder))
            os.makedirs(destination_folder)

        endgame_manager = EndgameManager(api_root, username=username, password=password, use_ssl=verify_ssl)

        all_completed = True

        # Check if tasks have all completed
        for entity_identifier, bulk_task_id in task_ids.items():
            try:
                if not endgame_manager.is_task_complete(bulk_task_id):
                    all_completed = False

            except Exception as e:
                all_completed = False
                siemplify.LOGGER.info(u"Failed to check status of task {}, entity {}".format(
                    bulk_task_id,
                    entity_identifier)
                )
                siemplify.LOGGER.exception(e)
                continue

        if not all_completed:
            siemplify.LOGGER.info(u"Tasks have not completed yet. Waiting")
            output_message = u"Tasks have not completed yet. Waiting"
            result_value = siemplify.parameters["additional_data"]
            status = EXECUTION_STATE_INPROGRESS
            siemplify.end(output_message, result_value, status)

        siemplify.LOGGER.info(u"All tasks have completed. Downloading files.")

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
                            u"Download file task failed on entity {}. Local message: {}. System message: {}".format(
                                entity_identifier,
                                local_msg,
                                system_msg)
                        )
                        known_failed_entities.append((entity_identifier, local_msg, system_msg))
                    except Exception as e:
                        failed_entities.append(entity_identifier)
                        siemplify.LOGGER.error(
                            u"Failed to discover task failure reason for entity {}".format(entity_identifier)
                        )
                        siemplify.LOGGER.exception(e)

                else:
                    entity = get_entity_by_identifier(siemplify, entity_identifier)

                    # Collect the results of the task
                    siemplify.LOGGER.info(u"Collecting results for task {}, entity {}".format(
                        bulk_task_id, entity_identifier)
                    )

                    results = endgame_manager.retrieve_task_results(
                        bulk_task_id
                    )

                    siemplify.LOGGER.info(
                        u"Found {} results for task {}, entity {}".format(len(results), bulk_task_id, entity.identifier)
                    )
                    json_results[entity.identifier] = results

                    error = False

                    if results:
                        for result in results:
                            # When running os.path.basename on Linux environment, and windows path, basename method
                            # misbehaves
                            file_name = ntpath.basename(result.get("filepath"))

                            try:
                                siemplify.LOGGER.info(u"Downloading file {}".format(file_name))
                                zip_filename = u"{}.zip".format(file_name)
                                generated_filename = generate_file_name(destination_folder, zip_filename)
                                file_content = endgame_manager.download_file(result.get("file_uuid"))

                                try:
                                    siemplify.LOGGER.info(
                                        u"Saving {} at {}".format(generated_filename, destination_folder))
                                    with open(os.path.join(destination_folder, generated_filename), 'wb') as f:
                                        f.write(file_content)

                                except Exception as e:
                                    error = True
                                    siemplify.LOGGER.error(
                                        u"Failed to save {} at {}".format(generated_filename, destination_folder))
                                    siemplify.LOGGER.exception(e)

                                try:
                                    siemplify.LOGGER.info(u"Attaching file {}".format(generated_filename))
                                    siemplify.result.add_entity_attachment(
                                        entity.identifier,
                                        generated_filename,
                                        base64.b64encode(file_content)
                                    )

                                except Exception as e:
                                    error = True
                                    siemplify.LOGGER.error(
                                        u"Failed to add file {} as attachment".format(generated_filename))
                                    siemplify.LOGGER.exception(e)

                            except Exception as e:
                                error = True
                                siemplify.LOGGER.error(u"Failed to download file {}".format(file_name))
                                siemplify.LOGGER.exception(e)

                        siemplify.result.add_data_table(
                            u"Endgame files from {}".format(entity_identifier),
                            construct_csv([result_to_csv(result) for result in results])
                        )

                    if error:
                        error_entities.append(entity.identifier)

                    else:
                        successful_entities.append(entity.identifier)

            except Exception as e:
                failed_entities.append(entity_identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity_identifier))
                siemplify.LOGGER.exception(e)

        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

        output_message = u"Successfully downloaded files from the following entities:\n   {}".format(
            u"\n   ".join([entity for entity in successful_entities])
        )

        if error_entities:
            output_message += u"\n\nTask was successfully completed on the following entities, but an error " \
                              u"occurred while saving the downloaded files (check logs for details):\n   {}".format(
                u"\n   ".join([entity for entity in error_entities])
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
            output_message += u"\n\nError occurred while initiating file download on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in init_failed_entities])
            )

        if known_failed_entities:
            output_message += u"\n\nFile download task has failed with known reason on the following entities:\n   {}".format(
                u"\n   ".join([u"{}: Local Message: {}, System Message: {}".format(entity, local_msg, system_msg) for
                               (entity, local_msg, system_msg) in known_failed_entities])
            )

        if failed_entities:
            output_message += u"\n\nFile download task has failed with unknown reason on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in failed_entities])
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


def get_entity_by_identifier(siemplify, entity_identifier):
    """
    Get Entity object by identifier
    :param siemplify: {SiemplifyAction}
    :param entity_identifier: {unicode} The identifier of the entity
    :return: {Entity} the matching entity
    """
    for entity in siemplify.target_entities:
        if entity.identifier == entity_identifier:
            return entity

    raise Exception(u"Entity {} was not found".format(entity_identifier))


def generate_file_name(destination_folder, original_file_name):
    """
    Generate the filename (to avoid duplicate names)
    :param destination_folder: {unicode} The destination folder
    :param original_file_name: {unicode} The original file name
    :return: {unicode} The generated filename
    """
    filename, filext = os.path.splitext(original_file_name)
    if not os.path.exists(os.path.join(destination_folder, original_file_name)):
        return original_file_name

    index = 1
    while os.path.exists(os.path.join(destination_folder, u"{} ({}){}".format(filename, index, filext))):
        index += 1

    return u"{} ({}){}".format(filename, index, filext)


def result_to_csv(result):
    """
    Create a CSV table for found file
    :param result: {dict} The found file info
    :return: {dict} The csv row data for the file
    """
    # TODO: Create a datamodel for this type of result and move this method there
    return {
        u"Name": os.path.basename(result.get(u"filepath")),
        u"Size": result.get(u"size"),
        u"File Path": result.get(u"filepath"),
        u"Hostname": result.get(u"endpoint").get("hostname"),
        u"IP Address": result.get(u"endpoint").get("ip_address"),
        u"OS": result.get(u"endpoint").get("display_operating_system"),
        u"File ID": result.get(u"file_uuid"),
        u"SHA-256": result.get(u"sha256"),
        u"MD5": result.get(u"md5")
    }


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        async_action()
