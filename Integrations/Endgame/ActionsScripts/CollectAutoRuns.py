from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from EndgameManager import EndgameManager, EndgameNotFoundError
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import sys
import base64
import json


INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"Collect Autoruns"
INVESTIGATION_NAME = "Siemplify AutoRun Collection"
WINDOWS_OS = "windows"
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

    category_all = extract_action_param(siemplify, param_name=u"Category \"All\"", is_mandatory=False,
                                        input_type=bool, default_value=True,
                                        print_value=True)
    category_network_provider = extract_action_param(siemplify, param_name=u"Category \"Network Provider\"",
                                                     is_mandatory=False, default_value=False,
                                                     input_type=bool,
                                                     print_value=True)
    category_office = extract_action_param(siemplify, param_name=u"Category \"Office\"", is_mandatory=False,
                                           input_type=bool, default_value=False,
                                           print_value=True)
    category_driver = extract_action_param(siemplify, param_name=u"Category \"Driver\"", is_mandatory=False,
                                           input_type=bool, default_value=False,
                                           print_value=True)
    category_app_init = extract_action_param(siemplify, param_name=u"Category \"App Init\"", is_mandatory=False,
                                             input_type=bool, default_value=False,
                                             print_value=True)
    category_winlogon = extract_action_param(siemplify, param_name=u"Category \"Winlogon\"", is_mandatory=False,
                                             input_type=bool, default_value=False,
                                             print_value=True)
    category_print_monitor = extract_action_param(siemplify, param_name=u"Category \"Print Monitor\"",
                                                  is_mandatory=False, default_value=False,
                                                  input_type=bool,
                                                  print_value=True)
    category_ease_of_access = extract_action_param(siemplify, param_name=u"Category \"Ease of Access\"",
                                                   is_mandatory=False, default_value=False,
                                                   input_type=bool,
                                                   print_value=True)
    category_wmi = extract_action_param(siemplify, param_name=u"Category \"WMI\"", is_mandatory=False,
                                        input_type=bool, default_value=False,
                                        print_value=True)
    category_lsa_provider = extract_action_param(siemplify, param_name=u"Category \"LSA Provider\"", is_mandatory=False,
                                                 input_type=bool, default_value=False,
                                                 print_value=True)
    category_service = extract_action_param(siemplify, param_name=u"Category \"Service\"", is_mandatory=False,
                                            input_type=bool, default_value=False,
                                            print_value=True)
    category_bits = extract_action_param(siemplify, param_name=u"Category \"Bits\"", is_mandatory=False,
                                         input_type=bool, default_value=False,
                                         print_value=True)
    category_known_dll = extract_action_param(siemplify, param_name=u"Category \"Known dll\"", is_mandatory=False,
                                              input_type=bool, default_value=False,
                                              print_value=True)
    category_print_provider = extract_action_param(siemplify, param_name=u"Category \"Print Provider\"",
                                                   is_mandatory=False, default_value=False,
                                                   input_type=bool,
                                                   print_value=True)
    category_image_hijack = extract_action_param(siemplify, param_name=u"Category \"Image Hijack\"", is_mandatory=False,
                                                 input_type=bool, default_value=False,
                                                 print_value=True)
    category_startup_folder = extract_action_param(siemplify, param_name=u"Category \"Startup Folder\"",
                                                   is_mandatory=False, default_value=False,
                                                   input_type=bool,
                                                   print_value=True)
    category_internet_explorer = extract_action_param(siemplify, param_name=u"Category \"Internet Explorer\"",
                                                      is_mandatory=False, default_value=False,
                                                      input_type=bool,
                                                      print_value=True)
    category_codec = extract_action_param(siemplify, param_name=u"Category \"Codec\"", is_mandatory=False,
                                          input_type=bool, default_value=False,
                                          print_value=True)
    category_logon = extract_action_param(siemplify, param_name=u"Category \"Logon\"", is_mandatory=False,
                                          input_type=bool, default_value=False,
                                          print_value=True)
    category_search_order_hijack = extract_action_param(siemplify, param_name=u"Category \"Search Order Hijack\"",
                                                        is_mandatory=False, default_value=False,
                                                        input_type=bool,
                                                        print_value=True)
    category_winsock_provider = extract_action_param(siemplify, param_name=u"Category \"Winsock Provider\"",
                                                     is_mandatory=False, default_value=False,
                                                     input_type=bool,
                                                     print_value=True)
    category_boot_execute = extract_action_param(siemplify, param_name=u"Category \"Boot Execute\"", is_mandatory=False,
                                                 input_type=bool, default_value=False,
                                                 print_value=True)
    category_phantom_dll = extract_action_param(siemplify, param_name=u"Category \"Phantom dll\"", is_mandatory=False,
                                                input_type=bool, default_value=False,
                                                print_value=True)
    category_com_hijack = extract_action_param(siemplify, param_name=u"Category \"Com Hijack\"", is_mandatory=False,
                                               input_type=bool, default_value=False,
                                               print_value=True)
    category_explorer = extract_action_param(siemplify, param_name=u"Category \"Explorer\"", is_mandatory=False,
                                             input_type=bool, default_value=False,
                                             print_value=True)
    category_scheduled_task = extract_action_param(siemplify, param_name=u"Category \"Scheduled Task\"",
                                                   is_mandatory=False,
                                                   default_value=False,
                                                   input_type=bool,
                                                   print_value=True)
    include_all_metadata = extract_action_param(siemplify, param_name=u"Include All Metadata", is_mandatory=False,
                                                input_type=bool, default_value=True,
                                                print_value=True)
    include_malware_classification_metadata = extract_action_param(siemplify,
                                                                   param_name=u"Include Malware Classification Metadata",
                                                                   is_mandatory=False,
                                                                   input_type=bool,
                                                                   default_value=False,
                                                                   print_value=True)
    include_authenticode_metadata = extract_action_param(siemplify, param_name=u"Include Authenticode Metadata",
                                                         is_mandatory=False,
                                                         input_type=bool,
                                                         default_value=False,
                                                         print_value=True)
    include_md5_hash = extract_action_param(siemplify, param_name=u"Include MD5 Hash", is_mandatory=False,
                                            input_type=bool,
                                            default_value=False,
                                            print_value=True)
    include_sha1_hash = extract_action_param(siemplify, param_name=u"Include SHA-1 Hash", is_mandatory=False,
                                             input_type=bool,
                                             default_value=False,
                                             print_value=True)
    include_sha256_hash = extract_action_param(siemplify, param_name=u"Include SHA-256 Hash", is_mandatory=False,
                                               input_type=bool,
                                               default_value=False,
                                               print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    sensor_ids = []
    successful_entities = []
    machine_ids = {}
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

                if endpoint.core_os.lower() != WINDOWS_OS:
                    siemplify.LOGGER.info(u"Endpoint {} OS in not supported. Skipping.".format(entity.identifier))
                    continue

                if endpoint.sensors:
                    successful_entities.append(entity.identifier)
                    sensor_ids.extend([sensor.id for sensor in endpoint.sensors])
                    machine_ids[endpoint.machine_id] = entity.identifier

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            siemplify.LOGGER.info(u"Initiating Autorun collection task on the following entities: {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            ))

            task_id = endgame_manager.get_task_id("collectAutoRunsRequest", endpoint.core_os.lower())
            task = endgame_manager.create_autorun_collection_task(
                category_all=category_all,
                category_network_provider=category_network_provider,
                category_office=category_office,
                category_driver=category_driver,
                category_app_init=category_app_init,
                category_winlogon=category_winlogon,
                category_print_monitor=category_print_monitor,
                category_ease_of_access=category_ease_of_access,
                category_wmi=category_wmi,
                category_lsa_provider=category_lsa_provider,
                category_service=category_service,
                category_bits=category_bits,
                category_known_dll=category_known_dll,
                category_print_provider=category_print_provider,
                category_image_hijack=category_image_hijack,
                category_startup_folder=category_startup_folder,
                category_internet_explorer=category_internet_explorer,
                category_codec=category_codec,
                category_logon=category_logon,
                category_search_order_hijack=category_search_order_hijack,
                category_winsock_provider=category_winsock_provider,
                category_boot_execute=category_boot_execute,
                category_phantom_dll=category_phantom_dll,
                category_com_hijack=category_com_hijack,
                category_explorer=category_explorer,
                category_scheduled_task=category_scheduled_task,
                include_all_metadata=include_all_metadata,
                include_malware_classification_metadata=include_malware_classification_metadata,
                include_authenticode_metadata=include_authenticode_metadata,
                include_md5_hash=include_md5_hash,
                include_sha1_hash=include_sha1_hash,
                include_sha256_hash=include_sha256_hash
            )

            # By default, the investigation is assigned to the login user
            investigation_id = endgame_manager.create_investigation(
                investigation_name=INVESTIGATION_NAME,
                assign_user=username,
                sensor_ids=sensor_ids,
                tasks={task_id: task},
                core_os=WINDOWS_OS
            )

            siemplify.LOGGER.info(u"Successfully created investigation {0}".format(investigation_id))

            if successful_entities:
                output_message += u"Successfully initiated Autoruns collection on the following entities:\n   {}".format(
                    u"\n   ".join([entity for entity in successful_entities])
                )

            if missing_entities:
                output_message += u"\n\nThe following entities didn't match an any endpoint and were skipped:\n   {}".format(
                    u"\n   ".join([entity for entity in missing_entities])
                )

            if failed_entities:
                output_message += u"\n\nError occurred while initiating Autoruns collection on the following entities:\n   {}".format(
                    u"\n   ".join([entity for entity in failed_entities])
                )

            output_message += u"\n\nInvestigation ID: {0}. Waiting for investigation to complete.".format(
                investigation_id
            )

            result_value = json.dumps({
                u"machine_ids": machine_ids,
                u"investigation_id": investigation_id,
                u"successful_entities": successful_entities,
                u"missing_entities": missing_entities,
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
    results_limit = extract_action_param(siemplify, param_name=u"Max Items to Return", is_mandatory=False,
                                         input_type=int,
                                         print_value=True)

    siemplify.LOGGER.info(u"----------------- Async - Started -----------------")

    result_value = u"false"
    output_message = u""
    json_results = {}
    results = []
    status = EXECUTION_STATE_COMPLETED

    action_details = json.loads(siemplify.parameters["additional_data"])
    investigation_id = action_details["investigation_id"]
    successful_entities = action_details["successful_entities"]
    missing_entities = action_details["missing_entities"]
    failed_entities = action_details["failed_entities"]
    machine_ids = action_details["machine_ids"]

    try:
        endgame_manager = EndgameManager(api_root, username=username, password=password, use_ssl=verify_ssl)

        # Check if investigation completed
        if endgame_manager.is_investigation_complete(investigation_id):
            siemplify.LOGGER.info(u"Investigation {} has completed. Collecting results.".format(investigation_id))

            # Collect the results of the investigation
            investigation_results = endgame_manager.retrieve_investigation_results(
                investigation_id,
                limit=results_limit
            )

            for task_id, investigation_result in investigation_results.items():
                for result in investigation_result.get('Results', []):
                    results.append(result)

            result_value = u"true"
            status = EXECUTION_STATE_COMPLETED

            results_by_entity = match_results_to_entity(machine_ids, results)

            for entity_identifier in successful_entities:
                entity_autoruns = results_by_entity.get(entity_identifier, [])
                json_results[entity_identifier] = entity_autoruns

                if entity_autoruns:
                    # Add table for each entity
                    siemplify.result.add_data_table(
                        u"Collected autoruns from {}".format(entity_identifier),
                        construct_csv([result_to_csv(result) for result in entity_autoruns])
                    )

            siemplify.result.add_attachment(
                u"Collected Autoruns",
                u"Collected_Autoruns.json",
                base64.b64encode(json.dumps(results))
            )

            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

            output_message = u"Successfully collected Autoruns from the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            )

            if missing_entities:
                output_message += u"\n\nThe following entities didn't match an any endpoint and were skipped:\n   {}".format(
                    u"\n   ".join([entity for entity in missing_entities])
                )

            if failed_entities:
                output_message += u"\n\nError occurred while initiating Autoruns collection on the following entities:\n   {}".format(
                    u"\n   ".join([entity for entity in failed_entities])
                )

        else:
            siemplify.LOGGER.info(u"Investigation {} has not completed yet. Waiting".format(investigation_id))
            output_message = u"Investigation {} has not completed yet. Waiting".format(investigation_id)
            result_value = siemplify.parameters["additional_data"]
            status = EXECUTION_STATE_INPROGRESS

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


def match_results_to_entity(machine_ids, results):
    """
    Match the task results to the entity that it connected to
    :param machine_ids: {dict} Mapping of endpoint machine ids to the entities identifiers
    :param results: {list} The results of the task
    :return: {dict} Mapping of entity to its results
    """
    results_by_entity = {}

    for result in results:
        entity_identifier = machine_ids.get(result.get(u"machine_id"))

        if entity_identifier not in results_by_entity:
            results_by_entity[entity_identifier] = [result]

        else:
            results_by_entity[entity_identifier].append(result)

    return results_by_entity


def result_to_csv(result):
    # TODO: Create a datamodel for this type of result and move this method there
    return {
        u"Name": result.get(u"file_name"),
        u"File Path": result.get(u"file_path"),
        u"Source Location": result.get(u"source_location"),
        u"Description": result.get(u"file_description"),
        u"Signature Status": result.get(u"signature_status"),
        u"Malware Score": result.get(u"malware_classification", {}).get("score"),
        u"Arguments": result.get(u"arguments"),
        u"Category": result.get(u"category"),
        u"Repeat Offender": result.get(u"repeat_offender"),
        u"MD5": result.get(u"hashes", {}).get("md5"),
        u"SHA1": result.get(u"hashes", {}).get("sha1"),
        u"SHA256": result.get(u"hashes", {}).get("sha256"),
    }


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        async_action()
