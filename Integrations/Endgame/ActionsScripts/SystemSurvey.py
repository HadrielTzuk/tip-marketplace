from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from EndgameManager import EndgameManager, EndgameNotFoundError
from SiemplifyDataModel import EntityTypes
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import sys
import json


INTEGRATION_NAME = u"Endgame"
SCRIPT_NAME = u"System Survey"
INVESTIGATION_NAME = u"Siemplify System Survey"
SUPPORTED_ENTITIES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME]
SUPPORTED_OSES = [u"windows", u"linux", u"solaris", u"macos"]
WINDOWS_OS = u"windows"

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

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    successful_entities = []
    investigation_ids = {}
    not_supported_entities = []
    missing_entities = []
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

                if endpoint.core_os.lower() not in SUPPORTED_OSES:
                    siemplify.LOGGER.info(u"Endpoint {} OS is not supported for this action. Skipping".format(entity.identifier))
                    not_supported_entities.append(entity.identifier)
                    continue

                if endpoint.sensors:
                    sensor_ids = [sensor.id for sensor in endpoint.sensors]

                    task_description_id = endgame_manager.get_task_id(u"systemSurveyRequest", endpoint.core_os)

                    investigation_id = endgame_manager.create_investigation(
                        investigation_name=INVESTIGATION_NAME,
                        assign_user=username,
                        sensor_ids=sensor_ids,
                        tasks={task_description_id: {}},
                        core_os=endpoint.core_os.lower()
                    )

                    siemplify.LOGGER.info(u"Successfully created investigation {0} for {1}".format(
                        investigation_id,
                        entity.identifier)
                    )

                    investigation_ids[entity.identifier] = investigation_id
                    successful_entities.append(entity.identifier)

            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message += u"Successfully initiated system survey on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            )

            status = EXECUTION_STATE_INPROGRESS

        else:
            # No sensor ids were found
            output_message = u"No suitable endpoints were found. Unable to initiate survey."
            result_value = u"false"
            status = EXECUTION_STATE_FAILED

        if missing_entities:
            output_message += u"\n\nThe following entities didn't match any endpoint and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in missing_entities])
            )

        if not_supported_entities:
            output_message += u"\n\nThe following entities run an unsupported OS and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in not_supported_entities])
            )

        if failed_entities:
            output_message += u"\n\nError occurred while initiating system survey on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in failed_entities])
            )

        if successful_entities:
            output_message += u"\n\nWaiting for investigations to complete."

        result_value = json.dumps({
            u"investigation_ids": investigation_ids,
            u"successful_entities": successful_entities,
            u"missing_entities": missing_entities,
            u"not_supported_entities": not_supported_entities,
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

    include_network_interfaces = extract_action_param(siemplify, param_name=u"Include Network Interface Information",
                                       is_mandatory=False, input_type=bool, print_value=True,
                                       default_value=False)

    include_disk = extract_action_param(siemplify, param_name=u"Include Disk Information",
                                       is_mandatory=False, input_type=bool, print_value=True,
                                       default_value=False)

    include_patches = extract_action_param(siemplify, param_name=u"Include Patch Information (Windows only)",
                                            is_mandatory=False, input_type=bool, print_value=True,
                                            default_value=False)

    include_security_products = extract_action_param(siemplify,
                                                 param_name=u"Include Security Product Information (Windows only)",
                                                 is_mandatory=False, input_type=bool, print_value=True,
                                                 default_value=False)

    results_limit = extract_action_param(siemplify, param_name=u"Max Items to Return", is_mandatory=False,
                                        input_type=int, print_value=True, default_value=None)

    siemplify.LOGGER.info(u"----------------- Async - Started -----------------")

    result_value = u"false"
    output_message = u""
    error_entities = []
    failed_entities = []
    successful_entities = []
    json_results = {}
    status = EXECUTION_STATE_COMPLETED

    action_details = json.loads(siemplify.parameters[u"additional_data"])
    investigation_ids = action_details[u"investigation_ids"]
    missing_entities = action_details[u"missing_entities"]
    not_supported_entities = action_details[u"not_supported_entities"]
    init_failed_entities = action_details[u"failed_entities"]

    try:
        endgame_manager = EndgameManager(api_root, username=username, password=password, use_ssl=verify_ssl)

        # Check if tasks have all completed
        for investigation_id in investigation_ids.values():
            try:
                if not endgame_manager.is_investigation_complete(investigation_id):
                    siemplify.LOGGER.info(u"Investigations have not completed yet. Waiting")
                    output_message = u"Investigations have not completed yet. Waiting"
                    result_value = siemplify.parameters[u"additional_data"]
                    status = EXECUTION_STATE_INPROGRESS
                    siemplify.end(output_message, result_value, status)

            except Exception as e:
                siemplify.LOGGER.info(u"Failed to check status of investigation {}".format(investigation_id))
                siemplify.LOGGER.exception(e)
                output_message = u"An error occurred while running action. Failed to check status of investigation {}".format(investigation_id)
                status = EXECUTION_STATE_FAILED
                siemplify.end(output_message, u'false', status)

        siemplify.LOGGER.info(u"All investigations have completed.")

        result_value = u"true"
        status = EXECUTION_STATE_COMPLETED

        for entity_identifier, investigation_id in investigation_ids.items():
            try:
                siemplify.LOGGER.info(u"Collecting connections info for {}".format(entity_identifier))
                # Collect the results of the investigation
                os_info = endgame_manager.retrieve_investigation_scope_results(
                    investigation_id,
                    scope=u"",
                    limit=results_limit
                )

                json_results[entity_identifier] = {
                    u"os_info": os_info
                }

                if os_info:
                    # Add table for each entity
                    siemplify.result.add_data_table(
                        u"General OS information from {}".format(entity_identifier),
                        construct_csv([general_info_to_csv(result) for result in os_info])
                    )

                if include_network_interfaces:
                    siemplify.LOGGER.info(u"Collecting network interfaces info entries for {}".format(entity_identifier))
                    network_interfaces = endgame_manager.retrieve_investigation_scope_results(
                        investigation_id,
                        scope=u"interfaces",
                        limit=results_limit
                    )

                    json_results[entity_identifier].update({
                        u"network_interfaces": network_interfaces
                    })

                    if network_interfaces:
                        # Add table for each entity
                        siemplify.result.add_data_table(
                            u"Network interface information from {}".format(entity_identifier),
                            construct_csv([network_interfaces_to_csv(result) for result in network_interfaces])
                        )

                if include_disk:
                    siemplify.LOGGER.info(u"Collecting disks info for {}".format(entity_identifier))
                    disks_info = endgame_manager.retrieve_investigation_scope_results(
                        investigation_id,
                        scope=u"disks",
                        limit=results_limit
                    )

                    json_results[entity_identifier].update({
                        u"disks_info": disks_info
                    })

                    if disks_info:
                        # Add table for each entity
                        siemplify.result.add_data_table(
                            u"Disk information from {}".format(entity_identifier),
                            construct_csv([disk_info_to_csv(result) for result in disks_info])
                        )

                if include_patches:
                    if endgame_manager.get_investigation_core_os(investigation_id) == WINDOWS_OS:
                        siemplify.LOGGER.info(u"Collecting patches info for {}".format(entity_identifier))
                        patches_info = endgame_manager.retrieve_investigation_scope_results(
                            investigation_id,
                            scope=u"hotfixes",
                            limit=results_limit
                        )

                        json_results[entity_identifier].update({
                            u"patches_info": patches_info
                        })

                        if patches_info:
                            # Add table for each entity
                            siemplify.result.add_data_table(
                                u"Patches information from {}".format(entity_identifier),
                                construct_csv([patches_to_csv(result) for result in patches_info])
                            )
                    else:
                        siemplify.LOGGER.info(u"Endpoint {} is running non-windows OS, and therefore patches info"
                                              u" collection is not supported.".format(entity_identifier))

                if include_security_products:
                    if endgame_manager.get_investigation_core_os(investigation_id) == WINDOWS_OS:
                        siemplify.LOGGER.info(u"Collecting installed security products info for {}".format(entity_identifier))
                        security_products_info = endgame_manager.retrieve_investigation_scope_results(
                            investigation_id,
                            scope=u"security_products",
                            limit=results_limit
                        )

                        json_results[entity_identifier].update({
                            u"installed_security_products": security_products_info
                        })

                        if security_products_info:
                            # Add table for each entity
                            siemplify.result.add_data_table(
                                u"Installed security products information from {}".format(entity_identifier),
                                construct_csv([security_product_to_csv(result) for result in security_products_info])
                            )
                    else:
                        siemplify.LOGGER.info(u"Endpoint {} is running non-windows OS, and therefore security products"
                                              u" info collection is not supported.".format(entity_identifier))

                successful_entities.append(entity_identifier)

            except Exception as e:
                error_entities.append(entity_identifier)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity_identifier))
                siemplify.LOGGER.exception(e)

        if successful_entities:
            output_message = u"Successfully completed system survey on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in successful_entities])
            )

        else:
            output_message = u"System survey didn't run on any entities."
            result_value = u"false"

        if failed_entities:
            output_message += u"\n\nSystem survey has failed on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in failed_entities])
            )

        if missing_entities:
            output_message += u"\n\nThe following entities didn't match any endpoint and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in missing_entities])
            )

        if not_supported_entities:
            output_message += u"\n\nThe following entities run an unsupported OS and were skipped:\n   {}".format(
                u"\n   ".join([entity for entity in not_supported_entities])
            )

        if init_failed_entities:
            output_message += u"\n\nError occurred while initiating system survey on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in init_failed_entities])
            )

        if error_entities:
            output_message += u"\n\nError occurred while running system survey on the following entities:\n   {}".format(
                u"\n   ".join([entity for entity in error_entities])
            )

        siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

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

    siemplify.LOGGER.info(u"----------------- Async - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


def general_info_to_csv(result):
    # TODO: Create a datamodel for this type of result and move this method there
    return {
        u"OS": result.get(u"endpoint", {}).get(u"display_operating_system"),
        u"Hostname": result.get(u"hostname"),
        u"Architecture": result.get(u"architecture"),
        u"Time": result.get(u"time", {}).get(u"tz_name"),
        u"RAM Used": u"{}%".format(result.get(u"memory", {}).get(u"ram_percent_used"))
    }


def network_interfaces_to_csv(result):
    # TODO: Create a datamodel for this type of result and move this method there
    return {
        u"Interface Name": result.get(u"interface_name"),
        u"IPV4": result.get(u"ipv4_addresses"),
        u"IPV6": result.get(u"ipv6_addresses"),
        u"MAC": result.get(u"mac_address")
    }


def disk_info_to_csv(result):
    # TODO: Create a datamodel for this type of result and move this method there
    return {
        u"Path": result.get(u"path"),
        u"Type": result.get(u"fstype"),
        u"Disk ID": result.get(u"disk_id"),
        u"Free": result.get(u"disk_free")
    }


def patches_to_csv(result):
    # TODO: Create a datamodel for this type of result and move this method there
    return {
        u"Patch ID": result.get(u"hotfix_id"),
        u"Installed On": result.get(u"installed_on")
    }


def security_product_to_csv(result):
    # TODO: Create a datamodel for this type of result and move this method there
    return {
        u"Name": result.get(u"name"),
        u"Type": result.get(u"security_product_type"),
        u"Enabled": result.get(u"enabled")
    }


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        async_action()
