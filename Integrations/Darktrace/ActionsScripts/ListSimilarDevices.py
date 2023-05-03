from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from DarktraceManager import DarktraceManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIST_SIMILAR_DEVICES_SCRIPT_NAME, DEVICE_KEYS
from SiemplifyDataModel import EntityTypes
from DarktraceExceptions import NegativeValueException


# Fix misalignment of MAC entity type
EntityTypes.MACADDRESS = EntityTypes.MACADDRESS.upper()
SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS, EntityTypes.HOSTNAME, EntityTypes.MACADDRESS]


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_SIMILAR_DEVICES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Token",
                                            is_mandatory=True, print_value=True)
    api_private_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                    param_name="API Private Token", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # Action parameters
    limit = extract_action_param(siemplify, param_name="Max Devices To Return", input_type=int, print_value=True,
                                 default_value=50)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_entities = []
    failed_entities = []
    json_results = {}
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]

    try:
        if limit <= 0:
            raise NegativeValueException

        manager = DarktraceManager(api_root=api_root, api_token=api_token, api_private_token=api_private_token,
                                   verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)

        manager.test_connectivity()

        for entity in suitable_entities:
            siemplify.LOGGER.info("\nStarted processing entity: {}".format(entity.identifier))

            try:
                if entity.entity_type == EntityTypes.ADDRESS:
                    device = manager.get_devices(DEVICE_KEYS.get("ip"), entity.identifier)
                elif entity.entity_type == EntityTypes.HOSTNAME:
                    device = manager.search_devices_by_hostname(entity.identifier)
                else:
                    device = manager.get_devices(DEVICE_KEYS.get("mac"), entity.identifier)

                if device and device.did:
                    similar_devices = manager.get_similar_devices(device.did, limit)

                    if similar_devices:
                        successful_entities.append(entity)
                        json_results[entity.identifier] = [device.to_json() for device in similar_devices]
                        siemplify.result.add_entity_table(
                            entity.identifier,
                            construct_csv([device.to_similars_table() for device in similar_devices])
                        )

                    else:
                        failed_entities.append(entity)
                else:
                    failed_entities.append(entity)

            except Exception as e:
                siemplify.LOGGER.error(f"Failed processing entities: {entity.identifier}: Error is: {e}")
                failed_entities.append(entity)

            siemplify.LOGGER.info("Finished processing entity {}\n".format(entity.identifier))

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message += "Successfully returned similar devices for the following endpoints from {}: \n{}"\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in successful_entities]))

        if failed_entities:
            output_message += "\nAction wasn't able to find any similar devices for the following endpoints from {}: \n{}"\
                .format(INTEGRATION_DISPLAY_NAME, "\n".join([entity.identifier for entity in failed_entities]))

        if not successful_entities:
            result = False
            output_message = "No similar devices were found for the provided endpoints."

    except NegativeValueException:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_SIMILAR_DEVICES_SCRIPT_NAME}\". Reason: " \
                         f"\"Max Devices To Return\" should be greater than 0."
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_SIMILAR_DEVICES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_SIMILAR_DEVICES_SCRIPT_NAME}.\" Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
