from FireEyeHelixConstants import PROVIDER_NAME, ADD_ENTITIES_TO_A_LIST
from FireEyeHelixExceptions import FireEyeHelixNotFoundListException
from FireEyeHelixManager import FireEyeHelixManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from TIPCommon import extract_configuration_param, extract_action_param
from UtilsManager import get_item_type_and_value


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_ENTITIES_TO_A_LIST
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    json_results = {}
    successful_entities = []
    failed_entities = []

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Init Integration Configurations
    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Root",
        is_mandatory=True
    )

    api_token = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="API Token",
        is_mandatory=True
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        input_type=bool
    )

    # Init Action Parameters
    short_name = extract_action_param(siemplify, param_name='List Short Name', is_mandatory=True, print_value=True)
    risk = extract_action_param(siemplify, param_name='Risk', is_mandatory=False, print_value=True)
    note = extract_action_param(siemplify, param_name='Note', is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = FireEyeHelixManager(
            api_root=api_root,
            api_token=api_token,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        shot_list = manager.get_list_by_short_name(short_name)

        for entity in siemplify.target_entities:
            try:
                siemplify.LOGGER.info("\n\nStarted processing entity: {}".format(entity.identifier))
                item_type, value = get_item_type_and_value(entity)
                entity_report = manager.add_item_to_list(shot_list.id, value, item_type, risk, note)

                json_results[entity.identifier] = entity_report.to_json()
                successful_entities.append(entity)
                siemplify.LOGGER.info("Successfully added the {} entity to list".format(entity.identifier))
            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error("Something went wrong while adding {} entity to list".format(entity.identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info("Finished processing entity: {}".format(entity.identifier))

        if successful_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message += "Successfully added the following entities to {provider_name} list with short name " \
                              "\"{short_name}\": \n {entities}"\
                .format(
                    provider_name=PROVIDER_NAME,
                    short_name=short_name,
                    entities="\n ".join([entity.identifier for entity in successful_entities])
                )

        if failed_entities:
            output_message += "\nAction was not able to add the following entities to the {provider_name} list with " \
                              "short name \"{short_name}\": \n {entities}"\
                .format(
                    provider_name=PROVIDER_NAME,
                    short_name=short_name,
                    entities="\n ".join([entity.identifier for entity in failed_entities])
                )

        if not successful_entities:
            msg = "\nNo entities were added to the list with short name \"{short_name}\" in {provider_name}."
            output_message += msg.format(provider_name=PROVIDER_NAME, short_name=short_name)
            result_value = False

    except FireEyeHelixNotFoundListException:
        output_message = "List with short name \"{short_name}\" was not found in {provider_name}." \
            .format(
                provider_name=PROVIDER_NAME,
                short_name=short_name
            )
        siemplify.LOGGER.info(output_message)
        result_value = False
    except Exception as e:
        output_message = "Error executing action \"Add Entities To a List\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result_value))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
