from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param
from ThreatQManager import ThreatQManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

# =====================================
#             CONSTANTS               #
# =====================================

INTEGRATION_NAME = u"ThreatQ"
SCRIPT_NAME = u"ThreatQ - GetIndicatorDetails"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    # Variables Definitions.
    result_value = u"true"
    status = EXECUTION_STATE_COMPLETED
    output_message = u""

    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # INIT INTEGRATION CONFIGURATION:
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="ServerAddress",
                                                 input_type=unicode)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="ClientId",
                                            input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           input_type=unicode)
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")

    entities_to_update = []
    failed_entities = []
    json_results = {}
    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)
        for entity in siemplify.target_entities:
            try:
                # Get reports for entity by it's identifier.
                indicator_obj = threatq_manager.get_indicator_details(entity.identifier)

                entities_to_update.append(entity)
                json_results[entity.identifier] = indicator_obj.to_json()

                siemplify.result.add_entity_table(entity.identifier, indicator_obj.to_csv())
                siemplify.LOGGER.info(u"Finished processing entity:{}".format(entity.identifier))

            except Exception as e:
                output_message += u"Unable to get indicators for {} \n".format(entity.identifier)
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"Failed processing entity:{}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        if entities_to_update:
            siemplify.update_entities(entities_to_update)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))
            output_message = u"Found indicators for: {0}".format(u", ".join([entity.identifier for entity in
                                                                             entities_to_update]))
            result_value = u"true"

        else:
            output_message = u"No data found for entities."
            result_value = u"false"

        if failed_entities:
            output_message += u"\nFailed to get details for the following entities:\n{0}".format(
                u"\n".join([entity.identifier for entity in
                            failed_entities]))

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = u"false"
        output_message = u"Some errors occurred. Please check log"

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
