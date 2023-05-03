from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from CiscoUmbrellaManager import CiscoUmbrellaIvestigate
from SiemplifyUtils import convert_dict_to_json_result_dict

# Consts
HOSTNAME = EntityTypes.HOSTNAME
OUTPUT_MESSAGE_TEMPLATE = 'Associated domains found for: {0}'
SCRIPT_NAME = "CiscoUmbrella - Get Associated Domains"
INTEGRATION_NAME = "CiscoUmbrella"

# Action Context
@output_handler
def main():
    # Define Variables.
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    json_results = {}
    failed_entities = []
    output_message = ""
    # Configuration.
    try:
        token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='InvestigateApiToken',
                                            is_mandatory=True)
        cisco_umbrella_manager = CiscoUmbrellaIvestigate(token)
        # Get Scope Entities.
        scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == HOSTNAME and not entity.is_internal]
        # Execute Action On Scope Entities.
        for entity in scope_entities:
            try:
                csv_output = ["Domains"]
                response = cisco_umbrella_manager.get_associated_domain(str(entity.identifier).lower())
                csv_output.append(response)
                json_results[entity.identifier] = response
                successful_entities.append(entity)
                siemplify.result.add_entity_table(entity.identifier, csv_output)
                result_value = True

            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error("An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

        # Organize Output Message.
        if successful_entities:
            entities_names = [entity.identifier for entity in successful_entities]
            output_message += 'Successfully processed entities: \n{}\n'.format(
                '\n'.join(entities_names)
            )

            siemplify.update_entities(successful_entities)
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

        if failed_entities:
            output_message += '\nThe following entities were not found in Cisco Umbrella:\n{}\n'.format(
                '\n'.join([entity.identifier for entity in failed_entities])
            )

        if not failed_entities and not successful_entities:
            output_message = "No entities were enriched."

        # add json
    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
    # Finish Action.
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
    main()
