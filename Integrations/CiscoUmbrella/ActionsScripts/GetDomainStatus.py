from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import add_prefix_to_dict_keys, convert_dict_to_json_result_dict
from CiscoUmbrellaManager import CiscoUmbrellaIvestigate

# Consts
HOSTNAME = EntityTypes.HOSTNAME
CISCO_UMBRELLA_PREFIX = 'CU'
SCRIPT_NAME = "CiscoUmbrella - Get Domain Status"
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
    try:
        # Configuration.
        token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='InvestigateApiToken',
                                            is_mandatory=True)
        cisco_umbrella_manager = CiscoUmbrellaIvestigate(token)
        # Get Scope Entities.
        scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == HOSTNAME and not entity.is_internal]

        # Execute Action On Scope Entities.
        for entity in scope_entities:
            try:
                response_csv = cisco_umbrella_manager.get_domain_status_csv(str(entity.identifier).lower())
                response_dict = cisco_umbrella_manager.get_domain_status_dict(str(entity.identifier).lower())
                siemplify.result.add_entity_table(entity.identifier, response_csv)
                json_results[entity.identifier] = response_dict
                entity.additional_properties.update(add_prefix_to_dict_keys(response_dict, CISCO_UMBRELLA_PREFIX))
                successful_entities.append(entity)
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
