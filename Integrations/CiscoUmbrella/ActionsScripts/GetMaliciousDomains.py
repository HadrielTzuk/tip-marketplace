from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
# Imports
from SiemplifyAction import SiemplifyAction
from CiscoUmbrellaManager import CiscoUmbrellaIvestigate
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param

# Consts
ADDRESS = EntityTypes.ADDRESS
SCRIPT_NAME = "CiscoUmbrella - Get Malicious Domains"
INTEGRATION_NAME = "CiscoUmbrella"


# Action Context
@output_handler
def main():
    # Define Variables.
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    successful_entities = []
    json_results = {}
    failed_entities = []
    output_message = ""
    # Configuration.
    try:
        token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name='InvestigateApiToken',
                                            is_mandatory=True)
        cisco_umbrella_manager = CiscoUmbrellaIvestigate(token)
        # Get Scope Entities.
        scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == ADDRESS
                          and not entity.is_internal]
        # Execute Action On Scope Entities.
        for entity in scope_entities:
            try:
                response = cisco_umbrella_manager.get_malicious_domain_csv(str(entity.identifier).lower())
                response_list = cisco_umbrella_manager.get_malicious_domains(str(entity.identifier).lower())
                json_results[entity.identifier] = response_list
                successful_entities.append(entity)
                siemplify.result.add_entity_table(entity.identifier, response)
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
            # add json
            siemplify.result.add_result_json(json_results)
        else:
            result_value = False
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
