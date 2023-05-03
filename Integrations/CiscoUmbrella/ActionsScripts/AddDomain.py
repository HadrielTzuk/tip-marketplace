from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from TIPCommon import extract_configuration_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from CiscoUmbrellaManager import CiscoUmbrellaEnforcment
import datetime

# Consts
HOSTNAME = EntityTypes.HOSTNAME
SCRIPT_NAME = "CiscoUmbrella - Add Domain"
INTEGRATION_NAME = "CiscoUmbrella"


@output_handler
def main():
    # Define Variables.
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")
    result_value = False
    status = EXECUTION_STATE_COMPLETED
    failed_entities = []
    successful_entities = []
    output_message = ""
    try:
        # Configuration.
        token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='EnforcementApiToken',
                                            is_mandatory=True)
        cisco_umbrella_manager = CiscoUmbrellaEnforcment(token)

        scope_entities = [entity for entity in siemplify.target_entities if entity.entity_type == HOSTNAME
                          and not entity.is_internal]

        siemplify.LOGGER.info("----------------- Main - Started -----------------")
        for entity in scope_entities:
            siemplify.LOGGER.info(u"Started processing entity: {}".format(entity.identifier))
            try:
                date = datetime.datetime.now()
                data = cisco_umbrella_manager.buildEvent(entity.identifier, time=date)
                cisco_umbrella_manager.addDomain(data)
                result_value = True
                successful_entities.append(entity)
                siemplify.LOGGER.info(u"Finished processing entity {0}".format(entity.identifier))
            except Exception as e:
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"An error occurred on entity {0}".format(entity.identifier))
                siemplify.LOGGER.exception(e)

                # Organize Output Message.
        if successful_entities:
            entities_names = [entity.identifier for entity in successful_entities]
            output_message += 'Successfully processed entities: \n{}\n'.format(
                '\n'.join(entities_names)
            )

            siemplify.update_entities(successful_entities)

        if failed_entities:
            output_message += '\nFailed processing entities:\n{}\n'.format(
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

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
