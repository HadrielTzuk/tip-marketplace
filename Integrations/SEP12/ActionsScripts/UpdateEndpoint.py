from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from SEP12Manager import SymantecEp12, COMPLETED, STATUS
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = "SEP12"
ACTION_NAME = "SEP12 - Update"
COMMAND = "sep_update_command_id"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    output_message = ""
    errors = ""

    siemplify.LOGGER.info("Starting Action")

    conf = siemplify.get_configuration('SEP12')
    client_id = conf["Client ID"]
    client_secret = conf["Client Secret"]
    refresh_token = conf["Refresh Token"]
    root_url = conf["Api Root"]
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             input_type=bool, default_value=False)
    sep_manager = SymantecEp12(root_url, client_id, client_secret, refresh_token, verify_ssl)
    siemplify.LOGGER.info("Connected.")

    enriched_entities = []

    for entity in siemplify.target_entities:
        try:
            computer_id = None

            if entity.entity_type == EntityTypes.ADDRESS:
                computer_id = sep_manager.getComputerIdByIP(entity.identifier)

            elif entity.entity_type == EntityTypes.HOSTNAME:
                computer_id = sep_manager.getComputerIdByComputerName(
                    entity.identifier)

                if not computer_id:
                    # Try separating the domain from the entity identifier:
                    computer_id = sep_manager.getComputerIdByComputerName(
                        entity.identifier.split(".")[0])

            if computer_id:
                siemplify.LOGGER.info("Scanning {}".format(entity.identifier))

                command_id = sep_manager.runClientCommandUpdate(computer_id)

                entity.additional_properties.update({
                    COMMAND: command_id,
                })

                enriched_entities.append(entity)

        except Exception as e:
            errors += "Update failed on {0}:\n{1}\n".format(entity.identifier, e.message)
            siemplify.LOGGER.error(
                "An error occurred on entity: {}.\n{}.".format(
                    entity.identifier, str(e)
                ))
            siemplify.LOGGER.exception(e)
            continue

    if enriched_entities:
        entities_names = ["{0}: {1}\n".format(entity.identifier,
                                            entity.additional_properties[
                                                COMMAND]) for entity in
                          enriched_entities]

        output_message += 'Updating the following entities:\n' + '\n'.join(
            entities_names)
        output_message += errors

        siemplify.update_entities(enriched_entities)
        siemplify.end(output_message, 'true')

    else:
        output_message += 'No suitable entities were found.\n'
        output_message += errors

        siemplify.end(output_message, 'false')


if __name__ == "__main__":
    main()

