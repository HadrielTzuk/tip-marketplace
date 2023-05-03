from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecATPManager import SymantecATPManager


ATP_PROVIDER = 'SymantecATP'
ACTION_NAME = "SymantecATP_Revoke From Blacklist"
INSIGHT_MESSAGE = "{0} revoked from blacklist."


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(ATP_PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    atp_manager = SymantecATPManager(conf.get('API Root'), conf.get('Client ID'), conf.get('Client Secret'), verify_ssl)

    errors = []
    revoked_entities = []
    result_value = False

    for entity in siemplify.target_entities:
        try:

            result = atp_manager.delete_blacklist_policy_by_identifier(entity.identifier)

            if result:
                revoked_entities.append(entity)
                siemplify.add_entity_insight(entity, INSIGHT_MESSAGE.format(entity.identifier),
                                             triggered_by=ATP_PROVIDER)
                result_value = True

        except Exception as err:
            error_message = 'Error revoke "{0}" from blacklist, Error: {1}'.format(entity.identifier, err.message)
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors.append(error_message)

    if result_value:
        output_message = "{0} were revoked from blacklisted.".format(",".join([entity.identifier for entity
                                                                               in revoked_entities]))
    else:
        output_message = "No entities were revoked from blacklisted."

    # Attach errors if exists.
    if errors:
        output_message = "{0},\n\nERRORS:\n{1} ".format(output_message, '\n'.join(errors))

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
