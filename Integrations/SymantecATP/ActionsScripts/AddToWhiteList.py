from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SymantecATPManager import SymantecATPManager
from SiemplifyDataModel import EntityTypes
from SymantecATPManager import ATPEntityTypes


ATP_PROVIDER = 'SymantecATP'
ACTION_NAME = "SymantecATP_Add To Whitelist"
INSIGHT_MESSAGE = '{0} was Whitelisted.'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME
    conf = siemplify.get_configuration(ATP_PROVIDER)
    verify_ssl = conf.get('Verify SSL', 'false').lower() == 'true'
    atp_manager = SymantecATPManager(conf.get('API Root'), conf.get('Client ID'), conf.get('Client Secret'), verify_ssl)

    errors = []
    whitelisted_entities = []
    result_value = False

    for entity in siemplify.target_entities:
        try:
            result = None

            if entity.entity_type == EntityTypes.FILEHASH:
                if atp_manager.is_hash_sha256(entity.identifier):
                    result = atp_manager.create_whitelist_policy(entity.identifier, ATPEntityTypes.SHA256)
            elif entity.entity_type == EntityTypes.HOSTNAME:
                result = atp_manager.create_whitelist_policy(entity.identifier, ATPEntityTypes.HOST)
            elif entity.entity_type == EntityTypes.ADDRESS:
                result = atp_manager.create_whitelist_policy(entity.identifier, ATPEntityTypes.ADDRESS)
            elif entity.entity_type == EntityTypes.URL:
                result = atp_manager.create_whitelist_policy(entity.identifier, ATPEntityTypes.URL)

            if result:
                whitelisted_entities.append(entity)
                siemplify.add_entity_insight(entity, INSIGHT_MESSAGE.format(entity.identifier),
                                             triggered_by=ATP_PROVIDER)
                result_value = True

        except Exception as err:
            error_message = 'Error adding "{0}" to a whitelist, Error: {1}'.format(entity.identifier, err.message)
            siemplify.LOGGER.error(error_message)
            siemplify.LOGGER.exception(err)
            errors.append(error_message)

    if result_value:
        output_message = "{0} were whitelisted.".format(",".join([entity.identifier for entity in
                                                                  whitelisted_entities]))
    else:
        output_message = "No entities were whitelisted."

    # Attach errors if exists.
    if errors:
        output_message = "{0},\n\nERRORS:\n{1}".format(output_message, ' \n '.join(errors))

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
