from SiemplifyUtils import output_handler
from ZscalerManager import ZscalerManager, ZscalerMissingError
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'Zscaler - Remove from blacklist'
    conf = siemplify.get_configuration('Zscaler')
    cloud_name = conf['Api Root']
    login_id = conf['Login ID']
    api_key = conf['Api Key']
    password = conf['Password']
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    zscaler_manager = ZscalerManager(cloud_name, login_id, api_key, password, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

    domains = []
    already_exists = []
    errors = []
    output_message = ''
    result_value = 'true'

    for entity in siemplify.target_entities:
        entity_to_block = None
        if entity.entity_type == EntityTypes.URL or entity.entity_type == EntityTypes.HOSTNAME:
            entity_to_block = zscaler_manager.validate_and_extract_url(entity.identifier.lower())

        if entity.entity_type == EntityTypes.ADDRESS and not entity.is_internal:
            entity_to_block = entity.identifier

        if entity_to_block:
            try:
                zscaler_manager.remove_from_blacklist(entity_to_block)
                # apply changes
                zscaler_manager.activate_changes()
                domains.append(entity.identifier)

            except ZscalerMissingError:
                already_exists.append(entity.identifier)
                siemplify.LOGGER.info(
                    "Unnecessary operation. {0} already removed from the blacklist".format(entity.identifier))

            except Exception as e:
                errors.append(entity.identifier)
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)

    if domains:
        output_message += 'Successfully remove the following entities from the Urls blacklist:\n' +\
                         '\n'.join(domains)

    if errors:
        output_message += '\n Errors occurred, check log for more information'

    if already_exists:
        output_message += '\n The following entities already removed from the blacklist:\n' + \
                          '\n'.join(already_exists)

    if not errors and not domains and not already_exists:
        output_message = "No entities were removed from the Urls blacklist"
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
