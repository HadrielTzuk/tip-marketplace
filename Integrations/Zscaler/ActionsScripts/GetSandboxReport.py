from SiemplifyUtils import output_handler
from ZscalerManager import ZscalerManager
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import dict_to_flat, create_entity_json_result_object, flat_dict_to_csv


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = 'Zscaler - Get Sandbox Report'
    conf = siemplify.get_configuration('Zscaler')
    cloud_name = conf['Api Root']
    login_id = conf['Login ID']
    api_key = conf['Api Key']
    password = conf['Password']
    verify_ssl = conf.get('Verify SSL', 'False').lower() == 'true'
    zscaler_manager = ZscalerManager(cloud_name, login_id, api_key, password, verify_ssl=verify_ssl, logger=siemplify.LOGGER)

    json_results = []
    errors = []
    result_value = 'false'
    entities = []
    output_message = ''
    missing_entities = []

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.FILEHASH:
            try:
                report = zscaler_manager.get_sandbox_report(entity.identifier)
                if report:
                    result_value = 'true'
                    entities.append(entity.identifier)
                    json_results.append(create_entity_json_result_object(entity.identifier, report))
                    flat_dict = dict_to_flat(report)
                    siemplify.result.add_entity_table('{0} Sandbox Report'.format(entity.identifier),
                                                      flat_dict_to_csv(flat_dict))
                else:
                    missing_entities.append(entity.identifier)
                    siemplify.LOGGER.info("{0} does not exist on Zscaler or not yet been completed".format(entity.identifier))

            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)
                errors.append(entity.identifier)

    if entities:
        output_message += 'The following Hashes found in Zscaler: \n{0}'.format('\n'.join(entities))

    if errors:
        output_message += 'Errors occurred on the following entities: \n{0}\nCheck logs for more details'.format('\n'.join(errors))

    if missing_entities:
        # Missing hash handle
        output_message += "The following hashes does not exist on Zscaler or not yet been completed: " \
                          "{0}\n".format(",".join(missing_entities))

    if not entities and not errors and not missing_entities:
        output_message = 'No entities were found in Zscaler.'

    # add json
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
