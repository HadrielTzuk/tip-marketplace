from SiemplifyUtils import output_handler
from TrendmicroDeepSecurityManager import TrendmicroManager
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes

SCRIPT_NAME = "TrendMicro Deep Security - ScanHost"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME

    conf = siemplify.get_configuration('TrendMicroDeepSecurity')
    api_root = conf.get('Api Root')
    api_key = conf.get('Api Secret Key')
    api_version = conf.get('Api Version')
    use_ssl = conf.get("Verify SSL")
    trendmicro_manager = TrendmicroManager(api_root, api_key, api_version, use_ssl)

    entities = []

    # TODO: Need to double check the development

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.HOSTNAME and not entity.is_internal:
            try:
                trendmicro_manager.scan_computers_for_malware(entity.identifier)
                entities.append(entity.identifier)
            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)

    if entities:
        result_value = 'true'
        output_message = 'Successfully request a malware scan on {0}'.format(', '.join([entity for entity in entities]))
    else:
        result_value = 'false'
        output_message = 'Failed to request a malware scan.'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()