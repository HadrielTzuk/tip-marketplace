from SiemplifyUtils import output_handler
from TrendmicroDeepSecurityManager import TrendmicroManager
from SiemplifyAction import SiemplifyAction
from SiemplifyDataModel import EntityTypes

SCRIPT_NAME = "TrendMicro Deep Security - AssignSecurityProfileToHost"


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

    # security profile that will be assigned to the hosts
    security_profile = siemplify.parameters.get('Security Profile Name')
    # Get policy ID
    policy_id = trendmicro_manager.get_policy_id_by_name(security_profile)

    entities = []

    for entity in siemplify.target_entities:
        if entity.entity_type == EntityTypes.HOSTNAME and not entity.is_internal:
            try:
                computer_id = trendmicro_manager.get_computer_id_by_name(entity.identifier)
                trendmicro_manager.assign_policy_to_computers(policy_id, computer_id)
                entities.append(entity.identifier)
            except Exception as e:
                # An error occurred - skip entity and continue
                siemplify.LOGGER.error("An error occurred on entity: {}.\n{}.".format(entity.identifier, str(e)))
                siemplify.LOGGER.exception(e)

    if entities:
        result_value = 'true'
        output_message = '{0} policy was assign to {1}'.format(security_profile, ', '.join([entity for entity in entities]))
    else:
        result_value = 'false'
        output_message = 'Can not assign {0} security profile'.format(security_profile)

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()