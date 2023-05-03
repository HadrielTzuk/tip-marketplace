from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from F5BigIQManager import F5BigIQManager
from TIPCommon import extract_configuration_param
# consts
f5_big_iq_provider = 'F5BigIQ'
SCRIPT_NAME = 'Change Policy Enforcement Mode'


@output_handler
def main():

    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    # configuration.
    config = siemplify.get_configuration(f5_big_iq_provider)
    host_address = config['Server Address']
    username = config['Username']
    password = config['Password']
    verify_ssl = extract_configuration_param(siemplify, provider_name=f5_big_iq_provider, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    f5_bigiq_manager = F5BigIQManager(host_address, username, password, verify_ssl)

    # parameters.
    policy_id = siemplify.parameters['Policy ID']
    enforcement_mode = siemplify.parameters['Enforcement Mode']

    # get event logs result.
    result_value = f5_bigiq_manager.change_policy_enforcement_mode(policy_id, enforcement_mode)
    output_message = 'Policy with ID:{0} enforcement mode changed to: {1}'.format(policy_id, enforcement_mode)

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
