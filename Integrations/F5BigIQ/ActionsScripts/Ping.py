from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from F5BigIQManager import F5BigIQManager
from TIPCommon import extract_configuration_param
import json

# consts
F5_BIG_IQ_PROVIDER = 'F5BigIQ'
SCRIPT_NAME = 'Get Event Logs By Blocking ID'


@output_handler
def main():

    # define variables.
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    # configuration.
    config = siemplify.get_configuration(F5_BIG_IQ_PROVIDER)
    host_address = config['Server Address']
    username = config['Username']
    password = config['Password']
    verify_ssl = extract_configuration_param(siemplify, provider_name=F5_BIG_IQ_PROVIDER, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    f5_bigiq_manager = F5BigIQManager(host_address, username, password, verify_ssl)

    if f5_bigiq_manager:
        output_message = 'Connection Established'
        result_value = True
    else:
        output_message = 'Connection Failed'
        result_value = False

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
