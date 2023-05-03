import json
from CynetManager import CynetManager
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param

INTEGRATION_NAME = "Cynet"


@output_handler
def main():
    siemplify = SiemplifyAction()
    hash_report = {}
    remediation_status_dict = {}

    # Configuration.
    conf = siemplify.get_configuration("Cynet")
    api_root = conf['Api Root']
    username = conf['Username']
    password = conf['Password']
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    cynet_manager = CynetManager(api_root, username, password, verify_ssl)

    remediation_id = siemplify.parameters.get('Remediation Id')
    remidaition_status = cynet_manager.get_remediation_status(remediation_id)

    if remidaition_status:
        status_message = ''
        for key, val in remidaition_status.items():
            status_message += "{0}: {1}, ".format(key,val)
        output_message = 'Remidiation status \n{0}'.format(status_message[:-1])
        result_value = 'true'
    else:
        output_message = 'Could not find results.'
        result_value = 'false'

    siemplify.result.add_result_json(json.dumps(remidaition_status))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
