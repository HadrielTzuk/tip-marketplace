from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction, ScriptResult
from RSAManager import RSAManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import EntityTypes
from constants import (
    INTEGRATION_NAME,
    ADDIPTOBLOCKLIST_ACTION
)

SUPPORTED_ENTITY_TYPES = [EntityTypes.ADDRESS]

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADDIPTOBLOCKLIST_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root")
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Username")
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Password")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool, is_mandatory=True)
                                             
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    successful_entities = []
    failed_entities = []
    output_message = ""
    ips_to_blocklist = [entity.identifier for entity in siemplify.target_entities if entity.entity_type in SUPPORTED_ENTITY_TYPES]
    
    if ips_to_blocklist:
        try:
            rsa_manager = RSAManager(api_root=api_root, username=username,
                                     password=password, verify_ssl=verify_ssl)
    
            ip_response = rsa_manager.add_ip_to_blocklist(ips_to_blocklist)
            siemplify.result.add_result_json(ip_response.to_json())       
            
            for entity in ips_to_blocklist:
                if entity not in ip_response.ips:
                    failed_entities.append(entity)
                else:
                    successful_entities.append(entity)
    
        except Exception as e:
            output_message = 'Error executing action {}. Reason: {}'.format(ADDIPTOBLOCKLIST_ACTION, e)
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.exception(e)
            status = EXECUTION_STATE_FAILED
            result_value = False


    if successful_entities:
        output_message = "Successfully added following IPs to blacklist in RSA Netwitness EDR: {}".format("\n".join([entity for entity in successful_entities]))
        
    if failed_entities:
        output_message += "Action was not able to add the following IPs to blacklist in RSA Netwitness EDR: {}".format("\n".join([entity for entity in failed_entities]))
        
    if not successful_entities and not failed_entities:
        result_value = False
        output_message += "No IPs were added to the blacklist in RSA Netwitness EDR."

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
