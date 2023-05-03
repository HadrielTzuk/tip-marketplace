from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from NetskopeManager import NetskopeManager
import base64
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

INTEGRATION_NAME = "Netskope"
DOWNLOADFILE_SCRIPT_NAME = '{} - DownloadFile'.format(INTEGRATION_NAME)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOADFILE_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Root',
                                           is_mandatory=True)
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Api Key',
                                           is_mandatory=True)    
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                           is_mandatory=True, default_value=True, input_type=bool)

    # Parameters
    file_id = extract_action_param(siemplify, param_name='File ID', is_mandatory=True)
    quarantine_profile_id = extract_action_param(siemplify, param_name='Quarantine Profile ID', is_mandatory=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')
    status = EXECUTION_STATE_FAILED
    result_value = False
    file_name = ""
    output_message = "File {} was not found in quarantine.".format(file_id)
    try:
        netskope_manager = NetskopeManager(server_address, api_key, verify_ssl=verify_ssl)
        files = netskope_manager.get_quarantined_files()
        file_content = netskope_manager.download_file(file_id, quarantine_profile_id)
        
        for quarantined_file in files:
            if quarantined_file.get("file_id") == file_id and quarantined_file.get(
                    "quarantine_profile_id") == quarantine_profile_id:
                file_name = quarantined_file.get("original_file_name")

        if file_name:
            siemplify.result.add_attachment(file_name, file_name, base64.b64encode(file_content).decode('ascii'))
            output_message = "Successfully downloaded file {}".format(file_id)
            result_value = True
        status = EXECUTION_STATE_COMPLETED 
        
    except Exception as e:
        output_message = "Error executing action \"DownloadFile\". Reason: {}".format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)
  
if __name__ == "__main__":
    main()