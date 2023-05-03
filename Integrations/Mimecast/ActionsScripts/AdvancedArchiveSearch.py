from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MimecastManager import MimecastManager
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import INTEGRATION_NAME, ADVANCED_ARCHIVE_SEARCH_ACTION

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADVANCED_ARCHIVE_SEARCH_ACTION

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    app_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Application ID",
                                            is_mandatory=True, print_value=True)
    app_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Application Key",
                                          is_mandatory=True)
    access_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Access Key",
                                             is_mandatory=True)
    secret_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Secret Key",
                                             is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, is_mandatory=True, print_value=True)

    xml_query = extract_action_param(siemplify, param_name="XML Query", print_value=True, is_mandatory=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = MimecastManager(api_root=api_root,
                                  app_id=app_id,
                                  app_key=app_key,
                                  access_key=access_key,
                                  secret_key=secret_key,
                                  verify_ssl=verify_ssl,
                                  siemplify=siemplify)
        
        archived_emails = manager.execute_query(xml_query=xml_query)
        
        if archived_emails:
            json_result = [archived_email.to_json() for archived_email in archived_emails]
            data_table = [archived_email.to_csv() for archived_email in archived_emails]
            
            siemplify.result.add_result_json(json_result)
            
            siemplify.result.add_data_table(
                    f"Results",
                    data_table=construct_csv(data_table))
            output_message = f"Successfully found archive emails for the provided criteria in {INTEGRATION_NAME}."
            
        else:
            output_message = f"No archive emails were found for the provided criteria in {INTEGRATION_NAME}."  
         
    except Exception as e:
        output_message = f'Error executing action {ADVANCED_ARCHIVE_SEARCH_ACTION}. Reason: {e}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(f'\n  status: {status}\n  result_value: {result_value}\n  output_message: {output_message}')
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()