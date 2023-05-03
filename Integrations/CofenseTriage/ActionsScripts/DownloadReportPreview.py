from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from CofenseTriageManager import CofenseTriageManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import (
    INTEGRATION_NAME,
    DOWNLOAD_REPORT_PREVIEW_ACTION,
    PNG_FILE_NAME,
    JPG_FILE_NAME,
    PNG_FORMAT,
    JPG_FORMAT

)
from UtilsManager import save_image_attachment
import os
import base64
from SiemplifyDataModel import InsightSeverity, InsightType
from CofenseTriageExceptions import (
    RecordNotFoundException
)

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOAD_REPORT_PREVIEW_ACTION
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Root", is_mandatory=True, print_value=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client ID", is_mandatory=True, print_value=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Client Secret", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True, print_value=True)

    report_id = extract_action_param(siemplify, param_name="Report ID", is_mandatory=True, print_value=True, input_type=str)
    download_folder = extract_action_param(siemplify, param_name="Download Folder", is_mandatory=True, print_value=True, input_type=str)
    image_format = extract_action_param(siemplify, param_name="Image Format", is_mandatory=True, print_value=True, input_type=str)
    overwrite = extract_action_param(siemplify, param_name="Overwrite", is_mandatory=False, default_value=False, print_value=True, input_type=bool)    
    create_insight = extract_action_param(siemplify, param_name="Create Insight", is_mandatory=False, default_value=False, print_value=True, input_type=bool)  
    
    output_message = ""
    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    json_results = {}

    if not download_folder.endswith("/"):
        download_folder = "{}{}".format(download_folder,"/")    
    
    if image_format == JPG_FORMAT:
        file_name = JPG_FILE_NAME.format(report_id)
        
    if image_format == PNG_FORMAT:
        file_name = PNG_FILE_NAME.format(report_id)
        
    absolute_file_path = "{}{}".format(download_folder, file_name)
    
    if not overwrite:
        if os.path.exists(absolute_file_path):
            status = EXECUTION_STATE_FAILED
            result_value = False
            output_message += "Error executing action {}. Reason: File with that file path already exists. Please remove it or set \"Overwrite\" to true".format(DOWNLOAD_REPORT_PREVIEW_ACTION)
            siemplify.LOGGER.error(output_message)
            siemplify.LOGGER.info('----------------- Main - Finished -----------------')
            siemplify.LOGGER.info(
                '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
            siemplify.end(output_message, result_value, status)        
    
    try:
        cofensetriage_manager = CofenseTriageManager(api_root=api_root, client_id=client_id, client_secret=client_secret, verify_ssl=verify_ssl)
        
        email_report = cofensetriage_manager.download_report_preview(report_id=report_id, image_format=image_format )
        absolute_file_path = save_image_attachment(path=download_folder, name=file_name, content=email_report.raw)
        
        json_results = {"absolute_file_path": absolute_file_path }
        
        with open(absolute_file_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
            
        if create_insight:
            siemplify.create_case_insight(triggered_by=INTEGRATION_NAME,
                                    title="Report {}. Preview".format(report_id),
                                    content='<img src="data:image/jpeg;base64,{}">'.format(encoded_string.decode("utf-8")),
                                    entity_identifier="",
                                    severity=InsightSeverity.INFO,
                                    insight_type=InsightType.General)
        
        
        output_message += "Successfully downloaded preview related to the report with ID {} in {}".format(report_id, INTEGRATION_NAME)        
        siemplify.result.add_result_json(json_results)
        
    except RecordNotFoundException as e:
        output_message += "Action wasn't able to download a preview related to the report with ID {} in {}. Reason:\n {}".format(report_id, DOWNLOAD_REPORT_PREVIEW_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False    
        
    except Exception as e:
        output_message += 'Error executing action {}. Reason: {}'.format(DOWNLOAD_REPORT_PREVIEW_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
