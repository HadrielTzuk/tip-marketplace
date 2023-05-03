from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction, ScriptResult
from AnyRunManager import AnyRunManager
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyDataModel import EntityTypes
from AnyRunExceptions import AnyRunError
from constants import (
    INTEGRATION_NAME,
    ANALYZE_FILEURL_ACTION,
    NETWORK_STATUS_MAPPING,
    STATUS_IN_PROGRESS,
    NETWORK_PRIVACY_TYPE,
    FILEURL_ELEMENT
)
import json
import sys

def start_operation(siemplify, anyrun_manager, wait_for_report, element_for_analysis, os_version ,operation_system_bitness, os_env_type,
                                                            network_connection_status, fakenet_feature_status,
                                                            use_tor, opt_network_mitm, opt_network_geo,
                                                            opt_network_heavyevasion, opt_privacy_type,
                                                            obj_ext_startfolder, opt_timeout,active_session):
    """
    Function that requests the analysis
    :param siemplify: SiemplifyAction object.
    :param anyrun_manager: AnyRun manager object.
    :param wait_for_report: {bool} Indicates if the action should be async or return the task id
    :param element_for_analysis: {str} File URL that should be analyzed
    :param os_env_type{string} Environment Type 
    :param os_version{string} Windows OS Version
    :param operation_system_bitness{string} Operation System Bitness
    :param network_connection_status{bool} Whether or now the Network connection status should be used
    :param fakenet_feature_status{bool} Whether or now the FakeNet should be used
    :param use_tor{bool} Whether or now the Tor should be used
    :param opt_network_geo {string} Which GEO Location to use
    :param opt_network_mitm {bool} Whether or now the MITM should be used
    :param opt_network_heavyevasion{bool} Whether or now the HeavyEvasion should be used
    :param opt_privacy_type {string}  Privacy Type
    :param opt_timeout {int} Timeout in seconds         
    :param active_session{int} How many seconds to wait for the available session   
    :param obj_ext_startfolder {string} Type of the startfolder
    """
    
    status = EXECUTION_STATE_INPROGRESS
    try:

        task = anyrun_manager.analyze(element_type=FILEURL_ELEMENT,element_for_analysis=element_for_analysis, os_version=os_version ,operation_system_bitness=operation_system_bitness, os_env_type=os_env_type,
                                                    network_connection_status=network_connection_status, fakenet_feature_status=fakenet_feature_status,
                                                    use_tor=use_tor, opt_network_mitm=opt_network_mitm, opt_network_geo=opt_network_geo,
                                                    opt_network_heavyevasion=opt_network_heavyevasion, opt_privacy_type=opt_privacy_type,
                                                    obj_ext_startfolder=obj_ext_startfolder, opt_timeout=opt_timeout, active_session=active_session)
        
        if task.task_id:
            result_value = {
                        "task_id": task.task_id
                    }
            
            result_value = json.dumps(result_value)
            
            output_message = "Created analysis tasks for the following File URL: {}".format(element_for_analysis)
        else:
            result_value=False
            output_message = "No Any.Run analysis tasks were created for the following File URL: {}".format(element_for_analysis)
            status = EXECUTION_STATE_COMPLETED
            
    except AnyRunError as e:
        output_message = "Action reached timeout waiting for report for file: {0}".format(element_for_analysis)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        return output_message, result_value, status
                
    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(ANALYZE_FILEURL_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        return output_message, result_value, status
        
    if not wait_for_report:
        result_value = True
        status = EXECUTION_STATE_COMPLETED
        siemplify.result.add_result_json(task.raw_data)
        
    return output_message, result_value, status

def query_operation_status(siemplify, anyrun_manager,element_for_analysis):
    """
    Function that periodically fetches the results of the analysis
    :param siemplify: SiemplifyAction object.
    :param anyrun_manager: AnyRun manager object.
    :param element_for_analysis: {str} File URL that should be analyzed
    """
    
    task_analysis = json.loads(siemplify.extract_action_param("additional_data"))
    
    try:
        task_id = task_analysis.get("task_id")
        analysis_report = anyrun_manager.fetch_report(task_id)
        analysis_status = analysis_report.status
        
    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(ANALYZE_FILEURL_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        return output_message, result_value, status
    
    if analysis_status == STATUS_IN_PROGRESS:
        status = EXECUTION_STATE_INPROGRESS
        result_value = json.dumps(task_analysis)
        output_message = "Report of the File URL {} with ID: {} is not ready yet. Will check again later....".format(element_for_analysis, task_id) 
    
    else:
        status = EXECUTION_STATE_COMPLETED
        result_value = True
        output_message = "Report of the File URL analysis successfully prepared."
        siemplify.result.add_result_json(analysis_report.raw_data)
                    
    return output_message, result_value, status

@output_handler
def main(is_first_run):
    siemplify = SiemplifyAction()
    siemplify.script_name = ANALYZE_FILEURL_ACTION
    mode = "Main" if is_first_run else "Get Report"
    siemplify.LOGGER.info("----------------- {} - Param Init -----------------".format(mode))

    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Api Key")
    
    url_for_analysis = extract_action_param(siemplify, param_name="URL to File", is_mandatory=True, print_value=True)
    wait_for_report = extract_action_param(siemplify, param_name="Wait for the report?", is_mandatory=False, default_value=True, input_type=bool, print_value=True)
    active_session = extract_action_param(siemplify, param_name="Try to create submission for x times", is_mandatory=True, default_value=30, input_type=int, print_value=True)
    os_version = extract_action_param(siemplify, param_name="OS Version", is_mandatory=False, print_value=True)
    operation_system_bitness = extract_action_param(siemplify, param_name="Operation System Bitness", is_mandatory=False, print_value=True)
    os_env_type = extract_action_param(siemplify, param_name="OS Environment Type", is_mandatory=False, print_value=True)
    network_connection_status = extract_action_param(siemplify, param_name="Network Connection Status", is_mandatory=False, print_value=True)
    fakenet_feature_status = extract_action_param(siemplify, param_name="FakeNet Feature Status", is_mandatory=False, print_value=True)
    use_tor = extract_action_param(siemplify, param_name="Use TOR", is_mandatory=False, print_value=True)
    opt_network_mitm = extract_action_param(siemplify, param_name="opt_network_mitm", is_mandatory=False, print_value=True)
    opt_network_geo = extract_action_param(siemplify, param_name="opt_network_geo", is_mandatory=False, print_value=True)
    opt_network_heavyevasion = extract_action_param(siemplify, param_name="opt_network_heavyevasion", is_mandatory=False, print_value=True)
    opt_privacy_type = extract_action_param(siemplify, param_name="opt_privacy_type", is_mandatory=False, print_value=True)
    obj_ext_startfolder = extract_action_param(siemplify, param_name="obj_ext_startfolder", is_mandatory=False, print_value=True)
    opt_timeout = extract_action_param(siemplify, param_name="opt_timeout", is_mandatory=False, print_value=True)

    #Mapping of params
    network_connection_status = NETWORK_STATUS_MAPPING.get(network_connection_status)
    opt_privacy_type = NETWORK_PRIVACY_TYPE.get(opt_privacy_type)  

    siemplify.LOGGER.info("----------------- {} - Started -----------------".format(mode))

    try:
        anyrun_manager = AnyRunManager(api_key=api_key)

        if is_first_run:
            output_message, result_value, status = start_operation(siemplify=siemplify, anyrun_manager=anyrun_manager,wait_for_report=wait_for_report,element_for_analysis=url_for_analysis, os_version=os_version ,operation_system_bitness=operation_system_bitness, os_env_type=os_env_type,
                                                            network_connection_status=network_connection_status, fakenet_feature_status=fakenet_feature_status,
                                                            use_tor=use_tor, opt_network_mitm=opt_network_mitm, opt_network_geo=opt_network_geo,
                                                            opt_network_heavyevasion=opt_network_heavyevasion, opt_privacy_type=opt_privacy_type,
                                                            obj_ext_startfolder=obj_ext_startfolder, opt_timeout=opt_timeout,active_session=active_session)
        else:
            output_message, result_value, status = query_operation_status(siemplify=siemplify, anyrun_manager=anyrun_manager,element_for_analysis=url_for_analysis)

    except Exception as e:
        output_message = 'Error executing action {}. Reason: {}'.format(ANALYZE_FILEURL_ACTION, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info("----------------- {} - Finished -----------------".format(mode))
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
        
    siemplify.end(output_message, result_value, status)

if __name__ == '__main__':
    is_first_run = len(sys.argv) < 3 or sys.argv[2] == 'True'
    main(is_first_run)
