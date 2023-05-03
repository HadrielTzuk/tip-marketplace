from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import dict_to_flat, flat_dict_to_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
from CuckooManager import CuckooManager
import sys
import json
from TIPCommon import extract_configuration_param, extract_action_param

SCRIPT_NAME = "Cuckoo - GetReport"
INTEGRATION_NAME = "Cuckoo"

def construct_flat_dict_from_report(result_json):
    """
    Create flat JSON from chosen key.
    :param result_json: {dict} JSON result.
    :return: {dict} flat dict.
    """
    result_dict = {}
    if "info" in result_json:
        info = result_json.get('info')
        result_dict['added'] = info.get('added')
        result_dict['duration'] = info.get('duration')
        result_dict['score'] = info.get('score')
        result_dict['id'] = info.get('id')
    if "target" in result_json:
        result_dict.update(dict_to_flat(result_json.get('target')))

    return result_dict


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    
    server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Api Root", is_mandatory=True)
    web_interface_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Web Interface Address", is_mandatory=True)
    ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="CA Certificate File", is_mandatory=False)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool, is_mandatory=True)    
    api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Token", is_mandatory=False)  
    
    task_id = extract_action_param(siemplify, param_name="Task ID", is_mandatory=True, print_value=True, input_type=str)

    cuckoo_manager = CuckooManager(server_address, web_interface_address, ca_certificate, verify_ssl, api_token)
    siemplify.LOGGER.info("Connected to Cuckoo {}".format(server_address))

    if cuckoo_manager.is_task_reported(task_id):
        report = cuckoo_manager.get_report(task_id)
        score = report.get('info', {}).get('score')

        if web_interface_address:
            siemplify.result.add_entity_link("Report Link For Task With ID: {0}".format(task_id),
                                             cuckoo_manager.construct_report_url(task_id))

        siemplify.result.add_data_table("Result For Task With ID: {0}".format(task_id), flat_dict_to_csv(
            construct_flat_dict_from_report(report)))

        siemplify.result.add_result_json(json.dumps(report))

        siemplify.end("Fetched report for task {}".format(task_id),
                      json.dumps(score), EXECUTION_STATE_COMPLETED)
    else:
        siemplify.end("Task {} in progress.".format(task_id), 'true',
                      EXECUTION_STATE_INPROGRESS)


def async_analysis():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("Start async")

    try:
        server_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                    param_name="Api Root", is_mandatory=True)
        web_interface_address = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                    param_name="Web Interface Address", is_mandatory=True)
        ca_certificate = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                    param_name="CA Certificate File", is_mandatory=False)
        verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                                default_value=False, input_type=bool, is_mandatory=True)    
        api_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="API Token", is_mandatory=False)    

        task_id = extract_action_param(siemplify, param_name="Task ID", is_mandatory=True, print_value=True, input_type=str)

        cuckoo_manager = CuckooManager(server_address, web_interface_address, ca_certificate, verify_ssl, api_token)
        

        siemplify.LOGGER.info("Connected to Cuckoo {}".format(server_address))

        if cuckoo_manager.is_task_reported(task_id):
            report = cuckoo_manager.get_report(task_id)
            score = report.get('info', {}).get('score')

            if web_interface_address:
                siemplify.result.add_entity_link("Report Link For Task With ID: {0}".format(task_id),
                                                 cuckoo_manager.construct_report_url(task_id))

            siemplify.result.add_data_table("Result For Task With ID: {0}".format(task_id), flat_dict_to_csv(
                construct_flat_dict_from_report(report)))

            siemplify.result.add_result_json(json.dumps(report))
            siemplify.LOGGER.info("Successfully fetch report for task {0}".format(task_id))
            siemplify.end("Fetched report for task {}".format(task_id),
                          json.dumps(score),
                          EXECUTION_STATE_COMPLETED)

        else:
            siemplify.end("Task {} in progress.".format(task_id), 'true',
                          EXECUTION_STATE_INPROGRESS)

    except Exception as e:
        siemplify.LOGGER.exception(e)


if __name__ == '__main__':
    if len(sys.argv) < 3 or sys.argv[2] == 'True':
        main()
    else:
        async_analysis()
