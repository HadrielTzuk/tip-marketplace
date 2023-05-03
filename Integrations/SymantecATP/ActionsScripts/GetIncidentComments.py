# coding=utf-8
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from SymantecATPManager import SymantecATPManager, SymantecATPTokenPermissionError, SymantecATPIncidentNotFoundError
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyDataModel import EntityTypes

# =====================================
#             CONSTANTS               #
# =====================================
SCRIPT_NAME = u'SymantecATP_Get Incident Comments'
INTEGRATION_NAME = u"SymantecATP"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    output_message = u""
    is_success = u"true"
    json_results = []
    csv_table = []
        
    status = EXECUTION_STATE_COMPLETED
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")
 
    # Integration Parameters
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client ID",
                                           is_mandatory=True)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Client Secret",
                                           is_mandatory=True)    
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)
    
    #Action Parameters
    incident_uuid = extract_action_param(siemplify, param_name=u"Incident UUID", is_mandatory=True)
    max_comments_to_return = extract_action_param(siemplify, param_name=u"Max Comments To Return", is_mandatory=False, default_value=20, input_type=int, print_value=True)
    
    if max_comments_to_return > 1000:
        max_comments_to_return = 1000
    
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")    
    try:
        atp_manager = SymantecATPManager(api_root, client_id, client_secret, verify_ssl)
        comments = atp_manager.get_comments_for_incident(incident_uuid,max_comments_to_return)

        for comment in comments:
            csv_table.append(comment.to_table())
            json_results.append(comment.to_json())
              
        if not comments:
            is_success = u"false"
            siemplify.LOGGER.info(u"No comments were found for the Symantec ATP incident with UUID {}".format(incident_uuid))  
            output_message += u"No comments were found for the Symantec ATP incident with UUID {}".format(incident_uuid)       
        else:
            siemplify.result.add_data_table(title=u"Symantec ATP Incident {} Comments".format(incident_uuid), data_table= construct_csv(csv_table))
            siemplify.result.add_result_json(json_results) 
            siemplify.LOGGER.info(u"Successfully returned comments for Symantec ATP incident with UUID {}".format(incident_uuid))
            output_message += u"Successfully returned comments for Symantec ATP incident with UUID {}".format(incident_uuid)

    except SymantecATPIncidentNotFoundError as e:
        is_success = u"false"
        output_message = u"Symantec ATP Incident with UUID {} was not found".format(incident_uuid)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        
    except SymantecATPTokenPermissionError as e:
        is_success = u"false"
        output_message = u"API token doesn’t have permissions to perform this action"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    except Exception as e:
        siemplify.LOGGER.error(u"General error performing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message += u"Error executing action Get Incident Comments. Reason: {0}".format(e)
        is_success = u"false"   

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, is_success, output_message))
    siemplify.end(output_message, is_success, status)
    
if __name__ == "__main__":
    main()