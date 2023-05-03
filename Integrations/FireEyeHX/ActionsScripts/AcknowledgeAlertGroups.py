from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from FireEyeHXManager import FireEyeHXManager, FireEyeHXNotFoundError
from SiemplifyUtils import output_handler

INTEGRATION_NAME = u"FireEyeHX"
SCRIPT_NAME = u"Acknowledge Alert Groups"
DEFAULT_LIMIT = 50
ACKNOWLEDGE = "Acknowledge"

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = u"{} - {}".format(INTEGRATION_NAME, SCRIPT_NAME)
    siemplify.LOGGER.info(u"================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"API Root",
                                           is_mandatory=True, input_type=unicode)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Username",
                                           is_mandatory=True, input_type=unicode)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Password",
                                           is_mandatory=True, input_type=unicode)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name=u"Verify SSL",
                                             default_value=False, input_type=bool)

    limit = extract_action_param(siemplify, param_name=u"Limit", is_mandatory=False,
                                          input_type=int, print_value=True, default_value=DEFAULT_LIMIT)

    alert_group_ids = extract_action_param(siemplify, param_name=u"Alert Groups IDs", is_mandatory=True,
                                          input_type=unicode, print_value=True)
    
    acknowledge = extract_action_param(siemplify, param_name=u"Acknowledgment", is_mandatory=True,
                                          input_type=unicode, print_value=True)    

    ack_comment = extract_action_param(siemplify, param_name=u"Acknowledgment Comment", is_mandatory=False,
                                          input_type=unicode, print_value=True)        
    

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    
    output_message = ""
    status = EXECUTION_STATE_COMPLETED
    result_value = True
    acknowledgement = False
    
    if limit < 0:
        siemplify.LOGGER.info(u"Given value for Limit parameter is non-positive, will use default value of {}".format(DEFAULT_LIMIT))
        limit = DEFAULT_LIMIT
    
    try:
        alert_group_ids = "".join(alert_group_ids.split()) #Remove whitespaces
        list_of_alert_ids = alert_group_ids.split(",")
        hx_manager = FireEyeHXManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl)
        
        if acknowledge == ACKNOWLEDGE:
            acknowledgement = True
        
        ack_details = hx_manager.ackowledge_alert_groups(list_of_alert_ids=list_of_alert_ids, ack_comment=ack_comment, acknowledgement=acknowledgement, limit=limit)
        
        if ack_details.total == len(list_of_alert_ids):
             output_message = u"Successfully updated acknowledgement status for all alert groups"
             
        else:
            
            not_acknowledged = list(set(list_of_alert_ids) - set(ack_details.entiries_ids))
            output_message = u"Successfully updated acknowledgement status for the following alert groups {} and couldn't acknowledge the following alert groups {}.".format(  
                ", ".join(ack_details.entiries_ids), ",".join(not_acknowledged))
            
        siemplify.result.add_result_json(ack_details.raw_data)

    except FireEyeHXNotFoundError as e:
        siemplify.LOGGER.error(u"Couldn't fetch alerts for the provided alert group ID. Please check the provided ID and try again.")
        siemplify.LOGGER.exception(e)
        result_value = False
        output_message = u"Couldn't fetch alerts for the provided alert group ID. Please check the provided ID and try again."               

    except Exception as e:
        siemplify.LOGGER.error(u"Failed to execute {} action, error is {}.".format(SCRIPT_NAME, e))
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = u"Failed to execute {} action, error is {}.".format(SCRIPT_NAME, e)
    
    finally:
        try:
            hx_manager.logout()
        except Exception as e:
            siemplify.LOGGER.error(u"Logging out failed. Error: {}".format(e))
            siemplify.LOGGER.exception(e)   
    
    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"Status: {}:".format(status))
    siemplify.LOGGER.info(u"Result Value: {}".format(result_value))
    siemplify.LOGGER.info(u"Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)

if __name__ == "__main__":
    main()
