# coding=utf-8
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon import extract_configuration_param, extract_action_param
from SymantecATPManager import SymantecATPManager, SymantecATPTokenPermissionError, SymantecATPIncidentNotFoundError
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler

# =====================================
#             CONSTANTS               #
# =====================================
SCRIPT_NAME = u'SymantecATP_Update Incident Resolution'
INTEGRATION_NAME = u"SymantecATP"

#Resolution Types
RESOLUTION_TYPES = {
    "INSUFFICIENT DATA":0, 
    "SECURITY RISK":1, 
    "FALSE POSITIVE":2, 
    "MANAGED EXTERNALLY":3, 
    "NOT SET":4, 
    "BENIGN":5, 
    "TEST":6
}

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    output_message = u""
    is_success = u"true"
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

    # Action Parameters
    incident_uuid = extract_action_param(siemplify, param_name=u"Incident UUID", is_mandatory=True)
    identifier_type = extract_action_param(siemplify, param_name=u"Resolution Status", is_mandatory=True, default_value=u"INSUFFICIENT DATA", input_type=unicode, print_value=True)
    
    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    try:
        atp_manager = SymantecATPManager(api_root, client_id, client_secret, verify_ssl) 
        resolution_status = RESOLUTION_TYPES.get(identifier_type)

        atp_manager.update_incident_resolution(incident_uuid, resolution_status)
        output_message = u"Successfully updated resolution on the Symantec ATP incident with UUID {}".format(incident_uuid)

    except SymantecATPIncidentNotFoundError as e:
        is_success = u"false"
        output_message = u"Symantec ATP Incident with UUID {0} was not found.".format(incident_uuid)
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
        output_message = u"Error executing action Update Incident Resolution. Reason: {0}".format(e)
        is_success = u"false"

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(u"\n  status: {}\n  is_success: {}\n  output_message: {}".format(status, is_success, output_message))
    siemplify.end(output_message, is_success, status)
    
if __name__ == "__main__":
    main()