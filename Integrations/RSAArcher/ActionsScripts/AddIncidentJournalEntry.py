from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from RSAArcherManager import RSAArcherManager, SecurityIncidentDoesntExistError
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from constants import PROVIDER_NAME, ADD_JOURNAL_ENTRY_SCRIPT_NAME

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADD_JOURNAL_ENTRY_SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # Configuration
    server_address = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u"Api Root",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u"Username",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u"Password",
        is_mandatory=True,
        input_type=unicode
    )

    instance_name = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u"Instance Name",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u"Verify SSL",
        is_mandatory=True,
        print_value=True,
        input_type=bool
    )

    # Parameters
    destination_content_id = extract_action_param(
        siemplify,
        param_name=u"Destination Content ID",
        is_mandatory=True,
        print_value=True,
        input_type=unicode,
    )

    text = extract_action_param(
        siemplify,
        param_name=u"Text",
        is_mandatory=True,
        print_value=True,
        input_type=unicode,
    )

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""

    try:
        archer_manager = RSAArcherManager(server_address,
                                          username,
                                          password,
                                          instance_name,
                                          verify_ssl,
                                          siemplify.LOGGER)
        
        application_id = archer_manager.get_incident_journal_app_id()
        request_details = archer_manager.get_security_incident_id(application_id)
        security_incident_level_id = archer_manager.get_security_incident_level()
    
        request_details["security_incident_level_id"] = security_incident_level_id
        
        _result = archer_manager.get_security_incident_details(incident_id=destination_content_id) #check if given content_id exist
        
        result = archer_manager.add_journal_entry(
            destination_content_id=destination_content_id,
            text=text,
            request_details=request_details, 
        )
        
        siemplify.result.add_result_json(result)
        output_message += u"Successfully added new journal entry to the Security Incident {0} in RSA Archer.".format(destination_content_id)       
        
    except SecurityIncidentDoesntExistError as e:
        output_message = u'Error executing action Add Incident Journal Entry. Reason: Security Incident {0} was not found.'.format(destination_content_id)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False            
    
    except Exception as e:
        output_message = u'Error executing action Add Incident Journal Entry. Reason: {0}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  result_value: {}\n  output_message: {}".format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()