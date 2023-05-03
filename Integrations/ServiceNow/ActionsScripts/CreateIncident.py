from ServiceNowManager import ServiceNowManager, DEFAULT_TABLE
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import INTEGRATION_NAME, CREATE_INCIDENT_SCRIPT_NAME
from UtilsManager import separate_key_value_pairs_from_string
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from exceptions import ServiceNowNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_INCIDENT_SCRIPT_NAME

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           print_value=False)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           print_value=False)

    default_incident_table = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                         param_name="Incident Table", print_value=True,
                                                         default_value=DEFAULT_TABLE)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    client_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Client ID",
                                            print_value=False)
    client_secret = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Client Secret", print_value=False)
    refresh_token = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                param_name="Refresh Token", print_value=False)
    use_oauth = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                            param_name="Use Oauth Authentication", default_value=False,
                                            input_type=bool)

    short_description = extract_action_param(siemplify, param_name="Short Description", print_value=True,
                                             is_mandatory=True)
    impact = extract_action_param(siemplify, param_name="Impact", print_value=True, is_mandatory=True)
    urgency = extract_action_param(siemplify, param_name="Urgency", print_value=True, is_mandatory=True)
    category = extract_action_param(siemplify, param_name="Category", print_value=True)
    assignment_group = extract_action_param(siemplify, param_name="Assignment group ID", print_value=True)
    assigned_to = extract_action_param(siemplify, param_name="Assigned User ID", print_value=True)
    description = extract_action_param(siemplify, param_name="Description", print_value=True)
    custom_fields_str = extract_action_param(siemplify, param_name="Custom Fields", print_value=True)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        try:
            custom_fields_dict = separate_key_value_pairs_from_string(custom_fields_str)
        except Exception:
            raise Exception("Invalid value was found in the 'Custom Fields' parameter. Please check the format.")

        service_now_manager = ServiceNowManager(api_root=api_root, username=username, password=password,
                                                default_incident_table=default_incident_table, verify_ssl=verify_ssl,
                                                siemplify_logger=siemplify.LOGGER, client_id=client_id,
                                                client_secret=client_secret, refresh_token=refresh_token,
                                                use_oauth=use_oauth)

        incident, not_used_custom_fields = service_now_manager.create_ticket(short_description=short_description,
                                                                             impact=impact, urgency=urgency,
                                                                             category=category,
                                                                             assignment_group=assignment_group,
                                                                             assigned_to=assigned_to,
                                                                             description=description,
                                                                             custom_fields=custom_fields_dict)
        if incident.is_empty():
            output_message = "Failed to create ServiceNow incident."

        else:
            output_message = "Successfully created incident with number {}.".format(incident.number)
            result_value = incident.number
            if not_used_custom_fields:
                output_message += "The following fields were not processed, when creating an incident: {}" \
                    .format(', '.join(not_used_custom_fields))
            siemplify.result.add_result_json(incident.to_json())

    except ServiceNowNotFoundException as e:
        output_message = str(e)
        result_value = False
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
    except Exception as e:
        output_message = "General error performing action {}. Reason: {}".format(CREATE_INCIDENT_SCRIPT_NAME, e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info('\n  status: {}\n  result_value: {}\n  output_message: {}'
                          .format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
