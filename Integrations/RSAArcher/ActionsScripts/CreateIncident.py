from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from RSAArcherManager import RSAArcherManager, InvalidArgumentsError, NotFoundApplicationError, DEFAULT_APP_NAME
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
import json

PROVIDER_NAME = u"RSAArcher"
SCRIPT_NAME = u'RSAArcher - CreateIncident'

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info(u"----------------- Main - Param Init -----------------")

    # Configuration
    server_address = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Api Root",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Username",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Password",
        is_mandatory=True,
        input_type=unicode
    )

    instance_name = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Instance Name",
        is_mandatory=True,
        print_value=True,
        input_type=unicode
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name="Verify SSL",
        is_mandatory=True,
        print_value=True,
        input_type=bool
    )

    # Parameters
    title = extract_action_param(
        siemplify,
        param_name="Incident Summary",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    description = extract_action_param(
        siemplify,
        param_name="Incident Details",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    owner = extract_action_param(
        siemplify,
        param_name="Incident Owner",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    status = extract_action_param(
        siemplify,
        param_name="Incident Status",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    priority = extract_action_param(
        siemplify,
        param_name="Priority",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    category = extract_action_param(
        siemplify,
        param_name="Category",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    custom_fields = extract_action_param(
        siemplify,
        param_name="Custom Fields",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    application_name = extract_action_param(
        siemplify,
        param_name="Application Name",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
        default_value=DEFAULT_APP_NAME
    )

    mapping_file = extract_action_param(
        siemplify,
        param_name="Custom Mapping File",
        is_mandatory=False,
        print_value=True,
        input_type=unicode,
    )

    remote_file = extract_action_param(
        siemplify,
        param_name='Remote File',
        is_mandatory=False,
        input_type=bool,
        print_value=True)

    siemplify.LOGGER.info(u"----------------- Main - Started -----------------")
    result_value = None
    result_status = EXECUTION_STATE_FAILED

    try:
        archer_manager = RSAArcherManager(server_address,
                                          username,
                                          password,
                                          instance_name,
                                          verify_ssl,
                                          siemplify.LOGGER,
                                          siemplify)

        custom_fields_dict = json.loads(custom_fields) if custom_fields else {}

        content_id, alias = archer_manager.create_incident(
            title=title,
            description=description,
            owner=owner,
            status=status,
            priority=priority,
            category=category,
            custom_fields=custom_fields_dict,
            app_name=application_name,
            map_file_path=mapping_file,
            remote_file=remote_file
        )
        incident_details = archer_manager.get_incident_by_id(incident_id=content_id, alias=alias, check_content=False)
        siemplify.result.add_result_json(incident_details.to_json())
        output_message = u"Successfully created incident. Content ID: {}".format(content_id)
        result_value = content_id
        result_status = EXECUTION_STATE_COMPLETED

    except NotFoundApplicationError as e:
        output_message = unicode(e)
        siemplify.LOGGER.error(output_message)

    except InvalidArgumentsError as e:
        output_message = u"Action wasn't able to create a new incident. Reason: {0}".format(e)
        siemplify.LOGGER.error(output_message)

    except Exception as e:
        output_message = u'Error executing action Create Incident. Reason: {0}'.format(e)
        siemplify.LOGGER.error(u"Error executing action {}".format(SCRIPT_NAME))
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u"----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        u"\n  status: {}\n  content_ID: {}\n  output_message: {}".format(result_status, result_value, output_message))
    siemplify.end(output_message, result_value, result_status)


if __name__ == '__main__':
    main()
