from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from custom_exceptions import (
    InvalidFieldException
)
from constants import (
    INTEGRATION_NAME,
    LIST_EVENTS_SCRIPT,
    ADDITIONAL_FIELDS_LIST
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_EVENTS_SCRIPT

    siemplify.LOGGER.info('=' * 10 + ' Main - Param Init ' + '=' * 10)

    server_address = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ServerAddress",
        input_type=unicode
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ClientId",
        input_type=unicode
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Username",
        input_type=unicode
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Password",
        input_type=unicode
    )

    additional_fields = extract_action_param(
        siemplify,
        param_name='Additional Fields',
        input_type=unicode,
        is_mandatory=False,

    )

    sort_field = extract_action_param(
        siemplify,
        param_name="Sort Field",
        input_type=unicode,
        is_mandatory=False,
        print_value=True,
    )

    sort_direction = extract_action_param(
        siemplify,
        param_name="Sort Direction",
        input_type=unicode,
        is_mandatory=False,
        print_value=True,
    )

    limit = extract_action_param(
        siemplify,
        param_name="Max Events To Return",
        input_type=int,
        is_mandatory=False,
        print_value=True,
    )

    if limit < 1:
        limit = 50

    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)
    execution_status = EXECUTION_STATE_COMPLETED
    result_value = False

    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)

        if additional_fields:
            additional_fields_to_list = [t.strip() for t in additional_fields.split(u',') if t.strip()]
            for field in additional_fields_to_list:
                if field not in ADDITIONAL_FIELDS_LIST:
                    raise InvalidFieldException

        results = threatq_manager.list_events(
            sort_field=sort_field,
            sort_direction=sort_direction,
            additional_fields=additional_fields,
            limit=limit
        )

        if results:
            siemplify.result.add_result_json([event.to_json() for event in results])
            siemplify.result.add_data_table(
                title=u'ThreatQ Events',
                data_table=construct_csv([event.to_table() for event in results])
            )
            output_message = u'Successfully listed ThreatQ events.'
            result_value = True
        else:
            output_message = u'No events were found in ThreatQ.'

    except InvalidFieldException as e:
        output_message = u'Error executing action \"List Events\". Reason: Invalid field was specified in ' \
                         u'the \'Additional Fields\' parameter.'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        execution_status = EXECUTION_STATE_FAILED

    except Exception as e:
        output_message = u'Error executing action \"List Events\". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        execution_status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info('=' * 10 + ' Main - Finished ' + '=' * 10)
    siemplify.LOGGER.info(
        u'Status: {}, Result Value: {}, Output Message: {}'
        .format(execution_status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, execution_status)


if __name__ == '__main__':
    main()