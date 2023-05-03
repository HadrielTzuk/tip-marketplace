from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from custom_exceptions import (
    ThreatQManagerException,
    ObjectNotFoundException,
    ObjectCreateException
)
from constants import (
    INTEGRATION_NAME,
    CREATE_EVENT_SCRIPT,
    HAPPENED_AT_DATETIME_DEFAULT_FORMAT
)
from datetime import datetime
from ThreatQUtils import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = CREATE_EVENT_SCRIPT

    siemplify.LOGGER.info('=' * 10 + ' Main - Param Init ' + '=' * 10)

    server_address = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ServerAddress"
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="ClientId"
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Username"
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Password"
    )
    
    event_type = extract_action_param(
        siemplify,
        param_name="Event Type",
        default_value=u"Spearphish",
        is_mandatory=True,
        print_value=True,
    )

    title = extract_action_param(
        siemplify,
        param_name="Title",
        is_mandatory=True,
        print_value=True,
    )
    dateTimeObj = datetime.now()
    happened_at_default = dateTimeObj.strftime(HAPPENED_AT_DATETIME_DEFAULT_FORMAT.encode('utf-8')).decode('utf-8')
    
    happened_at = extract_action_param(
        siemplify,
        param_name="Happened At",
        is_mandatory=False,
        print_value=True,
        default_value=happened_at_default,
    )

    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)
        
    try:
        #Check if happened_at param is in correct format
        validate_time_format(happened_at)
        threatq_manager = ThreatQManager(server_address, client_id, username, password)

        event_object = threatq_manager.create_event(
            event_type=event_type,
            title=title,
            happened_at=happened_at
        )
        
        siemplify.result.add_result_json(event_object.to_json())

        output_message = u'Successfully created new {} event in ThreatQ'.format(event_type)
        result_value = True
        execution_status = EXECUTION_STATE_COMPLETED

    except ObjectCreateException as e:
        output_message = u'Action was not able to create new {} event in ThreatQ.'.format(event_type)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_FAILED
        
    except ValueError as e:
        #Incorrect happent_at param format
        output_message = u'Error executing action \"Create Event\". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_FAILED     
    except (ThreatQManagerException, Exception) as e:
        output_message = u'Error executing action \"Create Event\". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = False
        execution_status = EXECUTION_STATE_FAILED
        
    siemplify.LOGGER.info('=' * 10 + ' Main - Finished ' + '=' * 10)
    siemplify.LOGGER.info(
        u'Status: {}, Result Value: {}, Output Message: {}'
        .format(execution_status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, execution_status)


if __name__ == '__main__':
    main()
