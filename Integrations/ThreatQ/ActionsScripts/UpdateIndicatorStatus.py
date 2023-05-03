from SiemplifyUtils import output_handler, convert_dict_to_json_result_dict
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED

from ThreatQManager import ThreatQManager
from constants import (
    INTEGRATION_NAME,
    UPDATE_INDICATOR_STATUS,
    HAPPENED_AT_DATETIME_DEFAULT_FORMAT
)
from datetime import datetime
from ThreatQUtils import *

@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = UPDATE_INDICATOR_STATUS
    # Variables Definitions.
    result_value = u"true"
    execution_status = EXECUTION_STATE_COMPLETED
    output_message = u""
        
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
    
    status = extract_action_param(
        siemplify,
        param_name="Status",
        default_value=u"Active",
        is_mandatory=True,
        print_value=True,
    )
    
    siemplify.LOGGER.info('=' * 10 + ' Main - Started ' + '=' * 10)
    updated_entities = []
    failed_entities = []
    json_results = {}
    
    try:
        threatq_manager = ThreatQManager(server_address, client_id, username, password)
        
        for entity in siemplify.target_entities:
            
            try:
                indicator_obj = threatq_manager.update_indicator_status(entity.identifier, status)
                updated_entities.append(entity)
                json_results[entity.identifier] = indicator_obj.to_json()
                siemplify.LOGGER.info(u"Finished processing entity:{}".format(entity.identifier))

            except Exception as e:
                output_message += u"Unable to get indicators for {} \n".format(entity.identifier)
                failed_entities.append(entity)
                siemplify.LOGGER.error(u"Failed processing entity:{}".format(entity.identifier))
                siemplify.LOGGER.exception(e)
  
        if updated_entities:
            siemplify.result.add_result_json(convert_dict_to_json_result_dict(json_results))

            output_message = u"Successfully updated status for the indicator with value: {0} in ThreatQ.".format(u", ".join([entity.identifier for entity in
                                                                             updated_entities]))
            result_value = u"true"

        else:
            output_message = u"No data found for entities."
            result_value = u"false"

        if failed_entities:
            output_message += u"\nAction was not able to update status for the indicator with value: {0} in ThreatQ.".format(
                u"\n".join([entity.identifier for entity in
                            failed_entities]))
        
    except Exception as e:
        output_message = u'Error executing action \"Update Indicator Status\". Reason: {}'.format(e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        result_value = u"false"
        execution_status = EXECUTION_STATE_FAILED
        
    siemplify.LOGGER.info('=' * 10 + ' Main - Finished ' + '=' * 10)
    siemplify.LOGGER.info(
        u'Status: {}, Result Value: {}, Output Message: {}'
        .format(execution_status, result_value, output_message)
    )
    siemplify.end(output_message, result_value, execution_status)


if __name__ == '__main__':
    main()