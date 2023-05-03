from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from IBossManager import IBossManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param
from constants import URL_RECATEGORIZATION_SCRIPT_NAME, INTEGRATION_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = URL_RECATEGORIZATION_SCRIPT_NAME
    siemplify.LOGGER.info('----------------- Main - Param Init -----------------')

    # Configuration
    cloud_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Cloud API Root',
                                           is_mandatory=True)
    account_api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Account API Root',
                                           is_mandatory=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Username',
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Password',
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name='Verify SSL',
                                             default_value=True, input_type=bool)

    siemplify.LOGGER.info('----------------- Main - Started -----------------')

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ''
    submitted_entities = []
    failed_entities = []
    suitable_entities = [entity for entity in siemplify.target_entities if entity.entity_type == EntityTypes.URL]

    try:
        manager = IBossManager(cloud_api_root, account_api_root, username, password, verify_ssl, siemplify.LOGGER)

        for entity in suitable_entities:
            try:
                siemplify.LOGGER.info('\n\nStarted processing entity: {}'.format(entity.identifier))

                manager.url_recategorization(entity.identifier)
                submitted_entities.append(entity.identifier)
                siemplify.LOGGER.info('Successfully submitted the following URL: \n {}'.format(entity.identifier))
            except Exception as e:
                failed_entities.append(entity.identifier)
                siemplify.LOGGER.error(
                    'Action was not able to submit the following URL:  \n {}'.format(entity.identifier))
                siemplify.LOGGER.exception(e)

            siemplify.LOGGER.info('Finished processing entity: {}'.format(entity.identifier))

        if failed_entities:
            output_message += 'Action was not able to submit the following URLs for recategorization: \n {}'.format(
                '\n'.join(failed_entities))

        if submitted_entities:
            output_message += '\n Successfully submitted the following URLs for recategorization: \n {}'.format(
                '\n'.join(submitted_entities))
        else:
            output_message = 'No URLs were submitted for recategorization.'
            siemplify.LOGGER.info(output_message)
            result_value = False

    except Exception as e:
        output_message = "Error executing action '{}'. Reason: {}".format(URL_RECATEGORIZATION_SCRIPT_NAME, e)
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    siemplify.LOGGER.info('----------------- Main - Finished -----------------')
    siemplify.LOGGER.info(
        '\n  status: {}\n  result_value: {}\n  output_message: {}'.format(status, result_value, output_message))
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
