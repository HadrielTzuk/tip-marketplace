from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param

from ObserveITManager import ObserveITManager
from ObserveITConstants import (
    PROVIDER_NAME,
    PING_SCRIPT_NAME
)
from ObserveITExceptions import (
    ObserveITException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    siemplify.LOGGER.info(u'=' * 20 + u' Main - Params Init ' + u'=' * 20)

    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u'API Root',
        input_type=unicode,
        is_mandatory=True,
        print_value=True
    )

    client_id = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u'Client ID',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    client_secret = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u'Client Secret',
        input_type=unicode,
        is_mandatory=True,
        print_value=False
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name=u'Verify SSL',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    siemplify.LOGGER.info(u'=' * 20 + u' Main - Started ' + u'=' * 20)

    try:
        manager = ObserveITManager(
            api_root=api_root,
            client_id=client_id,
            client_secret=client_secret,
            verify_ssl=verify_ssl
        )

        manager.test_connectivity()

        output_message = u'Successfully connected to the ObserveIT server with the provided connection parameters!'
        result = u'true'
        status = EXECUTION_STATE_COMPLETED

    except ObserveITException as e:
        output_message = u'Failed to connect to the ObserveIT server! Error is {}'.format(e)
        result = u'false'
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info(u'=' * 20 + u' Main - Finished ' + u'=' * 20)
    siemplify.LOGGER.info(u'Status: {}'.format(status))
    siemplify.LOGGER.info(u'Result: {}'.format(result))
    siemplify.LOGGER.info(u'Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
