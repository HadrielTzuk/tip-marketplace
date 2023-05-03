from TIPCommon import extract_configuration_param

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from LastlineManager import LastlineManager
from consts import INTEGRATION_NAME, PING
from exceptions import LastlineAuthenticationException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "{} - {}".format(INTEGRATION_NAME, PING)
    siemplify.LOGGER.info("================= Main - Param Init =================")

    api_root = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Api Root',
        is_mandatory=True,
        print_value=True
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Username',
        is_mandatory=True,
        print_value=True
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Password',
        is_mandatory=True,
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name='Verify SSL',
        input_type=bool,
        default_value=True,
        is_mandatory=False,
        print_value=True
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    try:
        manager = LastlineManager(api_root=api_root,
                                  username=username,
                                  password=password,
                                  verify_ssl=verify_ssl)

        siemplify.LOGGER.info(f"Connecting to {INTEGRATION_NAME}")
        manager.test_connectivity()
        output_message = f"Successfully connected to the {INTEGRATION_NAME} service with the provided connection " \
                         f"parameters!"

        result_value = True
        status = EXECUTION_STATE_COMPLETED

    except LastlineAuthenticationException as error:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to connect to the {INTEGRATION_NAME} service with the provided account. Please " \
                         f"check your configuration. Error is: {error}"
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    except Exception as error:
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f'Failed to connect to the {INTEGRATION_NAME} server! Error is: {error}'
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}:")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
