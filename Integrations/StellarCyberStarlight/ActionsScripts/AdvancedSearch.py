from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from StellarCyberStarlightConstants import PROVIDER_NAME, ADVANCED_SEARCH_SCRIPT_NAME, DEFAULT_LIMIT, DESCENDING_SORT
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from StellarCyberStarlightManager import StellarCyberStarlightManager
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from StellarCyberStarlightExceptions import (
    SearchExecutionException
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ADVANCED_SEARCH_SCRIPT_NAME

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Configurations
    api_root = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Root',
        is_mandatory=True,
        print_value=True
    )

    username = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='Username',
        is_mandatory=True,
        print_value=True
    )

    api_key = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='API Key',
        is_mandatory=True,
        print_value=False
    )

    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='Verify SSL',
        input_type=bool,
        is_mandatory=True,
        print_value=True
    )

    # Parameters
    index = extract_action_param(siemplify, param_name='Index', is_mandatory=True, print_value=True)
    dsl_query = extract_action_param(siemplify, param_name='DSL Query', is_mandatory=True, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result_value = False
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = StellarCyberStarlightManager(
            api_root=api_root,
            username=username,
            api_key=api_key,
            verify_ssl=verify_ssl
        )

        hits = manager.make_advanced_search(index=index,
                                            dsl_query=dsl_query)

        output_message = "Successfully executed search in Stellar Cyber Starlight."
        siemplify.result.add_result_json([hit.to_json() for hit in hits])
        result_value = True

    except SearchExecutionException as e:
        output_message = "Action wasn't able to execute search in Stellar Cyber Starlight. Reasons: {}".format(e)

    except Exception as e:
        output_message = "Error executing action \"Advanced Search\". Reason: {}".format(e)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result_value))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()

