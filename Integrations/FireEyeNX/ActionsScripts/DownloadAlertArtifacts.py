from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from FireEyeNXManager import FireEyeNXManager
from urllib.parse import urljoin
from FireEyeNXExceptions import ArtifactsNotFoundException
from FireEyeNXConstants import (
    PROVIDER_NAME,
    DOWNLOAD_ALERT_ARTIFACTS_SCRIPT_NAME
)


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = DOWNLOAD_ALERT_ARTIFACTS_SCRIPT_NAME
    siemplify.LOGGER.info('=' * 20 + ' Main - Params Init ' + '=' * 20)

    # Configuration
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
        print_value=False
    )

    password = extract_configuration_param(
        siemplify,
        provider_name=PROVIDER_NAME,
        param_name='Password',
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
    alert_uuid = extract_action_param(siemplify, param_name='Alert UUID', is_mandatory=True, print_value=True)
    download_path = extract_action_param(siemplify, param_name='Download Path', is_mandatory=True, print_value=True)

    siemplify.LOGGER.info('=' * 20 + ' Main - Started ' + '=' * 20)
    result = False
    status = EXECUTION_STATE_COMPLETED

    try:
        manager = FireEyeNXManager(
            api_root=api_root,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            siemplify=siemplify
        )

        response = manager.download_alert_artifacts(alert_uuid)
        absolute_path = urljoin(download_path, '{}.zip'.format(alert_uuid))
        if manager.save_artifacts_to_file(response, absolute_path):
            output_message = 'Successfully downloaded FireEye NX alert artifacts with alert id {}'.format(alert_uuid)
            siemplify.result.add_result_json({'file_path': absolute_path})
            result = True
        else:
            output_message = 'Action wasn’t able to download FireEye NX alert artifacts with alert id {}. Reason: ' \
                             'File with that path already exists.'.format(alert_uuid)

    except ArtifactsNotFoundException:
        output_message = 'Artifacts for alert with uuid {} were not found.'.format(alert_uuid)
        siemplify.LOGGER.error(output_message)

    except Exception as e:
        output_message = 'Error executing action \"Download Alert Artifacts\". Reason: {}'.format(e)
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info('=' * 20 + ' Main - Finished ' + '=' * 20)
    siemplify.LOGGER.info('Status: {}'.format(status))
    siemplify.LOGGER.info('Result: {}'.format(result))
    siemplify.LOGGER.info('Output Message: {}'.format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == '__main__':
    main()
