from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_INPROGRESS
import requests
import os
import json
import base64
import arrow
from EncryptionManager import AESManager, RSAManager
import time
import sys
from urlparse import urlparse

SDK_PATH = os.path.dirname(os.path.realpath(__file__))
MANAGERS_PATH = "Managers"
DEPENDENCIES_PATH = "Dependencies"
COMPLETED = 'COMPLETED'
ASYNC_PENDING = 'ASYNC_PENDING'
COMPLETION_STATUSES = ['COMPLETED', 'FAILED', 'ASYNC_PENDING']
COMPLETED_SUCCESSFULLY_STATUSES = [COMPLETED, ASYNC_PENDING]
ACTION_TYPE = "RUN_ACTION"
INDEX = "smp_python-{}"
PYTHON_LOG_TYPE = "python_log"


def validate_response(response, error_msg="An error occurred"):
    try:
        response.raise_for_status()

    except requests.HTTPError as error:
        raise Exception(
            "{error_msg}: {error} - {text}".format(
                error_msg=error_msg,
                error=error,
                text=error.response.content)
        )


@output_handler
def main():
    siemplify = SiemplifyAction()
    agent_details = None
    agent_id = siemplify.parameters['Agent Id']
    if "get_agent_by_id" in dir(siemplify):  #Valid method for 5.5.3-hf-8 & 5.6.0-hf-2 and higher versions
        agent_details = siemplify.get_agent_by_id(agent_id)
    publisher_id = siemplify.parameters['Publisher Id']
    publisher_details = siemplify.get_publisher_by_id(publisher_id)
    publisher_api_root = publisher_details["server_api_root"]
    api_token = publisher_details["api_token"]
    if agent_details:
        cert_file_content = agent_details["certificate"]
    else:
        cert_file_content = publisher_details["certificate"]
    integration_identifier = siemplify.parameters['Remote Integration Name']
    action_identifier = siemplify.parameters['Remote Action Name']
    installed_integrations_shared_folder = siemplify.parameters.get('Installed Integrations Shared Folder',
                                                                    'D:\SiemplifyIntegrations')
    context_data = siemplify.parameters['Remote Context Data']
    is_first_execution = siemplify.parameters['First Execution']
    action_script = siemplify.parameters['Remote Action Script']
    environment = siemplify.parameters["Environment"]
    is_test_action = str(siemplify.parameters.get("IsIntegrationTestAction")).lower() == str(True).lower()
    verify_ssl = str(siemplify.parameters.get("Verify SSL")).lower() == str(True).lower()
    integration_conf = siemplify.get_configuration(integration_identifier)
    managers = siemplify.parameters.get("Remote Integration Managers")
    # fetch latest integration version installed on the platform,
    integration_version = siemplify.get_integration_version(integration_identifier)
    case_data = siemplify._get_case() if not is_test_action else {}

    # Set script name according to the original integration
    siemplify.script_name = "RunRemote-{}".format(action_identifier)

    siemplify.LOGGER.info(
        "=========== Starting Remote Running of {} , Agent: {}============".format(action_identifier, agent_id))

    # Encryption
    aes_manager = AESManager()
    rsa_manager = RSAManager(public_key=cert_file_content)

    publisher_session = requests.Session()
    publisher_session.verify = verify_ssl

    siemplify.LOGGER.info("Constructing remote task package.")

    encrypted_symmetric_key = rsa_manager.encrypt(aes_manager.key)

    siemplify.LOGGER.info("Collecting managers.")

    if not os.path.exists(installed_integrations_shared_folder):
        raise Exception("Folder {0} NOT found.".format(installed_integrations_shared_folder))

    managers_data = json.loads(managers)
    encoded_managers = {}

    for manager in managers_data:
        try:
            encoded_managers[manager] = base64.b64encode(managers_data[manager])
        except UnicodeEncodeError:
            encoded_managers[manager] = base64.b64encode(managers_data[manager].encode("utf8"))

    siemplify.LOGGER.info("Collecting dependencies.")
    dependencies = {}

    dependencies_folder = os.path.join(
        *[installed_integrations_shared_folder, integration_identifier, DEPENDENCIES_PATH])

    if os.path.exists(dependencies_folder):
        sub_folders = [folder_name for folder_name in os.listdir(dependencies_folder) if
                       os.path.isdir(os.path.join(dependencies_folder, folder_name))]

        if sub_folders:
            for os_name in sub_folders:
                dependencies[os_name] = []
                for dependency in os.listdir(os.path.join(dependencies_folder, os_name)):
                    dependencies[os_name].append(dependency)

        else:
            # For backwards compatibility - if no folders by os, add them all
            # as cross dependencies
            dependencies["win64"] = []
            for dependency in os.listdir(dependencies_folder):
                dependencies["win64"].append(dependency)

    try:
        action_script = base64.b64encode(action_script)
    except UnicodeEncodeError:
        action_script = base64.b64encode(action_script.encode("utf8"))

    publisher_session.headers.update({"Authorization": "Token {}".format(api_token)})

    payload = {
        'data': aes_manager.encrypt(data=json.dumps(
            {
                'managers_data': encoded_managers,
                "action_data": action_script,
                "context_data": context_data,
                'environment_id': environment,
                'action_identifier': action_identifier,
                'integration_identifier': integration_identifier,
                'integration_conf': integration_conf,
                'case_data': case_data,
                'dependencies': dependencies,
                'integration_version': integration_version,
                'is_first_execution': is_first_execution
            })),
        'key': encrypted_symmetric_key,
        "type": ACTION_TYPE,
        'agent': agent_id

    }

    siemplify.LOGGER.info("Sending remote task package.")

    response = publisher_session.post(
        "{}/api/tasks/".format(publisher_api_root),
        json=payload
    )

    validate_response(response, "Unable to create remote task")

    task_id = response.json()['id']

    siemplify.LOGGER.info("Waiting for remote task {} to complete.".format(task_id))
    # Wait for task to complete
    while response.json()['status'] not in COMPLETION_STATUSES:
        time.sleep(1)
        response = publisher_session.get(r"{}/api/tasks/{}/".format(publisher_api_root, task_id))
        validate_response(response, "Unable to get status for task {}".format(task_id))

    siemplify.LOGGER.info("Remote task {} has finished.".format(task_id))

    siemplify.LOGGER.info("Decrypting results for task {}".format(task_id))
    results = response.json().get('results')
    if results:
        results = json.loads(aes_manager.decrypt(results))
    else:
        raise Exception("No Results were found on publisher")

    result_message = results.get('message', "")
    result_value = results.get('result_value', 0)
    current_status = response.json()['status']
    task_failed = False
    output_object = None

    if current_status in COMPLETED_SUCCESSFULLY_STATUSES:
        # Task is successful, might be async as well

        # Execute REST actions that were logged in the remote client
        rest_calls = results.get('rest_calls', [])
        siemplify.LOGGER.info("Task {} finished successfully. Performing REST calls.".format(task_id))
        siemplify.LOGGER.info("Task {} Found {} rest calls".format(task_id, len(rest_calls)))

        local_sdk_url = urlparse(siemplify.sdk_config.api_root_uri)
        for rest_action in rest_calls:
            for url, call_data in rest_action.items():
                url_data = urlparse(url)
                updated_url = url_data._replace(scheme=local_sdk_url.scheme, netloc=local_sdk_url.netloc)
                r = siemplify.session.post(updated_url.geturl(), json=call_data)
                siemplify.validate_siemplify_error(r)

        script_results = json.loads(results.get('script_results', "{}"))
        output_object = json.loads(script_results.get("ResultObjectJson", "{}"))
        debug_output = results.get('script_results', "{}")
        siemplify.LOGGER.info("Task {} has succeeded. Action Output: \n".format(task_id))
        sys.stdout.write(unicode(script_results['DebugOutput'] + " \n ").encode("utf-8"))


        # Delete the task
        siemplify.LOGGER.info("Deleting task {}".format(task_id))
        response = publisher_session.delete(
            r"{}/api/tasks/{}/".format(publisher_api_root, task_id)
        )
        validate_response(response,
                          "Unable to delete task {}".format(task_id))

        script_exit_status = EXECUTION_STATE_COMPLETED if current_status == COMPLETED else EXECUTION_STATE_INPROGRESS

    else:
        # Task has failed - write the error to stderr and
        # exit with status code 1
        error_message = results.get('DebugOutput', "")
        siemplify.LOGGER.info("Task {} has failed with error message: {}".format(task_id, error_message.encode("utf-8")))
        sys.stderr.write(unicode(error_message).encode("utf-8"))

        # Delete the task
        siemplify.LOGGER.info("Deleting task {}".format(task_id))
        response = publisher_session.delete(
            r"{}/api/tasks/{}/".format(publisher_api_root, task_id)
        )
        validate_response(response,
                          "Unable to delete task {}".format(task_id))
        task_failed = True

    output_message = "=========== End Remote Running of {} , Agent: {}============".format(action_identifier, agent_id)
    siemplify.LOGGER.info(output_message)

    if not task_failed:
        if output_object:
            siemplify.result._result_object = output_object
        siemplify.end(result_message, result_value, script_exit_status)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
