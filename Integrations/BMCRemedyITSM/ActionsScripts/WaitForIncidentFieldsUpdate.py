import json
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_INPROGRESS
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param
from BMCRemedyITSMManager import BMCRemedyITSMManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, WAIT_FOR_INCIDENT_FIELDS_UPDATE_SCRIPT_NAME, \
    STATUS_MAPPING
from BMCRemedyITSMExceptions import BMCRemedyITSMNotFoundException, BMCRemedyITSMTimeoutException
from UtilsManager import is_async_action_timeout


def check_incident_fields(incident, fields_to_check_dict):
    """
    Check incident fields
    :param incident: {Incident} Incident object
    :param fields_to_check_dict: {dict} dictionary containing needed fields and values
    :return: {tuple} updated_fields, not_updated_fields
    """
    updated_fields = []
    not_updated_fields = []
    not_found_fields = []

    for key, value in fields_to_check_dict.items():
        try:
            incident.raw_data[key]
        except KeyError:
            not_found_fields.append(key)

        if incident.raw_data.get(key, "") == value:
            updated_fields.append(key)
        else:
            not_updated_fields.append(key)

    if not_found_fields:
        raise Exception(f"the following fields were not found in the structure of the incident: "
                        f"{','.join(not_found_fields)}.")

    return updated_fields, not_updated_fields


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = WAIT_FOR_INCIDENT_FIELDS_UPDATE_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True, print_value=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # action parameters
    incident_id = extract_action_param(siemplify, param_name="Incident ID", is_mandatory=True, print_value=True)
    incident_status = extract_action_param(siemplify, param_name="Status", print_value=True)
    fields_to_check = extract_action_param(siemplify, param_name="Fields To Check", print_value=True)
    fail_if_timeout = extract_action_param(siemplify, param_name="Fail If Timeout", input_type=bool, is_mandatory=True,
                                           print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    result = True
    status = EXECUTION_STATE_COMPLETED
    manager = None
    output_message = ""

    try:
        # check if async action timeout approaching
        if is_async_action_timeout(siemplify):
            additional_data = json.loads(extract_action_param(siemplify=siemplify, param_name="additional_data",
                                                              default_value="[]"))
            if not fail_if_timeout:
                raise BMCRemedyITSMTimeoutException(f"The following fields were not updated for incident with ID "
                                                    f"{incident_id} in {INTEGRATION_DISPLAY_NAME}: "
                                                    f"{','.join(additional_data)}")

            raise Exception(f"The following fields were not updated for incident with ID {incident_id} in "
                            f"{INTEGRATION_DISPLAY_NAME}: {','.join(additional_data)}")

        try:
            fields_to_check_dict = json.loads(fields_to_check) if fields_to_check else {}
        except Exception:
            raise Exception("Invalid JSON payload provided in the parameter \"Fields To Check\". Please check the "
                            "structure.")

        if not STATUS_MAPPING.get(incident_status) and not fields_to_check_dict:
            raise Exception("\"Status\" or \"Fields To Check\" parameter should have a value.")

        if not fields_to_check_dict.get("Status") and incident_status:
            fields_to_check_dict["Status"] = incident_status

        manager = BMCRemedyITSMManager(api_root=api_root, username=username, password=password, verify_ssl=verify_ssl,
                                       siemplify_logger=siemplify.LOGGER)

        incidents = manager.get_incident_details(incident_id)
        incident = incidents[0] if incidents else None

        if not incident:
            raise BMCRemedyITSMNotFoundException(f"incident with ID {incident_id} was not found")

        updated_fields, not_updated_fields = check_incident_fields(incident, fields_to_check_dict)

        if len(updated_fields) == len(fields_to_check_dict.keys()):
            siemplify.result.add_result_json(incident.to_json())
            result = True
            status = EXECUTION_STATE_COMPLETED
            output_message = f"Incident with ID {incident_id} was updated in {INTEGRATION_DISPLAY_NAME}."
        else:
            result = json.dumps(not_updated_fields)
            status = EXECUTION_STATE_INPROGRESS
            output_message = f"Waiting for the following fields to be updated for incident with ID {incident_id} in " \
                             f"{INTEGRATION_DISPLAY_NAME}: {','.join(not_updated_fields)}"

    except BMCRemedyITSMTimeoutException as e:
        result = False
        status = EXECUTION_STATE_COMPLETED
        output_message = str(e)
    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {WAIT_FOR_INCIDENT_FIELDS_UPDATE_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action {WAIT_FOR_INCIDENT_FIELDS_UPDATE_SCRIPT_NAME}. Reason: {e}"

    finally:
        try:
            if manager:
                siemplify.LOGGER.info(f"Logging out from {INTEGRATION_DISPLAY_NAME}..")
                manager.logout()
                siemplify.LOGGER.info(f"Successfully logged out from {INTEGRATION_DISPLAY_NAME}")
        except Exception as error:
            siemplify.LOGGER.error(f"Logging out failed. Error: {error}")
            siemplify.LOGGER.exception(error)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
