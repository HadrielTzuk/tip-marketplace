from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from GoogleSecurityCommandCenterManager import GoogleSecurityCommandCenterManager
from constants import INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIST_ASSET_VULNERABILITIES_SCRIPT_NAME, \
    DEFAULT_RECORDS_LIMIT, ONLY_DATA, ONLY_STATISTICS, ONLY_VULNERABILTIES, ONLY_MISCONFIGURATIONS, \
    VULNERABILITY_CLASS, STATISTICS_DICT
from UtilsManager import convert_comma_separated_to_list, convert_list_to_comma_string, get_timestamp_from_range
from GoogleSecurityCommandCenterExceptions import GoogleSecurityCommandCenterInvalidJsonException, \
    GoogleSecurityCommandCenterInvalidProject
from collections import Counter
import copy


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = LIST_ASSET_VULNERABILITIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Root",
                                           is_mandatory=True, print_value=True)
    organization_id = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                  param_name="Organization ID", print_value=True)
    service_account_string = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME,
                                                         param_name="User's Service Account", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    # Action parameters
    resource_names = extract_action_param(siemplify, param_name="Asset Resource Names", is_mandatory=True,
                                          print_value=True)
    timeframe = extract_action_param(siemplify, param_name="Timeframe", is_mandatory=False, print_value=True)
    record_types = extract_action_param(siemplify, param_name="Record Types", is_mandatory=False, print_value=True)
    output_type = extract_action_param(siemplify, param_name="Output Type", is_mandatory=False, print_value=True)
    limit = extract_action_param(siemplify, param_name="Max Records To Return", is_mandatory=False, print_value=True,
                                 default_value=DEFAULT_RECORDS_LIMIT, input_type=int)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_names, failed_names, json_results, table_results = [], [], [], {}
    resource_names = convert_comma_separated_to_list(resource_names)

    try:
        start_time = get_timestamp_from_range(timeframe)

        manager = GoogleSecurityCommandCenterManager(api_root=api_root, organization_id=organization_id,
                                                     service_account_string=service_account_string,
                                                     verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER)
        manager.test_connectivity()
        assets = manager.get_asset_details(resource_names=resource_names)

        for name in resource_names:
            asset = next((asset for asset in assets if asset.asset_name == name), None)
            try:
                vulnerabilities, misconfigurations = [], []
                if record_types == ONLY_VULNERABILTIES:
                    vulnerabilities = manager.get_vulnerabilities(resource_name=name, timestamp=start_time, limit=limit)
                elif record_types == ONLY_MISCONFIGURATIONS:
                    misconfigurations = manager.get_misconfigurations(resource_name=name, timestamp=start_time, limit=limit)
                else:
                    vulnerabilities = manager.get_vulnerabilities(resource_name=name, timestamp=start_time, limit=limit)
                    misconfigurations = manager.get_misconfigurations(resource_name=name, timestamp=start_time, limit=limit)

                if vulnerabilities or misconfigurations:
                    successful_names.append(name)
                    vulnerabilities_stats = copy.deepcopy(STATISTICS_DICT)
                    misconfigurations_stats = copy.deepcopy(STATISTICS_DICT)
                    counted_vulnerabilities = Counter(item.severity for item in vulnerabilities)
                    counted_misconfigurations = Counter(item.severity for item in misconfigurations)

                    for t, count in counted_vulnerabilities.items():
                        vulnerabilities_stats.update({t.lower(): count})
                    for t, count in counted_misconfigurations.items():
                        misconfigurations_stats.update({t.lower(): count})

                    if output_type == ONLY_DATA:
                        results = {
                            "siemplify_asset_display_name": asset.get_user_friendly_name() or name,
                            "vulnerabilities": {
                                "data": [v.as_vulnerability_json() for v in vulnerabilities]
                            },
                            "misconfigurations": {
                                "data": [m.as_vulnerability_json() for m in misconfigurations]
                            }
                        }
                        if record_types == ONLY_VULNERABILTIES:
                            results.pop("misconfigurations", None)
                        elif record_types == ONLY_MISCONFIGURATIONS:
                            results.pop("vulnerabilities", None)

                        json_results.append({
                            "asset_identifier": name,
                            "results": results
                        })
                    elif output_type == ONLY_STATISTICS:
                        results = {
                            "siemplify_asset_display_name": asset.get_user_friendly_name() or name,
                            "vulnerabilities": {
                                "statistics": vulnerabilities_stats
                            },
                            "misconfigurations": {
                                "statistics": misconfigurations_stats
                            }
                        }
                        if record_types == ONLY_VULNERABILTIES:
                            results.pop("misconfigurations", None)
                        elif record_types == ONLY_MISCONFIGURATIONS:
                            results.pop("vulnerabilities", None)

                        json_results.append({
                            "asset_identifier": name,
                            "results": results
                        })
                    else:
                        results = {
                            "siemplify_asset_display_name": asset.get_user_friendly_name() or name,
                            "vulnerabilities": {
                                "statistics": vulnerabilities_stats,
                                "data": [v.as_vulnerability_json() for v in vulnerabilities]
                            },
                            "misconfigurations": {
                                "statistics": misconfigurations_stats,
                                "data": [m.as_vulnerability_json() for m in misconfigurations]
                            }
                        }
                        if record_types == ONLY_VULNERABILTIES:
                            results.pop("misconfigurations", None)
                        elif record_types == ONLY_MISCONFIGURATIONS:
                            results.pop("vulnerabilities", None)

                        json_results.append({
                            "asset_identifier": name,
                            "results": results
                        })

                    table_results[f"{name} Vulnerabilities"] = [v.to_vulnerability_table() for v in vulnerabilities]
                    table_results[f"{name} Misconfigurations"] = [m.to_vulnerability_table() for m in misconfigurations]
                else:
                    failed_names.append(name)
            except Exception as e:
                siemplify.LOGGER.error(f"Failed processing resource: {name}: Error is: {e}")
                failed_names.append(name)

        if successful_names:
            output_message = f"Successfully returned related vulnerabilities and misconfigurations to the following " \
                             f"entities in {INTEGRATION_DISPLAY_NAME}: " \
                             f"{convert_list_to_comma_string(successful_names)}\n\n"
            siemplify.result.add_result_json(json_results)
            for table_name, data in table_results.items():
                if data:
                    siemplify.result.add_data_table(table_name, construct_csv(data))

        if failed_names:
            output_message += f"No vulnerabilities and misconfigurations were found to the following entities in " \
                              f"{INTEGRATION_DISPLAY_NAME}: {convert_list_to_comma_string(failed_names)}\n"

        if not successful_names:
            result = False
            output_message = f"No vulnerabilities and misconfigurations were found for the provided assets in " \
                             f"{INTEGRATION_DISPLAY_NAME}"

    except GoogleSecurityCommandCenterInvalidProject:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Project_id was not found in JSON payload provided in the parameter " \
                         "\"User's Service Account\". Please check."
    except GoogleSecurityCommandCenterInvalidJsonException:
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = "Invalid JSON payload provided in the parameter \"User's Service Account\". Please " \
                         "check the structure."

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {LIST_ASSET_VULNERABILITIES_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Error executing action \"{LIST_ASSET_VULNERABILITIES_SCRIPT_NAME}.\" Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")

    siemplify.end(output_message, result, status)


if __name__ == "__main__":
    main()
