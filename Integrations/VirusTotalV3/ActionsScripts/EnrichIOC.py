from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
from VirusTotalManager import VirusTotalManager
from constants import PROVIDER_NAME, INTEGRATION_NAME, ENRICH_IOC_SCRIPT_NAME, IOC_TYPES, WIDGET_THEME_MAPPING
from UtilsManager import convert_comma_separated_to_list, prepare_ioc_for_manager
from exceptions import VirusTotalNotFoundException


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_IOC_SCRIPT_NAME

    # integration configuration
    api_key = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="API Key")
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             default_value=True, input_type=bool)
    # action parameters
    ioc_type = extract_action_param(siemplify, param_name="IOC Type", print_value=False)
    iocs_string = extract_action_param(siemplify, param_name="IOCs", is_mandatory=True, print_value=False)
    widget_theme = extract_action_param(siemplify, param_name="Widget Theme", print_value=True)
    fetch_widget = extract_action_param(siemplify, param_name="Fetch Widget", input_type=bool, default_value=True,
                                        print_value=True)
    iocs = convert_comma_separated_to_list(iocs_string)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    output_message = ""
    result_value = True
    status = EXECUTION_STATE_COMPLETED
    json_results = []
    successful_iocs = []
    failed_iocs = []
    not_found_iocs = []
    request_items = {
        IOC_TYPES.get("filehash"): {
            'url_prefix': 'files',
            'parser_method': 'build_ioc_object'
        },
        IOC_TYPES.get("url"): {
            'url_prefix': 'urls',
            'parser_method': 'build_ioc_object'
        },
        IOC_TYPES.get("domain"): {
            'url_prefix': 'domains',
            'parser_method': 'build_ioc_object'
        },
        IOC_TYPES.get("ip_address"): {
            'url_prefix': 'ip_addresses',
            'parser_method': 'build_ioc_object',
        },
    }

    try:
        manager = VirusTotalManager(api_key=api_key, verify_ssl=verify_ssl)

        for ioc in iocs:
            siemplify.LOGGER.info(f"\nStarted processing ioc: {ioc}")

            request_item = request_items.get(ioc_type)
            ioc_value = prepare_ioc_for_manager(ioc, ioc_type)

            try:
                ioc_details = manager.get_ioc_details(
                    url_prefix=request_item.get('url_prefix'),
                    ioc=ioc_value,
                    parser_method=request_item.get('parser_method')
                )

                if ioc_details:
                    widget_link, _ = manager.get_widget(
                        ioc, theme_colors=WIDGET_THEME_MAPPING.get(widget_theme)
                    ) if fetch_widget else (None, None)
                    json_results.append({
                        "identifier": ioc,
                        "details": ioc_details.to_json(widget_link=widget_link)
                    })
                    siemplify.result.add_entity_link(f"{ioc}", ioc_details.to_case_wall_link(ioc_type, ioc_value))
                    siemplify.result.add_data_table(f"{ioc}", data_table=construct_csv(ioc_details.to_table()))
                    successful_iocs.append(ioc)
                else:
                    not_found_iocs.append(ioc)
                    siemplify.LOGGER.error(f"No information were found for ioc {ioc}")

            except VirusTotalNotFoundException:
                not_found_iocs.append(ioc)
                siemplify.LOGGER.error(f"No information were found for ioc {ioc}")
            except Exception as err:
                failed_iocs.append(ioc)
                siemplify.LOGGER.error(f"Failed processing ioc: {ioc}")
                siemplify.LOGGER.exception(err)

            siemplify.LOGGER.info(f"Finished processing ioc {ioc}\n")

        if successful_iocs:
            siemplify.result.add_result_json({"iocs": json_results})
            output_message += "Successfully enriched the following IOCs using {}: \n{}" \
                .format(PROVIDER_NAME, "\n".join([ioc for ioc in successful_iocs]))

        if not_found_iocs:
            output_message += "\nNo information found for the following IOCs using {}: \n{}" \
                .format(PROVIDER_NAME, "\n".join([ioc for ioc in not_found_iocs]))

        if failed_iocs:
            output_message += "\nAction wasn't able to enrich the following IOCs using {}: \n{}" \
                .format(PROVIDER_NAME, "\n".join([ioc for ioc in failed_iocs]))

        if not successful_iocs:
            siemplify.result.add_result_json({"iocs": []})
            result_value = False
            output_message = "No information about IOCs were found."

    except Exception as err:
        output_message = f"Error executing action {ENRICH_IOC_SCRIPT_NAME}. Reason: {err}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(err)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result Value: {result_value}")
    siemplify.LOGGER.info(f"Output Message: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == '__main__':
    main()
