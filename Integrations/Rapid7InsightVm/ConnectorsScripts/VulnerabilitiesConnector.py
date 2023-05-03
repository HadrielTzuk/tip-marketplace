import sys

from EnvironmentCommon import GetEnvironmentCommonFactory
from Rapid7Manager import Rapid7Manager
from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import AlertInfo
from SiemplifyUtils import output_handler, unix_now
from TIPCommon import (
    read_ids,
    is_approaching_timeout,
    pass_whitelist_filter,
    convert_list_to_comma_string,
    is_overflowed,
    extract_connector_param
)
from UtilsManager import (
    pass_severity_filter,
    write_ids
)
from constants import (
    CONNECTOR_NAME,
    SEVERITIES,
    POSSIBLE_GROUPINGS,
    DEFAULT_ASSET_LIMIT,
    HOST_GROUPING,
    NONE_GROUPING,
    STORED_IDS_LIMIT
)

connector_starting_time = unix_now()


@output_handler
def main(is_test_run):
    siemplify = SiemplifyConnectorExecution()
    siemplify.script_name = CONNECTOR_NAME
    processed_alerts = []

    if is_test_run:
        siemplify.LOGGER.info(u"***** This is an \"IDE Play Button\"\\\"Run Connector once\" test run ******")

    siemplify.LOGGER.info(u"------------------- Main - Param Init -------------------")

    api_root = extract_connector_param(siemplify, param_name=u"API Root", is_mandatory=True, print_value=True)
    username = extract_connector_param(siemplify, param_name=u"Username", is_mandatory=True, print_value=True)
    password = extract_connector_param(siemplify, param_name=u"Password", is_mandatory=True)
    verify_ssl = extract_connector_param(siemplify, param_name=u"Verify SSL", is_mandatory=True, input_type=bool,
                                         print_value=True)

    environment_field_name = extract_connector_param(siemplify, param_name=u"Environment Field Name", print_value=True)
    environment_regex_pattern = extract_connector_param(siemplify, param_name=u"Environment Regex Pattern",
                                                        print_value=True)

    script_timeout = extract_connector_param(siemplify, param_name=u"PythonProcessTimeout", is_mandatory=True,
                                             input_type=int, print_value=True)
    lowest_severity_to_fetch = extract_connector_param(siemplify, param_name=u"Lowest Severity To Fetch",
                                                       print_value=True)
    fetch_limit = extract_connector_param(siemplify, param_name=u"Max Assets To Process", input_type=int,
                                          default_value=DEFAULT_ASSET_LIMIT, print_value=True)
    grouping_mechanism = extract_connector_param(siemplify, param_name=u"Grouping Mechanism", is_mandatory=True,
                                                 print_value=True)
    whitelist_as_a_blacklist = extract_connector_param(siemplify, u"Use whitelist as a blacklist", is_mandatory=True,
                                                       input_type=bool, print_value=True)
    device_product_field = extract_connector_param(siemplify, u"DeviceProductField", is_mandatory=True)
    grouping_mechanism = grouping_mechanism.title()

    try:
        siemplify.LOGGER.info(u"------------------- Main - Started -------------------")

        if fetch_limit < 1:
            siemplify.LOGGER.info(u"Max Assets To Process must be greater than zero. The default value {} "
                                  u"will be used".format(DEFAULT_ASSET_LIMIT))
            fetch_limit = DEFAULT_ASSET_LIMIT

        if lowest_severity_to_fetch and lowest_severity_to_fetch.lower() not in SEVERITIES:
            raise Exception(u"Invalid value given for Lowest Severity To Fetch parameter. Possible values are: "
                            u"{}.".format(convert_list_to_comma_string([severity.title() for severity in SEVERITIES])))

        if grouping_mechanism not in POSSIBLE_GROUPINGS:
            siemplify.LOGGER.error(u"Invalid value given for Grouping Mechanism. {} will be used".format(NONE_GROUPING))
            grouping_mechanism = NONE_GROUPING

        # Read already existing alerts ids
        assets_list = read_ids(siemplify)
        siemplify.LOGGER.info(u"Successfully loaded existing assets from ids file")

        manager = Rapid7Manager(api_root=api_root,
                                username=username,
                                password=password,
                                verify_ssl=verify_ssl,
                                siemplify=siemplify)

        filtered_assets, assets_list = manager.get_assets(
            assets_list=assets_list,
            limit=fetch_limit
        )

        siemplify.LOGGER.info(u"Fetched {} assets".format(len(filtered_assets)))
        fetched_vulnerabilities = []

        if is_test_run:
            siemplify.LOGGER.info(u"This is a TEST run. Only 1 asset will be processed.")
            filtered_assets = filtered_assets[:1]

        for asset in filtered_assets:
            try:
                if is_approaching_timeout(connector_starting_time, script_timeout):
                    siemplify.LOGGER.info(u"Timeout is approaching. Connector will gracefully exit")
                    break

                siemplify.LOGGER.info(u"Started processing asset {}".format(asset.id))
                asset_json = next((item for item in assets_list if item.get("asset_id", None) == asset.id), {})

                environment_common = GetEnvironmentCommonFactory.create_environment_manager(
                    siemplify,
                    environment_field_name,
                    environment_regex_pattern
                )

                for alert in manager.get_asset_vulnerabilities(asset_id=asset.id,
                                                               existing_ids=asset_json["vulnerabilities"]):
                    siemplify.LOGGER.info(u"Started processing vulnerability {}".format(alert.id))

                    existing_alert = next((item for item in fetched_vulnerabilities if item.id == alert.id), None)
                    if existing_alert:
                        alert = existing_alert
                    else:
                        alert.details = manager.get_vulnerability_details(vulnerability_id=alert.id)
                        fetched_vulnerabilities.append(alert)

                    if not pass_filters(siemplify, whitelist_as_a_blacklist, alert.details, "title",
                                        lowest_severity_to_fetch):
                        continue

                    # Update existing alerts
                    asset_json["vulnerabilities"].append(alert.id)
                    asset.vulnerabilities.append(alert)

                    if grouping_mechanism == NONE_GROUPING:
                        alert_info = alert.get_alert_info(
                            alert_info=AlertInfo(),
                            environment_common=environment_common,
                            device_product_field=device_product_field
                        )

                        if is_overflowed(siemplify, alert_info, is_test_run):
                            siemplify.LOGGER.info(
                                u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. '
                                u'Skipping...'.format(alert_name=unicode(alert_info.rule_generator),
                                                      alert_identifier=unicode(alert_info.ticket_id),
                                                      environment=unicode(alert_info.environment),
                                                      product=unicode(alert_info.device_product)))
                            # If is overflowed we should skip
                            continue

                        siemplify.LOGGER.info(u"Alert {} was created.".format(alert.id))
                        processed_alerts.append(alert_info)

                    siemplify.LOGGER.info(u"Finished processing vulnerability {}".format(alert.id))

                if grouping_mechanism == HOST_GROUPING and asset.vulnerabilities:
                    alert_info = asset.get_alert_info(
                        alert_info=AlertInfo(),
                        environment_common=environment_common,
                        device_product_field=device_product_field,
                        execution_time=connector_starting_time
                    )

                    if is_overflowed(siemplify, alert_info, is_test_run):
                        siemplify.LOGGER.info(
                            u'{alert_name}-{alert_identifier}-{environment}-{product} found as overflow alert. '
                            u'Skipping...'.format(alert_name=unicode(alert_info.rule_generator),
                                                  alert_identifier=unicode(alert_info.ticket_id),
                                                  environment=unicode(alert_info.environment),
                                                  product=unicode(alert_info.device_product)))
                        # If is overflowed we should skip
                        continue

                    siemplify.LOGGER.info(u"Alert {} was created.".format(asset.id))
                    processed_alerts.append(alert_info)

                asset_json["vulnerabilities"] = asset_json["vulnerabilities"][-STORED_IDS_LIMIT:]
                asset_json["processed"] = True

            except Exception as e:
                siemplify.LOGGER.error(u"Failed to process asset {}".format(asset.id))
                siemplify.LOGGER.exception(e)

                if is_test_run:
                    raise

            siemplify.LOGGER.info(u"Finished processing asset {}".format(asset.id))

        if not is_test_run:
            siemplify.LOGGER.info(u"Saving existing ids.")
            write_ids(siemplify, assets_list)

    except Exception as e:
        siemplify.LOGGER.error(u"Got exception on main handler. Error: {}".format(e))
        siemplify.LOGGER.exception(e)

        if is_test_run:
            raise

    siemplify.LOGGER.info(u"Created total of {} cases".format(len(processed_alerts)))
    siemplify.LOGGER.info(u"------------------- Main - Finished -------------------")
    siemplify.return_package(processed_alerts)


def pass_filters(siemplify, whitelist_as_a_blacklist, alert, model_key, lowest_risk_to_fetch):
    # All alert filters should be checked here
    if not pass_whitelist_filter(siemplify, whitelist_as_a_blacklist, alert, model_key):
        return False

    if not pass_severity_filter(siemplify, alert, lowest_risk_to_fetch):
        return False

    return True


if __name__ == "__main__":
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    is_test = not (len(sys.argv) < 2 or sys.argv[1] == "True")
    main(is_test)
