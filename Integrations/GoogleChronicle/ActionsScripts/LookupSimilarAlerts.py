from SiemplifyUtils import output_handler, convert_unixtime_to_datetime
from GoogleChronicleManager import GoogleChronicleManager
from SiemplifyAction import SiemplifyAction
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from TIPCommon import extract_configuration_param, extract_action_param, construct_csv
import consts
import utils
import json
import exceptions


SCRIPT_NAME = "Lookup Similar Alerts"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = f"{consts.INTEGRATION_NAME} - {SCRIPT_NAME}"
    siemplify.LOGGER.info("================= Main - Param Init =================")

    # INIT INTEGRATION CONFIGURATION:
    creds = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                        param_name="User's Service Account",
                                        is_mandatory=True)
    api_root = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                           param_name="API Root", is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME, param_name="Verify SSL",
                                             is_mandatory=True, input_type=bool, print_value=True)
    ui_root = extract_configuration_param(siemplify, provider_name=consts.INTEGRATION_NAME,
                                          param_name="UI Root", is_mandatory=True)
    ui_root = ui_root[:-1] if ui_root.endswith("/") else ui_root

    try:
        creds = json.loads(creds)
    except Exception as e:
        siemplify.LOGGER.error("Unable to parse credentials as JSON.")
        siemplify.LOGGER.exception(e)
        siemplify.end("Unable to parse credentials as JSON. Please validate creds.", "false", EXECUTION_STATE_FAILED)

    timeframe = extract_action_param(siemplify, param_name="Time Frame", is_mandatory=False, print_value=True)
    entities = extract_action_param(siemplify, param_name="IOCs / Assets", is_mandatory=True, print_value=True)
    similarity_by = extract_action_param(siemplify, param_name="Similarity By", is_mandatory=False, print_value=True)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    entities = utils.convert_comma_separated_to_list(entities)
    assets, products, filtered_alerts = [], [], []
    total_run_time = 0
    total_processed_events = 0

    external_url = None
    rule_urls = set()
    ioc_warn_message = f"In order to find similar alerts for IOC, action had to change the \"Similarity By\" value " \
                       f"to \"Only IOC/Assets\"."

    try:
        alert_start_time = convert_unixtime_to_datetime(
            int(siemplify._current_alert.additional_properties.get("StartTime")))
        alert_end_time = convert_unixtime_to_datetime(
            int(siemplify._current_alert.additional_properties.get("EndTime")))

        start_time, end_time = utils.get_timestamps(range_string=timeframe,
                                                    alert_start_time=alert_start_time,
                                                    alert_end_time=alert_end_time)

        manager = GoogleChronicleManager(api_root=api_root, verify_ssl=verify_ssl, siemplify_logger=siemplify.LOGGER,
                                         **creds)

        alert_type = siemplify._current_alert.additional_properties.get("alert_type")
        rule_id = siemplify._current_alert.additional_properties.get("rule_id")
        alert_name = siemplify._current_alert.additional_properties.get("alert_name")
        product_name = siemplify._current_alert.additional_properties.get("product_name")

        if alert_type:
            if alert_type in [consts.RULE_ALERT_TYPE, consts.EXTERNAL_ALERT_TYPE]:
                if similarity_by in [consts.SIMILARITY_BY_PRODUCT, consts.SIMILARITY_BY_ASSETS]:
                    rule_id = "-"
                    alerts, time_elapsed = manager.get_rule_alerts(rule_id=rule_id,
                                                                   start_time=start_time,
                                                                   end_time=end_time)
                    external_alerts, external_time_elapsed = manager.list_alerts(start_time=start_time,
                                                                       end_time=end_time,
                                                                       limit=10000,
                                                                       fetch_user_alerts=True)

                    for external_alert in external_alerts:
                        alerts.extend(external_alert.alert_infos)

                    total_run_time += time_elapsed + external_time_elapsed
                    total_processed_events += len(alerts)
                    assets, products, filtered_alerts = check_matches(alerts=alerts, similarity=similarity_by,
                                                                      assets=entities, alert_name=alert_name,
                                                                      product_name=product_name, alert_type=alert_type)
                    for al in filtered_alerts:
                        if al.alert_main_type == consts.RULE_ALERT_TYPE:
                            rule_urls.add(f"{ui_root}/ruleDetections?ruleId={al.rule_id}")

                    if external_alerts:
                        external_url = f"{ui_root}/enterpriseInsights?startTime={start_time}&endTime={end_time}"
                else:
                    if alert_type == consts.RULE_ALERT_TYPE:
                        rule_id = "-" if similarity_by in [consts.SIMILARITY_BY_PRODUCT, consts.SIMILARITY_BY_ASSETS] else rule_id
                        alerts, time_elapsed = manager.get_rule_alerts(rule_id=rule_id,
                                                                       start_time=start_time,
                                                                       end_time=end_time)
                        total_run_time += time_elapsed
                        total_processed_events += len(alerts)
                        assets, products, filtered_alerts = check_matches(alerts=alerts, similarity=similarity_by,
                                                                          assets=entities, alert_name=alert_name,
                                                                          product_name=product_name, alert_type=alert_type)

                        for al in filtered_alerts:
                            if al.alert_main_type == consts.RULE_ALERT_TYPE:
                                rule_urls.add(f"{ui_root}/ruleDetections?ruleId={al.rule_id}")

                    elif alert_type == consts.EXTERNAL_ALERT_TYPE:
                        alerts, time_elapsed = manager.list_alerts(start_time=start_time,
                                                                   end_time=end_time,
                                                                   limit=10000,
                                                                   fetch_user_alerts=True)
                        alert_infos = []
                        for alert in alerts:
                            alert_infos.extend(alert.alert_infos)
                        total_run_time += time_elapsed
                        total_processed_events += len(alert_infos)
                        assets, products, filtered_alerts = check_matches(alerts=alert_infos, similarity=similarity_by,
                                                                          assets=entities, alert_name=alert_name,
                                                                          product_name=product_name, alert_type=alert_type)

                        if alerts:
                            external_url = f"{ui_root}/enterpriseInsights?startTime={start_time}&endTime={end_time}"

            elif alert_type == consts.IOC_ALERT_TYPE:
                rule_id = "-"
                alerts, time_elapsed = manager.get_rule_alerts(rule_id=rule_id,
                                                               start_time=start_time,
                                                               end_time=end_time)
                external_alerts, external_time_elapsed = manager.list_alerts(start_time=start_time,
                                                                   end_time=end_time,
                                                                   limit=10000,
                                                                   fetch_user_alerts=True)

                for external_alert in external_alerts:
                    alerts.extend(external_alert.alert_infos)

                total_run_time += time_elapsed + external_time_elapsed
                total_processed_events += len(alerts)
                if similarity_by != consts.SIMILARITY_BY_ASSETS:
                    siemplify.LOGGER.info(ioc_warn_message)
                assets, products, filtered_alerts = check_matches(alerts=alerts, similarity=consts.SIMILARITY_BY_ASSETS,
                                                                  assets=entities, alert_name=alert_name,
                                                                  product_name=product_name, alert_type=alert_type)

                for al in filtered_alerts:
                    if al.alert_main_type == consts.RULE_ALERT_TYPE:
                        rule_urls.add(f"{ui_root}/ruleDetections?ruleId={al.rule_id}")

                if external_alerts:
                    external_url = f"{ui_root}/enterpriseInsights?startTime={start_time}&endTime={end_time}"

            if filtered_alerts:
                output_message = "Successfully counted similar alerts from the provided time frame in Google Chronicle"
                if alert_type == consts.IOC_ALERT_TYPE and similarity_by != consts.SIMILARITY_BY_ASSETS:
                    output_message += f"\n\n{ioc_warn_message}"
                    similarity_by = consts.SIMILARITY_BY_ASSETS

                json_results, table_results = create_results(similarity=similarity_by, assets=assets, products=products,
                                                             filtered_alerts=filtered_alerts, alert_name=alert_name,
                                                             alert_type=alert_type, rule_urls=list(rule_urls))

                result_json = {"count": len(filtered_alerts), "distinct": json_results,
                               "processed_alerts": total_processed_events, "run_time": total_run_time}
                if external_url:
                    result_json["external_url"] = external_url
                    siemplify.result.add_link("EXTERNAL URL", external_url)
                if rule_urls:
                    # result_json["rule_urls"] = list(rule_urls)
                    for rule_url in rule_urls:
                        siemplify.result.add_link("RULE URLS", rule_url)

                siemplify.result.add_result_json(result_json)
                for key, value in table_results.items():
                    siemplify.result.add_data_table(key, construct_csv(value))

            else:
                output_message = "No similar alerts were found from the provided time frame in Google Chronicle"

        else:
            result_value = False
            output_message = "Action wasn't able to retrieve data about similar alerts. " \
                             "Make sure that this action is executed on the alert from \"Chronicle Alerts Connector\"."

    except exceptions.GoogleChronicleAPILimitError as e:
        output_message = f"Error executing action \"{SCRIPT_NAME}\". Reason: all of the retries are exhausted. " \
                         f"Please wait for a minute and try again."
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False

    except Exception as e:
        siemplify.LOGGER.error(f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        result_value = False
        output_message = f"Error executing action \"{SCRIPT_NAME}\". Reason: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}:".format(status))
    siemplify.LOGGER.info("Result Value: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))
    siemplify.end(output_message, result_value, status)


def check_matches(alerts, similarity, assets, alert_name, product_name, alert_type):
    found_entities = set()
    found_products = []
    matched_alerts = []

    for alert in alerts:
        if similarity == consts.SIMILARITY_BY_NAME_AND_PRODUCT:
            matching_products = [name for name in utils.convert_comma_separated_to_list(product_name)
                                 if name in alert.get_product_names_list]
            is_same_name = alert.name.lower() == alert_name.lower() if alert_type == consts.EXTERNAL_ALERT_TYPE else True
            if is_same_name and matching_products:
                for entity in assets:
                    if entity.lower() in alert.get_all_entities:
                        found_entities.add(entity)
                        found_products.extend(matching_products)
                        if alert.id not in [al.id for al in matched_alerts]:
                            matched_alerts.append(alert)
        elif similarity == consts.SIMILARITY_BY_NAME:
            is_same_name = alert.name.lower() == alert_name.lower() if alert_type == consts.EXTERNAL_ALERT_TYPE else True
            if is_same_name:
                for entity in assets:
                    if entity.lower() in alert.get_all_entities:
                        found_entities.add(entity)
                        if alert.id not in [al.id for al in matched_alerts]:
                            matched_alerts.append(alert)
        elif similarity == consts.SIMILARITY_BY_PRODUCT:
            matching_products = [name for name in utils.convert_comma_separated_to_list(product_name)
                                 if name in alert.get_product_names_list]
            if matching_products:
                for entity in assets:
                    if entity.lower() in alert.get_all_entities:
                        found_entities.add(entity)
                        found_products.extend(matching_products)
                        if alert.id not in [al.id for al in matched_alerts]:
                            matched_alerts.append(alert)
        elif similarity == consts.SIMILARITY_BY_ASSETS:
            for entity in assets:
                if entity.lower() in alert.get_all_entities:
                    found_entities.add(entity)
                    if alert.id not in [al.id for al in matched_alerts]:
                        matched_alerts.append(alert)

    return found_entities, list(set(found_products)), matched_alerts


def create_results(similarity, assets, products, filtered_alerts, alert_name, alert_type, rule_urls):
    json_results = []
    table_results = {}

    if not alert_name:
        alert_name = filtered_alerts[0].name if filtered_alerts else ""

    if similarity == consts.SIMILARITY_BY_NAME_AND_PRODUCT:
        for asset in assets:
            table_results[asset] = []
            matched_alerts = filtered_alerts
            matched_alerts = [al for al in matched_alerts if asset.lower() in al.get_all_entities]
            if matched_alerts:
                for m_alert in matched_alerts:
                    if m_alert.alert_main_type == consts.RULE_ALERT_TYPE:
                        for element in m_alert.collection_elements:
                            element["references"] = [ref for ref in element.get("references", []) if
                                                     ref.get("event", {}).get("metadata", {}).get("productName") in products]
                matched_products = list(set([alert.get_unique_product_name for alert in matched_alerts if alert.get_unique_product_name]))
                for product in matched_products:
                    product_alerts = [al for al in matched_alerts if product == al.get_unique_product_name]
                    if product_alerts:
                        json_results.append(to_json(alerts=product_alerts, product_name=product, entity=asset,
                                                    alert_name=alert_name, alert_type=alert_type, rule_urls=rule_urls))
                        table_results[asset].append(to_table(alerts=product_alerts, product_name=product,
                                                             alert_name=alert_name, alert_type=alert_type))
    elif similarity == consts.SIMILARITY_BY_NAME:
        products = [alert.get_unique_product_name for alert in filtered_alerts]
        products = list(set(products))
        for asset in assets:
            table_results[asset] = []
            matched_alerts = filtered_alerts
            matched_alerts = [al for al in matched_alerts if asset.lower() in al.get_all_entities]
            if matched_alerts:
                for product in products:
                    product_alerts = [al for al in matched_alerts if product == al.get_unique_product_name]
                    if product_alerts:
                        json_results.append(to_json(alerts=product_alerts, product_name=product, entity=asset,
                                                    alert_name=alert_name, alert_type=alert_type, rule_urls=rule_urls))
                        table_results[asset].append(to_table(alerts=product_alerts, product_name=product,
                                                             alert_name=alert_name, alert_type=alert_type))
    elif similarity == consts.SIMILARITY_BY_PRODUCT:
        for asset in assets:
            table_results[asset] = []
            matched_alerts = filtered_alerts
            matched_alerts = [al for al in matched_alerts if asset.lower() in al.get_all_entities]
            if matched_alerts:
                for m_alert in matched_alerts:
                    if m_alert.alert_main_type == consts.RULE_ALERT_TYPE:
                        for element in m_alert.collection_elements:
                            element["references"] = [ref for ref in element.get("references", []) if
                                                     ref.get("event", {}).get("metadata", {}).get(
                                                         "productName") in products]
                matched_products = list(set([alert.get_unique_product_name for alert in matched_alerts if alert.get_unique_product_name]))
                for product in matched_products:
                    product_alerts = [al for al in matched_alerts if product == al.get_unique_product_name]
                    if product_alerts:
                        names = list({alert.name for alert in product_alerts})
                        for name in names:
                            name_alerts = [al for al in product_alerts if name == al.name]
                            if name_alerts:
                                json_results.append(to_json(alerts=name_alerts, product_name=product, entity=asset,
                                                            alert_name=name, alert_type=alert_type, rule_urls=rule_urls))
                                table_results[asset].append(to_table(alerts=product_alerts, product_name=product,
                                                                     alert_name=name, alert_type=alert_type))
    elif similarity == consts.SIMILARITY_BY_ASSETS:
        products = [alert.get_unique_product_name for alert in filtered_alerts]
        products = list(set(products))
        for asset in assets:
            table_results[asset] = []
            matched_alerts = filtered_alerts
            matched_alerts = [al for al in matched_alerts if asset.lower() in al.get_all_entities]
            if matched_alerts:
                for product in products:
                    product_alerts = [al for al in matched_alerts if product == al.get_unique_product_name]
                    if product_alerts:
                        names = list({alert.name for alert in product_alerts})
                        for name in names:
                            name_alerts = [al for al in product_alerts if name == al.name]
                            if name_alerts:
                                json_results.append(to_json(alerts=name_alerts, product_name=product, entity=asset,
                                                            alert_name=name, alert_type=alert_type, rule_urls=rule_urls))
                                table_results[asset].append(to_table(alerts=product_alerts, product_name=product,
                                                                     alert_name=name, alert_type=alert_type))

    return json_results, table_results


def to_json(alerts, product_name, entity, alert_name, alert_type, rule_urls):
    first_seen_list = []
    last_seen_list = []
    for alert in alerts:
        if alert.alert_main_type == consts.EXTERNAL_ALERT_TYPE:
            first_seen_list.append(alert.timestamp)
            last_seen_list.append(alert.timestamp)
        elif alert.alert_main_type == consts.RULE_ALERT_TYPE:
            first_seen_list.append(alert.start_time)
            last_seen_list.append(alert.end_time)

    first_seen = sorted(first_seen_list)[0]
    last_seen = sorted(last_seen_list)[-1]

    hostnames, urls, ips, subjects, users, emails, hashes, processes = [], [], [], [], [], [], [], []

    for alert in alerts:
        hostnames.extend(alert.get_hostnames_list)
        urls.extend(alert.get_urls_list)
        ips.extend(alert.get_ips_list)
        subjects.extend(alert.get_subjects_list)
        users.extend(alert.get_users_list)
        emails.extend(alert.get_emails_list)
        hashes.extend(alert.get_hashes_list)
        processes.extend(alert.get_processes_list)

    json_data = {
        "first_seen": first_seen or "",
        "last_seen": last_seen or "N/A",
        "product_name": product_name or "",
        "used_ioc_asset": entity or "",
        "name": alert_name or "",
        "hostnames": utils.convert_list_to_comma_string(list(set(hostnames))) or "",
        "urls": utils.convert_list_to_comma_string(list(set(urls))) or "",
        "ips": utils.convert_list_to_comma_string(list(set(ips))) or "",
        "subjects": utils.convert_list_to_comma_string(list(set(subjects))) or "",
        "users": utils.convert_list_to_comma_string(list(set(users))) or "",
        "email_addresses": utils.convert_list_to_comma_string(list(set(emails))) or "",
        "hashes": utils.convert_list_to_comma_string(list(set(hashes))) or "",
        "processes": utils.convert_list_to_comma_string(list(set(processes))) or "",
        "count": len(alerts)
    }

    if rule_urls:
        json_data["rule_urls"] = rule_urls

    return json_data


def to_table(alerts, product_name, alert_name, alert_type):
    first_seen_list = []
    last_seen_list = []
    for alert in alerts:
        if alert.alert_main_type == consts.EXTERNAL_ALERT_TYPE:
            first_seen_list.append(alert.timestamp)
            last_seen_list.append(alert.timestamp)
        elif alert.alert_main_type == consts.RULE_ALERT_TYPE:
            first_seen_list.append(alert.start_time)
            last_seen_list.append(alert.end_time)

    first_seen = sorted(first_seen_list)[0]
    last_seen = sorted(last_seen_list)[-1]

    hostnames, urls, ips, subjects, users, emails, hashes, processes = [], [], [], [], [], [], [], []

    for alert in alerts:
        hostnames.extend(alert.get_hostnames_list)
        urls.extend(alert.get_urls_list)
        ips.extend(alert.get_ips_list)
        subjects.extend(alert.get_subjects_list)
        users.extend(alert.get_users_list)
        emails.extend(alert.get_emails_list)
        hashes.extend(alert.get_hashes_list)
        processes.extend(alert.get_processes_list)

    return {
        "First Seen": first_seen or "N/A",
        "Last Seen": last_seen or "N/A",
        "Product": product_name or "N/A",
        "Alert Name": alert_name or "N/A",
        "Hostnames": utils.convert_list_to_comma_string(list(set(hostnames))) or "N/A",
        "URLs": utils.convert_list_to_comma_string(list(set(urls))) or "N/A",
        "IPs": utils.convert_list_to_comma_string(list(set(ips))) or "N/A",
        "Subjects": utils.convert_list_to_comma_string(list(set(subjects))) or "N/A",
        "Users": utils.convert_list_to_comma_string(list(set(users))) or "N/A",
        "Email Addresses": utils.convert_list_to_comma_string(list(set(emails))) or "N/A",
        "Hashes": utils.convert_list_to_comma_string(list(set(hashes))) or "N/A",
        "Processes": utils.convert_list_to_comma_string(list(set(processes))) or "N/A"
    }


if __name__ == "__main__":
    main()
