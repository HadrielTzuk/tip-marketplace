from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from ProofPointTapManager import ProofPointTapManager
from constants import GET_CAMPAIGN_SCRIPT_NAME, INTEGRATION_NAME, INTEGRATION_DISPLAY_NAME, LIMIT_DEFAULT, MAX_LIMIT, \
    CAMPAIGNS_TABLE_NAME, CAMPAIGN_EVIDENCE_TABLE_NAME
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyDataModel import InsightSeverity, InsightType
from TIPCommon import extract_configuration_param, extract_action_param, string_to_multi_value, construct_csv
from utils import validate_positive_integer
from SiemplifyDataModel import EntityTypes


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = GET_CAMPAIGN_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Api Root",
                                           is_mandatory=True, print_value=True)
    username = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Username",
                                           is_mandatory=True)
    password = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Password",
                                           is_mandatory=True)
    verify_ssl = extract_configuration_param(siemplify, provider_name=INTEGRATION_NAME, param_name="Verify SSL",
                                             input_type=bool, print_value=True)

    campaign_ids = string_to_multi_value(extract_action_param(siemplify, param_name='Campaign ID', is_mandatory=True,
                                                              print_value=True))

    create_insight = extract_action_param(siemplify, param_name='Create Insight', print_value=True, input_type=bool)
    create_entity = extract_action_param(siemplify, param_name='Create Threat Campaign Entity', print_value=True,
                                         input_type=bool)
    fetch_forensics = extract_action_param(siemplify, param_name='Fetch Forensics Info', print_value=True,
                                           input_type=bool)
    fetch_types = string_to_multi_value(extract_action_param(siemplify, param_name='Forensic Evidence Type Filter',
                                                             print_value=True))
    max_forensics_to_fetch = extract_action_param(siemplify, param_name='Max Forensics Evidence To Return',
                                                  print_value=True, input_type=int, default_value=50)

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    result_value = True
    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    successful_ids, failed_ids, json_result, csv_result = [], [], [], []

    try:
        validate_positive_integer(
            number=max_forensics_to_fetch,
            err_msg="Max Forensics Evidence To Return parameter should be positive"
        )

        if max_forensics_to_fetch > MAX_LIMIT:
            raise Exception(
                f'Max Forensics Evidence To Return parameter should be less than maximum limit parameter: {MAX_LIMIT}')

        manager = ProofPointTapManager(server_address=api_root, username=username, password=password,
                                       verify_ssl=verify_ssl, force_check_connectivity=True)

        for campaign_id in campaign_ids:
            try:
                campaign = manager.get_campaign(campaign_id=campaign_id)
                campaign_json = campaign.to_json()

                if fetch_forensics:
                    forensics_data = manager.get_campaign_forensics(campaign_id=campaign_id, filters=fetch_types,
                                                                    limit=max_forensics_to_fetch)

                    if forensics_data:
                        campaign_json.update({
                            "forensics": forensics_data.to_json()
                        })

                        siemplify.result.add_data_table(
                            CAMPAIGN_EVIDENCE_TABLE_NAME.format(id=campaign_id),
                            construct_csv([forensic.to_table() for forensic in forensics_data.forensics])
                        )

                if create_insight:
                    siemplify.create_case_insight(triggered_by=INTEGRATION_NAME, title=f"{campaign_id}",
                                                  content=campaign.to_insight(), entity_identifier="",
                                                  severity=InsightSeverity.INFO, insight_type=InsightType.General)

                if create_entity:
                    siemplify.add_entity_to_case(campaign.name, EntityTypes.THREATACTOR, is_internal=False,
                                                 is_suspicous=False, is_enriched=False, is_vulnerable=True,
                                                 properties={'is_new_entity': True})

                csv_result.append(campaign.to_table())
                json_result.append(campaign_json)
                successful_ids.append(campaign_id)
            except Exception as e:
                failed_ids.append(campaign_id)
                siemplify.LOGGER.error(f"An error occurred on campaign_id: {campaign_id}. {e}.")
                siemplify.LOGGER.exception(e)

        if successful_ids:
            siemplify.result.add_result_json(json_result)
            siemplify.result.add_data_table(CAMPAIGNS_TABLE_NAME, construct_csv(csv_result))

            output_message += f"Successfully found information for the following campaigns in " \
                              f"{INTEGRATION_DISPLAY_NAME}: {', '.join(successful_ids)}\n"

            if failed_ids:
                output_message += f"Action wasn't able to find information for the following campaigns in" \
                                  f" {INTEGRATION_DISPLAY_NAME}: {', '.join(failed_ids)}\n"
        else:
            output_message = "No information about provided campaigns was found."
            result_value = False

    except Exception as e:
        output_message = f"Error executing action {GET_CAMPAIGN_SCRIPT_NAME}. Reason: {e}"
        result_value = False
        status = EXECUTION_STATE_FAILED
        siemplify.LOGGER.error(output_message)
        siemplify.LOGGER.exception(e)

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info("Status: {}".format(status))
    siemplify.LOGGER.info("Result: {}".format(result_value))
    siemplify.LOGGER.info("Output Message: {}".format(output_message))

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
