from SiemplifyAction import SiemplifyAction
from RecordedFutureManager import RecordedFutureManager
from RecordedFutureCommon import RecordedFutureCommon
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param, extract_action_param
from constants import PROVIDER_NAME, ENRICH_HOST_SCRIPT_NAME, DEFAULT_THRESHOLD


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ENRICH_HOST_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    api_url = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiUrl")
    api_key = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiKey")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)

    threshold = extract_action_param(siemplify, param_name="Risk Score Threshold", is_mandatory=True,
                                     default_value=DEFAULT_THRESHOLD, input_type=int)
    include_related_entities = extract_action_param(siemplify, param_name="Include Related Entities",
                                                    default_value=False, input_type=bool, print_value=True)
    
    recorded_future_common = RecordedFutureCommon(siemplify, api_url, api_key, verify_ssl=verify_ssl)
    recorded_future_common.enrich_common_logic([EntityTypes.HOSTNAME], threshold, ENRICH_HOST_SCRIPT_NAME,
                                               include_related_entities)


if __name__ == '__main__':
    main()
