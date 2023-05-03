from SiemplifyAction import SiemplifyAction
from RecordedFutureManager import RecordedFutureManager
from RecordedFutureCommon import RecordedFutureCommon
from SiemplifyDataModel import EntityTypes
from SiemplifyUtils import output_handler
from TIPCommon import extract_configuration_param
from constants import PROVIDER_NAME, GET_IP_RELATED_ENTITIES_SCRIPT_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_IP_RELATED_ENTITIES_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")
    
    api_url = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiUrl")
    api_key = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="ApiKey")
    verify_ssl = extract_configuration_param(siemplify, provider_name=PROVIDER_NAME, param_name="Verify SSL",
                                             default_value=False, input_type=bool)
    
    recorded_future_common = RecordedFutureCommon(siemplify, api_url, api_key, verify_ssl=verify_ssl)
    recorded_future_common.get_related_entities_logic([EntityTypes.ADDRESS], GET_IP_RELATED_ENTITIES_SCRIPT_NAME)


if __name__ == '__main__':
    main()
