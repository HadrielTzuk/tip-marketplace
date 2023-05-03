from SiemplifyAction import SiemplifyAction
from XDRManager import XDRManager

PROVIDER_NAME = 'PaloAltoCortexXDR'
SCRIPT_NAME = "Palo Alto Cortex XDR - Ping"


def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    siemplify.LOGGER.info("================= Main - Param Init =================")

    conf = siemplify.get_configuration(PROVIDER_NAME)
    api_root = conf.get('Api Root')
    api_key = conf.get('Api Key')
    api_key_id = conf.get('Api Key ID')
    verify_ssl = str(conf.get('Verify SSL', 'False')).lower() == 'true'

    siemplify.LOGGER.info("----------------- Main - Started -----------------")
    xdr_manager = XDRManager(api_root, api_key, api_key_id, verify_ssl)

    output_message = "Successfully connected to Palo Alto Cortex XDR"
    result_value = 'true'

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        "\n  result_value: {}\n  output_message: {}".format(result_value, output_message))
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()

