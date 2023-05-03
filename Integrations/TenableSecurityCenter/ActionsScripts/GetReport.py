from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from TenableManager import TenableSecurityCenterManager

SCRIPT_NAME = "TenableSecurityCenter - GetReport"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = SCRIPT_NAME
    conf = siemplify.get_configuration('TenableSecurityCenter')
    server_address = conf['Server Address']
    username = conf['Username']
    password = conf['Password']
    use_ssl = conf['Use SSL'].lower() == 'true'

    report_id = siemplify.parameters.get('Report ID')
    report_name = siemplify.parameters.get('Report Name')

    tenable_manager = TenableSecurityCenterManager(server_address, username,
                                                   password, use_ssl)
    try:
        if report_id:
            siemplify.LOGGER.info('Fetching report by ID: {0}'.format(report_id))
            report = tenable_manager.get_report_by_id(report_id)
        elif report_name:
            siemplify.LOGGER.info('Fetching report by name: {0}'.format(report_name))
            report = tenable_manager.get_report_by_name(report_name)
        else:
            raise Exception('One of Report ID or Report name must be inserted.')
    except Exception as err:
        siemplify.LOGGER.error('Failed fetching report, ERROR: {0}'.format(err.message))
        siemplify.LOGGER.exception(err)
        raise

    if report:
        siemplify.result.add_result_json(report)
        output_message = 'Report found.'
        result_value = 'true'
    else:
        output_message = 'Report not found.'
        result_value = 'false'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
