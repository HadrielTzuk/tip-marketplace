from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from MicroFocusITSMAManager import MicroFocusITSMAManager


ITSMA_PROVIDER = 'MicroFocusITSMA'


@output_handler
def main():
    # Configuration
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration(ITSMA_PROVIDER)
    itsma_manager = MicroFocusITSMAManager(conf['API Root'], conf['Username'], conf['Password'], conf['Tenant ID'],
                                           conf['External System'], conf['External ID'], conf['Verify SSL'])

    # Parameters.
    incident_id = siemplify.parameters.get('Incident ID')
    status = siemplify.parameters.get('Status')

    result_value = itsma_manager.update_external_incident_status(incident_id, status)

    if result_value:
        output_message = 'An incident with id "{0}" external status was change to {1}'.format(incident_id, status)
    else:
        output_message = 'No ticket was updated.'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
