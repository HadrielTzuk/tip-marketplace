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
    display_label = siemplify.parameters.get('Display Label')
    description = siemplify.parameters.get('Description')
    impact_scope = siemplify.parameters.get('Impact Scope')
    urgency = siemplify.parameters.get('Urgency')
    service_id = siemplify.parameters.get('Service ID')

    incident_id = itsma_manager.create_incident(display_label, description, impact_scope, urgency, service_id)

    if incident_id:
        output_message = 'An incident with id "{0}" was successfully created.'.format(incident_id)
    else:
        output_message = 'No ticket was created.'

    siemplify.end(output_message, incident_id)


if __name__ == "__main__":
    main()
