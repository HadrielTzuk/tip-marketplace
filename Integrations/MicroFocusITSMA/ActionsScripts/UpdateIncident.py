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
    display_label = siemplify.parameters.get('Display Label')
    description = siemplify.parameters.get('Description')
    impact_scope = siemplify.parameters.get('Impact Scope')
    urgency = siemplify.parameters.get('Urgency')
    service_id = siemplify.parameters.get('Service ID')

    result_value = itsma_manager.update_incident(incident_id, display_label, description, impact_scope, urgency,
                                                 service_id)

    if result_value:
        updated_params = [param for param, value in siemplify.parameters.iteritems() if value and key is not
                          'Incident ID']

        output_message = 'An incident with id "{0}" was successfully updated. \n Updated parameters: {1}'.format(
            incident_id, ",".join(updated_params))
    else:
        output_message = 'No ticket was updated.'

    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
