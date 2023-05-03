from SiemplifyUtils import output_handler
from SiemplifyDataModel import EntityTypes
from SiemplifyAction import SiemplifyAction
from ProtectwiseManager import ProtectwiseManager
import base64


@output_handler
def main():
    siemplify = SiemplifyAction()

    # This action MUST run in alert scope
    if not siemplify.current_alert:
        siemplify.end("This action can't run manually.", 'false')

    events = siemplify.current_alert.security_events

    configurations = siemplify.get_configuration('Protectwise')
    email = configurations['Email']
    password = configurations['Password']

    protectwise_manager = ProtectwiseManager(email, password)

    found_pcaps_events = []

    for event in events:
        start_time = event.start_time
        end_time = event.end_time

        # Start and end time can't be equal. If they are -
        # add 1 second to the end time
        if start_time == end_time:
            end_time = str(int(end_time) + 1)

        protectwise_events = protectwise_manager.get_events(start_time,
                                                            end_time)

        for protectwise_event in protectwise_events:
            # Download PCAP
            pcap_content = protectwise_manager.download_pcap(
                protectwise_event['id'])

            # Attach the downloaded pcap
            siemplify.result.add_attachment(
                "ProtectWise pcap - {0}: {1}".format(
                    event.name, protectwise_event['id']
                ),
                "{}.pcap".format(protectwise_event['id']),
                base64.b64encode(pcap_content)
            )

        if protectwise_events:
            found_pcaps_events.append(event.name)

    if found_pcaps_events:
        output_message = 'Successfully downloaded pcap for events in the case timeframe: \n' + '\n'.join(
            found_pcaps_events)
    else:
        output_message = "No pcaps were downloaded."

    siemplify.end(output_message, 'true')


if __name__ == '__main__':
    main()