from SiemplifyUtils import output_handler
# Imports
from SiemplifyAction import SiemplifyAction
from ZendeskManager import ZendeskManager
from SiemplifyUtils import construct_csv
import json
import base64


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration("Zendesk")
    user_email = conf['User Email Address']
    api_token = conf['Api Token']
    server_address = conf['Server Address']
    zendesk = ZendeskManager(user_email, api_token, server_address)
    ticket_id = siemplify.parameters['Ticket ID']

    json_result = {}

    ticket_details = zendesk.get_ticket_details(ticket_id)
    ticket_comments = zendesk.get_ticket_comments(ticket_id)
    ticket_attachments = zendesk.get_attachments_from_ticket(ticket_id)

    if ticket_comments:
        ticket_comments_csv = construct_csv(ticket_comments)
        siemplify.result.add_data_table('Ticket Comments', ticket_comments_csv)
        json_result["Comments"] = ticket_comments
    else:
        json_result["Comments"] = {}

    if ticket_attachments:
        attachments_names = []
        for attachment in ticket_attachments:
            for file_name, file_content in attachment.items():
                siemplify.result.add_attachment(file_name, file_name, base64.b64encode(file_content))
                attachments_names.append(file_name)
        json_result["Attachments"] = ticket_attachments
    else:
        json_result["Attachments"] = {}

    if ticket_details:
        ticket_json = json.dumps(ticket_details['ticket'], indent=4, sort_keys=True)
        siemplify.result.add_json("Ticket Data", ticket_json)
        output_message = "Ticket with id {0} received.".format(ticket_id)
        result_value = ticket_json
        json_result["Details"] = ticket_details
    else:
        output_message = 'Can not retrieve ticket with id {0}.'.format(ticket_id)
        result_value = 'false'
        json_result["Details"] = {}

    siemplify.end(output_message, result_value)


if __name__ == '__main__':
    main()
