INTEGRATION_NAME = "EasyVista"
PING_ACTION = '{} - Ping'.format(INTEGRATION_NAME)
GET_EASYVISTA_TICKET_ACTION = '{} - Get EasyVista Ticket'.format(INTEGRATION_NAME)
ADD_COMMENT_TO_TICKET= '{} - Add Comment To Ticket'.format(INTEGRATION_NAME)
WAIT_FOR_TICKET_UPDATE = '{} - Wait For Ticket Update'.format(INTEGRATION_NAME)
CLOSE_EASYVISTA_TICKET = '{} - Close EasyVista Ticket'.format(INTEGRATION_NAME)

DATETIME_FORMAT = '%m/%d/%Y %H:%M:%S'

#Endpoints
PING_QUERY = '{}/requests?max_rows=1'
TICKET_MODIFICATION = '{}/requests/{}'
TICKET_COMMENT  = '{}/requests/{}/comment'
TICKET_DESCRIPTION  = '{}/requests/{}/description'
TICKET_DOCUMENTS = '{}/requests/{}/documents'
TICKET_ACTIONS = '{}/actions?search=REQUEST.RFC_NUMBER:{}'