from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from SysAidManager import SysAidManager

PROVIDER = u"SysAid"
ACTION_NAME = u"SysAid - CreateServiceRequest"


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.action_definition_name = ACTION_NAME
    conf = siemplify.get_configuration(PROVIDER)
    verify_ssl = conf.get(u'Verify SSL').lower() == u'true'
    manager = SysAidManager(server_address=conf.get(u'Api Root'),
                            username=conf.get(u'Username'),
                            password=conf.get(u'Password'),
                            verify_ssl=verify_ssl)

    title = siemplify.parameters.get(u'Title')
    description = siemplify.parameters.get(u'Description')
    status = siemplify.parameters.get(u'Status')
    priority = siemplify.parameters.get(u'Priority')
    assignee = siemplify.parameters.get(u'Assignee')
    urgency = siemplify.parameters.get(u'Urgency')
    request_user = siemplify.parameters.get(u'Request User')
    assigned_group = siemplify.parameters.get(u'Assigned Group')
    category = siemplify.parameters.get(u'Category')
    sub_category = siemplify.parameters.get(u'Subcategory')
    third_category = siemplify.parameters.get(u'Third Category')

    service_request_id = manager.create_service_request(
        title=title,
        description=description,
        status=status,
        priority=priority,
        assignee=assignee,
        urgency=urgency,
        request_user=request_user,
        category=category,
        sub_category=sub_category,
        third_category=third_category,
        assigned_group=assigned_group
    )
    siemplify.end(u"Successfully created service request {}.".format(service_request_id), service_request_id)


if __name__ == '__main__':
    main()