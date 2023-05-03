from SiemplifyAction import *
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = "SIemplifyTest - Test Action Params"

    boolean = str(siemplify.parameters.get("Boolean", "False")).lower() == 'true'
    integer = int(siemplify.parameters.get("Integer", 0)) if siemplify.parameters.get("Integer") else 0
    password = siemplify.parameters.get("Password")
    string = siemplify.parameters.get("String")
    ip = siemplify.parameters.get("IP")
    email = siemplify.parameters.get("Email")
    user = siemplify.parameters.get("User")
    stage = siemplify.parameters.get("Stage")
    case_close_reason = siemplify.parameters.get("Case Close Reason")
    close_case_root_cause = siemplify.parameters.get("Close Case Root Cause")
    priority = siemplify.parameters.get("Priority")
    email_content = siemplify.parameters.get("Email Content")
    content = siemplify.parameters.get("Content")
    playbook_name = siemplify.parameters.get("Playbook Name")
    entity_type = siemplify.parameters.get("Entity Type")
    lst = siemplify.parameters.get("List")

    print("Boolean: {}".format(boolean))
    print("Integer: {}".format(integer))
    print("Password: {}".format(password))
    print("String: {}".format(string))
    print("IP: {}".format(ip))
    print("Email: {}".format(email))
    print("User: {}".format(user))
    print("Stage: {}".format(stage))
    print("Case Close Reason: {}".format(case_close_reason))
    print("Close Case Root Cause: {}".format(close_case_root_cause))
    print("Priority: {}".format(priority))
    print("Email Content: {}".format(email_content))
    print("Content: {}".format(content))
    print("Playbook Name: {}".format(playbook_name))
    print("Entity Type: {}".format(entity_type))
    print("List: {}".format(lst))

    output_message = 'Test completed.'
    result_value = 'true'
    siemplify.end(output_message, result_value)


if __name__ == "__main__":
    main()
