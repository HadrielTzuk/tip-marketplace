from SiemplifyJob import SiemplifyJob
from SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = "DummyJob" # In order to use the SiemplifyLogger, you must assign a name to the script.
    
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
    
    siemplify.LOGGER.info("Boolean: {}".format(boolean))
    siemplify.LOGGER.info("Integer: {}".format(integer))
    siemplify.LOGGER.info("Password: {}".format(password))
    siemplify.LOGGER.info("String: {}".format(string))
    siemplify.LOGGER.info("IP: {}".format(ip))
    siemplify.LOGGER.info("Email: {}".format(email))
    siemplify.LOGGER.info("User: {}".format(user))
    siemplify.LOGGER.info("Stage: {}".format(stage))
    siemplify.LOGGER.info("Case Close Reason: {}".format(case_close_reason))
    siemplify.LOGGER.info("Close Case Root Cause: {}".format(close_case_root_cause))
    siemplify.LOGGER.info("Priority: {}".format(priority))
    siemplify.LOGGER.info("Email Content: {}".format(email_content))
    siemplify.LOGGER.info("Content: {}".format(content))
    siemplify.LOGGER.info("Playbook Name: {}".format(playbook_name))
    siemplify.LOGGER.info("Entity Type: {}".format(entity_type))
    siemplify.LOGGER.info("List: {}".format(lst))


if __name__ == "__main__":
    main()