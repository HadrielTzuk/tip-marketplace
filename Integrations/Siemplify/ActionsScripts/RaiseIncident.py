from SiemplifyUtils import output_handler
from SiemplifyAction import *


@output_handler
def main():
    siemplify = SiemplifyAction()
    soc_role = siemplify.parameters.get("Soc Role", '@SocManager')
    siemplify.raise_incident()
    siemplify.assign_case(soc_role)

    output_message = "The case raised to Incident status"
    siemplify.end(output_message, "true")


if __name__ == '__main__':
    main()
