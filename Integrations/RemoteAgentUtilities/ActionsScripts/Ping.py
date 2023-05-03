from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction

siemplify = SiemplifyAction()


output_message = 'Connection Established.'
result_value = 'true'
siemplify.end(output_message, result_value)