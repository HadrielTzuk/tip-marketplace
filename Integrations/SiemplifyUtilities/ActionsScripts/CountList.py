from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction


ACTION_NAME = 'Siemplify_Count List'


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = ACTION_NAME

    list_count = 0

    # Parameters.
    input_string = siemplify.parameters.get('Input String', '')
    delimiter = siemplify.parameters.get('Delimiter', ',')

    if input_string:
        list_count = len(input_string.split(delimiter))

    output_message = "List length is: {0}".format(list_count)

    siemplify.end(output_message, list_count)


if __name__ == '__main__':
    main()
