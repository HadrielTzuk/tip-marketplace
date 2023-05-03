from SiemplifyUtils import output_handler
from SiemplifyAction import SiemplifyAction
from RedisManager import RedisManager
import json


@output_handler
def main():
    siemplify = SiemplifyAction()
    conf = siemplify.get_configuration('Redis')
    server = conf['Server Address']
    port = int(conf['Port'])

    redis_manager = RedisManager(server, port, 0)
    list_name = siemplify.parameters['List Name']
    json_results = {}

    list_values = redis_manager.get_list(list_name)
    if list_values:
        siemplify.result.add_json("List values:", json.dumps(list_values))
        json_results = json.dumps(list_values)
        # output_message = "List {list} values are:{list_values}.".format(list=list_name, list_values=list_values)
        output_message = "List contain {0} elements".format(len(list_values))
    else:
        # output_message = "Can not find values for {list}.".format(list=list_name)
        output_message = "Can not find values"

    # add json
    siemplify.result.add_result_json(json_results)
    siemplify.end(output_message, json.dumps(list_values))


if __name__ == '__main__':
    main()
