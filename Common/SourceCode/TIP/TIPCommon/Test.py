# from expected_result_matrix import expected_result_matrix
import json

from TIPCommon import extract_script_param


class Logger(object):

    def info(self, msg):
        print
        msg


class Siemplify(object):

    def __init__(self):
        self.LOGGER = Logger()


siemplify = Siemplify()
input_dictionary = {
    "Param int": 1,
    "Param float": 1.1,
    "Param bool A": True,
    "Param bool B": True,
    "Param str": "AAA"
}

param_name_possibilities = ["Param int", "Param float", "Param bool A",
                            "Param bool B", "Param str", "FICTIONAL KEY"]
is_mandatory_possibilities = [True, False]
input_type_possibilities = [int, float, bool, str]
default_value_possibilities = [None, "AAA", 2, 2.2, True]

result_matrix = {}


def populate_result_matrix():

    # Populate the result matrix file with empty values:
    expected_result_matrix = {}
    for param_name in param_name_possibilities:
        for is_mandatory in is_mandatory_possibilities:
            for default_value in default_value_possibilities:
                # if isinstance(default_value,str):
                #     default_value = "'{0}'".format(default_value)
                for input_type in input_type_possibilities:
                    if (input_type != None):
                        input_type = "{0}".format(input_type.__name__)

                    if param_name not in expected_result_matrix:
                        expected_result_matrix[param_name] = {}

                    if is_mandatory not in expected_result_matrix[param_name]:
                        expected_result_matrix[param_name][is_mandatory] = {}

                    if default_value not in expected_result_matrix[param_name][
                        is_mandatory]:
                        expected_result_matrix[param_name][is_mandatory][
                            default_value] = {}

                    value = input_dictionary.get(param_name)

                    if value is None and is_mandatory == False:
                        value = default_value

                    converted_value = value

                    if converted_value is not None:
                        if input_type == "str":
                            converted_value = str(value)
                        elif input_type == "int" and (
                            isinstance(value, float) or isinstance(
                            value,
                            bool
                        )):
                            converted_value = int(value)
                        elif input_type == "float" and (
                            isinstance(value, int) or isinstance(value, bool)):
                            converted_value = float(value)

                    expected_result_matrix[param_name][is_mandatory][
                        default_value][input_type] = converted_value

                    if default_value and not (
                        type(default_value).__name__ == input_type):
                        expected_result_matrix[param_name][is_mandatory][
                            default_value][
                            input_type] = "Given default_value of '{0}' doesn't match expected type {1}".format(
                            default_value,
                            input_type
                        )
                    elif value is None and is_mandatory == True:
                        expected_result_matrix[param_name][is_mandatory][
                            default_value][
                            input_type] = "Missing mandatory parameter {0}".format(
                            param_name
                        )
                    elif input_type == "bool":
                        if value is None:
                            pass
                        else:
                            lowered = str(value).lower()
                            valid_lowered_bool_values = [str(True).lower(),
                                                         str(False).lower()]
                            if lowered not in valid_lowered_bool_values:
                                expected_result_matrix[param_name][
                                    is_mandatory][default_value][
                                    input_type] = "Paramater named {0}, with value {1} isn't a valid BOOL".format(
                                    param_name,
                                    value
                                )
                    elif input_type == "int" and value is not None:
                        try:
                            int(value)
                        except Exception as e:
                            expected_result_matrix[param_name][is_mandatory][
                                default_value][input_type] = e.message
                    elif input_type == "float" and value is not None:
                        try:
                            float(value)
                        except Exception as e:
                            expected_result_matrix[param_name][is_mandatory][
                                default_value][input_type] = e.message
                    # print "expected_result_matrix['{0}'][{1}][{2}][{3}] = None".format(param_name, is_mandatory,
                    #                                                                  default_value, input_type)

    with open("expected_result_matrix.json", "w") as f:
        f.write(json.dumps(expected_result_matrix))


# print json.dumps(expected_result_matrix)


def find_expected_result(
    expected_matrix,
    param_name,
    is_mandatory,
    default_value,
    input_type
):
    is_mandatory = str(is_mandatory)

    if param_name is None:
        param_name = "null"

    if (default_value is None):
        default_value = "null"
    else:
        default_value = str(default_value)

    input_type = input_type.__name__

    return expected_matrix[param_name][is_mandatory][default_value][input_type]


def run_test():
    for param_name in param_name_possibilities:
        for is_mandatory in is_mandatory_possibilities:
            for default_value in default_value_possibilities:
                for input_type in input_type_possibilities:
                    expected_result = find_expected_result(
                        expected_result_matrix,
                        param_name,
                        is_mandatory,
                        default_value,
                        input_type
                    )
                    result = None
                    try:
                        result = extract_script_param(
                            siemplify,
                            input_dictionary,
                            param_name,
                            default_value,
                            input_type,
                            is_mandatory,
                            False
                        )
                    except Exception as e:
                        result = e.message

                    # result_matrix["{0} | IsMan: {1} | default: {2} | type: {3}".format(param_name, is_mandatory, default_value, input_type)] = result

                    if expected_result != result:
                        print
                        "{0} | IsMan: {1} | default: {2} | type: {3} | Result {4} != excpected {5}".format(
                            param_name,
                            is_mandatory,
                            default_value,
                            input_type,
                            result,
                            expected_result
                        )
                    else:
                        pass


print
"------------------------------------------------------------------------"

populate_result_matrix()

with open("expected_result_matrix.json", "r") as f:
    expected_result_matrix = json.loads(f.read())

run_test()

print
"========================"
# for key in result_matrix:
#     print "{0} : {1}".format(key,result_matrix[key])
