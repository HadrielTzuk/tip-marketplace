# ============================================================================#
# title           :SiemplifyUtilitiesManager.py
# description     :This Module contain all Siemplify Utilities operations functionality
# author          :avital@siemplify.co
# date            :18-11-2018
# python_version  :2.7
# libraries       :
# requirements     :
# ============================================================================#
# ============================= IMPORTS ===================================== #
import base64
import copy
import email
import itertools
import operator
import re
from email.header import decode_header

import arrow

# ============================== CONSTS ===================================== #
URL_REGEX = {"urls": "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"}
EMAIL_PATTERN = "(?<=<)(.*?)(?=>)"
QUERY_PARAMETER_VALUE_FORMAT = '{0}={1}'  # {0} - Query Field, {1} - Value.
QUERY_PARAMETER_SINGLE_QUOTE_VALUE_FORMAT = """{0}='{1}'"""
QUERY_PARAMETER_DOUBLE_QUOTE_VALUE_FORMAT = '{0}="{1}"'
QUERY_PARAMETER_SINGLE_AND_DOUBLE_QUOTE_VALUE_FORMAT = """{0}='"{1}"'"""
QUERY_OPERATOR_FORMAT = ' {0} '  # {0} - Query operator.

STRING_FIELD_TYPE = 'string'
NUMBER_FIELD_TYPE = 'int'
DATE_FIELD_TYPE = 'date'


# ============================= CLASSES ===================================== #
class SiemplifyUtilitiesManagerError(Exception):
    pass


class SiemplifyUtilitiesManager(object):
    @staticmethod
    def parse_eml(eml_content):
        """
        Extracts all data from e-mail, including sender, to, etc., and returns
        it as a dictionary
        :param msg: {email.message.Message} An eml object
        :return: {dict} The data of the eml
        """
        msg = email.message_from_string(eml_content)
        sender, to, cc, bcc, subject, date = SiemplifyUtilitiesManager.extract_metadata(msg)
        text_body, html_body, count = SiemplifyUtilitiesManager.extract_content(msg)
        text_body = text_body.strip()
        html_body = html_body.strip()

        recipients = [recipient for recipient in itertools.chain(to, cc, bcc) if recipient not in sender]

        return {
            "Subject": subject,
            "From": ",".join(sender),
            "To": ",".join(to),
            "CC": ",".join(cc),
            "BCC": ",".join(bcc),
            "Recipients": ", ".join(recipients),
            "Date": date,
            "Body": text_body,
            "HTML Body": html_body,
            "Attachments": SiemplifyUtilitiesManager.extract_attachments(msg),
            "Links": SiemplifyUtilitiesManager.extract_regex_from_content(html_body, URL_REGEX)
        }

    @staticmethod
    def extract_regex_from_content(content, regex_map):
        """
        Get urls, subject, from and to addresses from email body
        :param content: {str} email body
        :param regex_map: {dict} regex map
        :return: {dict} fields after parse.
        """
        result_dictionary = {}

        for key, regex_value in regex_map.items():
            regex_object = re.compile(regex_value)
            all_results = regex_object.findall(content)
            for index, result in enumerate(all_results, 1):
                # Divide keys
                key_name = '{0}_{1}'.format(key, index) if len(
                    all_results) > 1 else key
                result_dictionary[key_name] = result

        return result_dictionary

    @staticmethod
    def extract_metadata(msg):
        """
        Extract metadata (sender, recipient, date and subject) from EML
        :param msg: {email.message.Message} An eml object
        :return: (tuple) sender, recipient, date and subject
        """
        return re.findall(EMAIL_PATTERN, msg.get("from", "").strip()), \
               re.findall(EMAIL_PATTERN, msg.get("to", "").strip()), \
               re.findall(EMAIL_PATTERN, msg.get("cc", "").strip()), \
               re.findall(EMAIL_PATTERN, msg.get("bcc", "").strip()), \
               msg.get("subject", "").strip(), \
               msg.get("date", "").strip()

    @staticmethod
    def extract_content(msg):
        """
        Extracts content from an e-mail message.
        :param msg: {email.message.Message} An eml object
        :return: {tuple} Text body, Html body, files dict (file_name: file_hash),
        count of parts of the emails
        """
        html_body = ""
        text_body = ""
        files = {}
        count = 0

        if not msg.is_multipart():
            # Not an attachment!
            # See where this belong - text_body or html_body
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                text_body += msg.get_payload(decode=True)
            elif content_type == "text/html":
                html_body += msg.get_payload(decode=True)

            return text_body, html_body, 1

        # This IS a multipart message.
        # So, we iterate over it and call extract_content() recursively for
        # each part.
        for part_msg in msg.get_payload():
            # part is a new Message object which goes back to extract_content
            part_text_body, part_html_body, part_count = SiemplifyUtilitiesManager.extract_content(
                part_msg)
            text_body += part_text_body
            html_body += part_html_body
            count += part_count

        return text_body, html_body, count

    @staticmethod
    def extract_attachments(msg):
        """
        Get attachment name and content from eml
        :param msg: {email.Message} The msg to extract attachments from
        :return: {dict} attachment name and his content
        """
        attachments = msg.get_payload()
        attachments_dict = {}

        for attachment in attachments:
            # Extract filename from attachment
            filename = attachment.get_filename()
            # Some emails can return an empty attachment
            # possibly if there are a signature.
            # Validate that the attachment has a filename
            if filename:
                # Handle 'UTF-8' issues
                fname, charset = decode_header(filename)[0]
                if charset:
                    filename = fname.decode(charset)
                # Get attachment content
                file_content = attachment.get_payload(decode=True)
                attachments_dict.update({filename: base64.b64encode(file_content)})

        return attachments_dict

    @staticmethod
    def form_query(field, operator, values, add_single_quotes=False, add_double_quotes=False):
        """
        Form query string from given parameters.
        :param field: {string} Query target field(SrcIP, DestHost, exc..).
        :param operator: {string} Query operator(OR, AND, exc..)
        :param values: {string} Target values(Comma separated).
        :return: {string} Query string.
        """
        if add_single_quotes and add_double_quotes:
            query_items = [QUERY_PARAMETER_SINGLE_AND_DOUBLE_QUOTE_VALUE_FORMAT.format(field, value) for value in
                           values]
        elif add_single_quotes:
            query_items = [QUERY_PARAMETER_SINGLE_QUOTE_VALUE_FORMAT.format(field, value) for value in values]
        elif add_double_quotes:
            query_items = [QUERY_PARAMETER_DOUBLE_QUOTE_VALUE_FORMAT.format(field, value) for value in values]
        else:
            query_items = [QUERY_PARAMETER_VALUE_FORMAT.format(field, value) for value in values]
        return unicode(QUERY_OPERATOR_FORMAT.format(operator).join(query_items)).encode('utf-8')

    @staticmethod
    def intersect_lists(first_list, second_list):
        """
        Intersect two lists.
        :param first_list: {list} First list to intersect.
        :param second_list: {list} Second list to intersect.
        :return: {list} Intersected list.
        """
        return [x for x in first_list if x in second_list]

    @staticmethod
    def union_lists(first_list, second_list):
        """
        Union two lists.
        :param first_list: {list} First list to union.
        :param second_list: {list} Second list to union.
        :return: {list} United list.
        """
        return list(set().union(first_list, second_list))

    @staticmethod
    def subtract_lists(first_list, second_list):
        """
        Subtract two lists.
        :param first_list: {list} First list to subtract.
        :param second_list: {list} Second list to subtract.
        :return: {list} Subtracted list.
        """
        return [item for item in first_list if item not in second_list]

    @staticmethod
    def xor_lists(first_list, second_list):
        """
        Xor two lists.
        :param first_list: {list} First list operate.
        :param second_list: {list} Second list to operate.
        :return: {list} Subtracted list.
        """
        return list(set(first_list) ^ set(second_list))

    @staticmethod
    def get_operator_fn(op):
        """
        Get the operator function matching a given operator
        :param op: {str} The operator
        :return: {function} The operator function matching the given op
        """
        return {
            '>': operator.gt,
            '>=': operator.ge,
            '<': operator.lt,
            '<=': operator.le,
            '=': operator.eq,
            '!=': operator.neg,
            'in': operator.contains,
            'not in': lambda a, b: a not in b
        }[op]

    @staticmethod
    def find_values_in_dict(json_dict, path):
        """
        Find values in a dict by a given path
        :param json_dict: {dict} The json dict to search in
        :param path: {str} The path to the values
        :return: {list} The found values
        """
        if not path:
            return [json_dict]

        if not "." in path and json_dict.get(path):
            return json_dict.get(path) if isinstance(json_dict.get(path),
                                                     list) else [
                json_dict.get(path)]

        key = path.split(".", 1)[0]

        if key == "*" or key == "**":
            results = []
            for item in json_dict.values():
                if isinstance(item, list):
                    for element in item:
                        results.extend(
                            SiemplifyUtilitiesManager.find_values_in_dict(
                                element,
                                path.split(".", 1)[
                                    1]))

                elif not isinstance(item, dict):
                    continue

                else:
                    results.extend(
                        SiemplifyUtilitiesManager.find_values_in_dict(item,
                                                                      path.split(
                                                                          ".", 1)[
                                                                          1]))
            return results

        value = json_dict.get(key)

        if not isinstance(json_dict.get(key), dict) and not isinstance(
                json_dict.get(key), list):
            # If the value is not a list or a dict - this branch doesn't match the given path.
            return []

        if isinstance(value, dict):
            # Check if the current branch contains a matching value of the filter
            return SiemplifyUtilitiesManager.find_values_in_dict(value,
                                                                 path.split(
                                                                     ".", 1)[
                                                                     1])

        elif isinstance(value, list):
            results = []
            # Iterate the items in the current list
            for item in value:
                # Check if the current item is not a list or a dict
                if not isinstance(json_dict.get(key), dict) and not isinstance(
                        json_dict.get(key), list):
                    # The current branch doesn't match the given path
                    continue

                results.extend(
                    SiemplifyUtilitiesManager.find_values_in_dict(item,
                                                                  path.split(
                                                                      ".", 1)[
                                                                      1]))

            return results

    @staticmethod
    def filter_json(json_dict, path, operator, condition_value):
        """
        Filter a json dict by path, operator and condition value
        :param json_dict: {dict} The dict to filter
        :param path: {str} The path in the dict to the value ot filter by
        :param operator: {str} The operator of the condition
        :param condition_value: The value of the condition
        :return: {dict} The filtered dict (new instance of a dict)
        """
        temp_dict = copy.deepcopy(json_dict)

        if not SiemplifyUtilitiesManager.find_values_in_dict(temp_dict, path):
            return {}

        SiemplifyUtilitiesManager.recursive_filter_json(temp_dict, path,
                                                        operator,
                                                        condition_value)
        return temp_dict

    @staticmethod
    def recursive_filter_json(json_dict, path, operator, condition_value,
                              delete_non_matching=True):
        """
        Filter a json dict by path, operator and condition value
        :param json_dict: {dict} The dict to filter
        :param path: {str} The path in the dict to the value ot filter by
        :param operator: {str} The operator of the condition
        :param condition_value: The value of the condition
        :param delete_non_matching: Whether to delete non matching branches ot not
        :return: {bool} Whether the current branch is matching the filter
        """
        if not "." in path:
            # Reached the end of the given branch - check condition on value
            # If the value at the end of the path is a dict or list - return False
            if isinstance(json_dict.get(path), dict) or isinstance(
                    json_dict.get(path), list) or not json_dict.get(path):
                return False

            if operator == "*": return True

            # Check if the condition is true
            # The condition will be done on str to prevent type comparison problems
            return SiemplifyUtilitiesManager.get_operator_fn(operator)(
                str(json_dict.get(path)),
                str(condition_value))

        # Get the key of the dict at the current level in the path
        key = path.split(".", 1)[0]

        if key == "*":
            is_match = False
            # Check if the current branch contains a matching value of the filter
            for item_key, item in json_dict.items():
                if isinstance(item, list):
                    # Handle a list - for each item check if there is a match
                    valid_sub_branches = []
                    for element in item:
                        is_match = SiemplifyUtilitiesManager.recursive_filter_json(
                            element,
                            path.split(".", 1)[1],
                            operator,
                            condition_value)

                        if is_match or not delete_non_matching:
                            valid_sub_branches.append(element)

                    if valid_sub_branches:
                        # There are items in the list that match the filter - remove all
                        # the items from the list that doesn't match.
                        json_dict[item_key] = valid_sub_branches
                        is_match = True

                elif not isinstance(item,
                                    dict) or not SiemplifyUtilitiesManager.recursive_filter_json(
                    item, path.split(".", 1)[1], operator,
                    condition_value):
                    # Not a match - delete the item
                    del json_dict[item_key]
                else:
                    is_match = True

            return is_match

        elif key == "**":
            is_match = False
            # Check if the current branch contains a matching value of the filter
            for item_key, item in json_dict.items():
                # Handle a list - for each item check if there is a match
                if isinstance(item, list):
                    valid_sub_branches = []

                    for element in item:
                        is_match = SiemplifyUtilitiesManager.recursive_filter_json(
                            element,
                            path.split(".", 1)[1],
                            operator,
                            condition_value
                        )

                        if is_match or not delete_non_matching:
                            valid_sub_branches.append(element)

                    if valid_sub_branches:
                        # There are items in the list that match the filter - remove all
                        # the items from the list that doesn't match.
                        json_dict[item_key] = valid_sub_branches
                        is_match = True

                    else:
                        json_dict[item_key] = []

                elif isinstance(item, dict) and \
                        SiemplifyUtilitiesManager.recursive_filter_json(
                            item,
                            path.split(".", 1)[1],
                            operator,
                            condition_value
                        ):
                    is_match = True

                if not json_dict[item_key]:
                    # No matching sub branches were found - delete the entire tree
                    # from current level
                    del json_dict[item_key]

            if not is_match:
                # NO match found - remove the branch
                for key_to_delete in json_dict.keys():
                    del json_dict[key_to_delete]

            return is_match

        # Get the value at the current level
        value = json_dict.get(key)

        if not isinstance(json_dict.get(key), dict) and not isinstance(
                json_dict.get(key), list):
            # If the value is not a list or a dict - this branch doesn't match the given path.
            return False

        if isinstance(value, dict):
            # Check if the current branch contains a matching value of the filter
            is_match = SiemplifyUtilitiesManager.recursive_filter_json(value,
                                                                       path.split(
                                                                           ".",
                                                                           1)[
                                                                           1],
                                                                       operator,
                                                                       condition_value)

            if not is_match:
                # The current branch doesn't match the filter - remove it from the json dict
                if delete_non_matching:
                    del json_dict[key]
                return False

            # The current branch is valid
            return True

        elif isinstance(value, list):
            valid_sub_branches = []
            # Iterate the items in the current list
            for item in value:
                # Check if the current item is not a list or a dict
                if not isinstance(item, dict) and not isinstance(item, list):
                    # The current branch doesn't match the given path
                    continue

                # Check if the current branch contains a matching value of the filter
                is_match = SiemplifyUtilitiesManager.recursive_filter_json(
                    item, path.split(".", 1)[1],
                    operator,
                    condition_value)

                if is_match or not delete_non_matching:
                    valid_sub_branches.append(item)

            if valid_sub_branches:
                # There are items in the list that match the filter - remove all
                # the items from the list that doesn't match.
                json_dict[key] = valid_sub_branches
                return True
            else:
                del json_dict[key]
            # No items match the filter - remove the current list from the json dict
            return False

    @staticmethod
    def remove_item_from_list_by_value(target_list, value):
        """
        Remove items from list if they are uqual to the value.
        :param target_list: {list} List to remove the value from.
        :param value: {any type} Value to remove from list.
        :return: {list} Result list.
        """
        return [x for x in target_list if x != value]

    @staticmethod
    def get_value_for_nested_key(dict_obj, keys_list, wild_card_value=None):
        """
        Get value from from dict by a nested key.
        :param dict_obj: {dict} Dictionary object.
        :param keys_list: {list} List of keys which represent a nested key.
        :param wild_card_value: {string} A wild card sign.
        :return: {any type} Target value.
        """
        for key in keys_list:
            if isinstance(dict_obj, dict):
                if wild_card_value and key == wild_card_value:
                    dict_obj = dict_obj.values()[0]
                else:
                    dict_obj = dict_obj.get(key)
            else:
                return None
        return dict_obj

    @staticmethod
    def add_value_to_a_nested_key(dict_obj, keys_list, new_value, wild_card_value=None):
        """
        Add value to a nested key.
        :param dict_obj: {dict} Dictionary object.
        :param keys_list: {list} List of keys which represent a nested key.
        :param new_value: {any type} Target value can be any type.
        :param wild_card_value: {string} A wild card sign.
        :return: {dict} Result dictionary.
        """
        target_element = dict_obj
        for key in keys_list[:-1]:
            if wild_card_value and key == wild_card_value:
                target_element = target_element.values()[0]
            else:
                target_element = target_element.get(key)
        target_element[keys_list[-1]] = new_value
        return dict_obj

    @classmethod
    def fetch_branches_from_dict(cls, dict_obj, keys_list, wild_card_value=None):
        """
        Fetch all branches from dict by specific nested key.
        :param dict_obj: {dict} Dictionary object.
        :param keys_list: {list} List of keys which represent a nested key.
        :param wild_card_value: {string} A wild card sign.
        :return: {list} List of relevant branches.
        """
        # Avoid by reference mistakes.
        local_key_list = copy.deepcopy(keys_list)
        branches = []
        keys_passes = []
        while local_key_list:
            new_branches = []
            keys_passes.append(local_key_list[0])
            current_key = local_key_list.pop(0)
            if not branches:
                branch = copy.deepcopy(dict_obj)
                if isinstance(branch, list):
                    for item in branch:
                        branches.append(item)
                else:
                    branches.append(branch)

            for index, branch in enumerate(branches):
                if wild_card_value and current_key == wild_card_value:
                    branches = cls.remove_item_from_list_by_value(branches, branch)
                    nested_value = cls.get_value_for_nested_key(branch, keys_passes[:-1], wild_card_value)
                    for key, val in nested_value.items():
                        new_branches.append(
                            cls.add_value_to_a_nested_key(copy.deepcopy(branch), keys_passes[:-1], {key: val}))

                elif isinstance(cls.get_value_for_nested_key(branch, keys_passes, wild_card_value), list):
                    branches = cls.remove_item_from_list_by_value(branches, branch)
                    nested_value = cls.get_value_for_nested_key(branch, keys_passes, wild_card_value)
                    for item in nested_value:
                        new_branches.append(cls.add_value_to_a_nested_key(copy.deepcopy(branch), keys_passes, item,
                                                                          wild_card_value))
            branches.extend(new_branches)

        # Filter unnecessary branches.
        for branch in branches:
            if not cls.get_value_for_nested_key(branch, keys_passes, wild_card_value):
                branches = cls.remove_item_from_list_by_value(branches, branch)

        return branches

    @classmethod
    def sort_list_of_dicts_by_nested_key(cls, dicts_list, nested_key, field_type, reverse=True, wild_card_value=None):
        """
        Sort list of dictionaries by nested key.
        :param dicts_list: {dict} list of dictionaries.
        :param nested_key: {string} Nested keys point separated, EXM: key.in_key.in_in_key
        :param field_type: {string} The type of the field to sort by.
        :param reverse: Reverse results order {bool}
        :param wild_card_value: {string} A wild card sign.
        :return: {list} list of sorted dicts.
        """
        if field_type in [STRING_FIELD_TYPE, NUMBER_FIELD_TYPE]:
            return sorted(dicts_list, key=lambda k: cls.get_value_for_nested_key(k, nested_key, wild_card_value),
                          reverse=reverse)
        elif field_type == DATE_FIELD_TYPE:
            return sorted(dicts_list, key=lambda k: arrow.get(
                cls.get_value_for_nested_key(k, nested_key, wild_card_value)).datetime, reverse=reverse)
        raise SiemplifyUtilitiesManagerError('Failed sorting dict, Error: Invalid Field Type, '
                                             'must be number,string or date.')

    @classmethod
    def extract_ioc_document_from_search_term(cls, search_term):
        """
        Extract ioc document from a search term
        :param search_term: {str or [str]} IOC search term
        :return: {str or [str]} Extracted IOC document
        """
        if isinstance(search_term, unicode):
            return search_term.split(u"/")[0]
        elif isinstance(search_term, list):
            return [term.split(u"/")[0] for term in search_term]
