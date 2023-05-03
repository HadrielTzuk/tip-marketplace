# ============================================================================#
# title           :RSAArcherManager.py
# description     :This Module contain all RSAArcher operations functionality
# author          :avital@siemplify.co
# date            :13-09-2018
# python_version  :2.7
# libreries       :requests, xmltodict
# requirments     :
# product_version :6.0+
# ============================================================================#

# Documentation:
# XML (but very useful): http://pncapifestwiki.eastus2.cloudapp.azure.com/apifest-wiki/dokuwiki/lib/exe/fetch.php?media=rsa_archer_6_web_services_api_reference_guide.pdf
# REST API: http://pncapifestwiki.eastus2.cloudapp.azure.com/apifest-wiki/dokuwiki/lib/exe/fetch.php?media=rsa_archer_6_rest_api_reference_guide.pdf



# ============================= IMPORTS ===================================== #

import requests
import xmltodict
from RSAArcherParser import RSAArcherParser
from UtilsManager import filter_old_alerts, read_configs, write_configs
import json
import os
from datetime import datetime
from constants import DEFAULT_LIMIT, DATE_CREATED_FIELD_NAME, SECURITY_INCIDENTS_APP_NAME, SECURITY_ALERT, SECURITY_EVENT
from SiemplifyUtils import unix_now

# ============================== CONSTS ===================================== #

HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
}

XML_HEADERS = {
    'Accept': 'text/xml',
    'Content-Type': 'text/xml'
}

DEFAULT_APP_NAME = u'Incidents'
SECURITY_INCIDENTS_APP_ID = 75
TEXT_FIELD_TYPE = 1
LIST_FIELD_TYPE = 4
USER_GROUP_LIST_FIELD_TYPE = 8
CROSS_REFERENCE_FIELD_TYPE = 9

# ============================= CLASSES ===================================== #


class RSAArcherManagerError(Exception):
    """
    General Exception for RSAArcher manager
    """
    pass

class SecurityIncidentDoesntExistError(RSAArcherManagerError):
    """
    Security Incident doesn't exist
    """
    pass

class InvalidArgumentsError(RSAArcherManagerError):
    pass


class NotFoundApplicationError(RSAArcherManagerError):
    pass


class RSAArcherManager(object):
    """
    RSAArcher Manager
    """
    def __init__(self, api_root, username, password, instance_name, verify_ssl=False, siemplify_logger=None,
                 siemplify=None):
        self.api_root = api_root
        self.json_session = requests.Session()
        self.json_session.verify = verify_ssl
        self.json_session.headers = HEADERS

        self.xml_session = requests.Session()
        self.xml_session.verify = verify_ssl
        self.xml_session.headers = XML_HEADERS

        self.token = self.get_token(
            username,
            password,
            instance_name
        )

        self.json_session.headers.update({
            'Authorization': "Archer session-id={}".format(self.token),
        })

        self.xml_session.headers.update({
            'Authorization': "Archer session-id=\"{}\"".format(self.token),
        })

        self.parser = RSAArcherParser()
        self.siemplify_logger = siemplify_logger
        self.siemplify = siemplify

    def get_token(self, username, password, instance_name):
        """
        Get a token
        :param username: {str} The username
        :param password: {str} The password
        :param instance_name: {str} The instance name
        :return: {str} The session token
        """
        url = "{}/api/core/security/login".format(self.api_root)
        response = self.json_session.post(url, json={
            'InstanceName': instance_name,
            'Username': username,
            'Password': password,
            'UserDomain': ""
        })
        self.validate_response(response, "Unable to get token")
        return response.json()["RequestedObject"]["SessionToken"]

    def logout(self):
        """
        Logout from Archer
        :return: {bool} True if successful, exception otherwise.
        """
        url = "{}/api/core/security/logout".format(self.api_root)
        response = self.json_session.post(url, json={
            'Value': self.token
        })
        self.validate_response(response, "Unable to logout")
        return True

    def get_app_by_name(self, app_name=DEFAULT_APP_NAME):
        """
        Fetch the Internal ID of the specified app
        :param app_name: {str} The name of the application
        :return: {int} Id of the application
        """
        url = "{}/api/core/system/application?$filter=Name eq \'{}\'".format(self.api_root, app_name)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get app id")
        return self.parser.build_application_object(raw_json=response.json())

    def create_incident(self, title, description, status, owner, priority, category, custom_fields, app_name,
                        map_file_path, remote_file):
        """
        Create an incident
        :param title: {str} The incident summary (incident title)
        :param description: {str} The incident description (incident details)
        :param status: {str} The incident status
        :param owner: {str} The username of the incident's owner
        :param priority: {str} The priority of the incident
        :param category: {str} The incident's category
        :param custom_fields: {dict} Dictionary of custom fields
        :param app_name: {str} The name of the application
        :param map_file_path: {str} Mapping File path
        :param remote_file: {bool} Indicates whether the map file path is a url
        :return: {int} The content ID of the created incident.
        """
        url = "{}/api/core/content".format(self.api_root)

        app = self.get_app_by_name(app_name=app_name)
        if not app:
            raise NotFoundApplicationError(u"Action wasn't able to create a new incident. Reason: {} application "
                                           u"was not found.".format(app_name))

        levels = self.get_levels_for_application_id(app.id)

        if not levels:
            raise RSAArcherManagerError(u"No levels found for application {}".format(app.id))

        level = levels[0]

        payload = {
            "Content": {
                "LevelId": level["Id"],
                "FieldContents": self.construct_content(title=title,
                                                        description=description,
                                                        status=status,
                                                        priority=priority,
                                                        owner=owner,
                                                        category=category,
                                                        custom_fields=custom_fields,
                                                        app_id=app.id,
                                                        map_file_path=map_file_path,
                                                        remote_file=remote_file)
            }
        }

        response = self.json_session.post(url, json=payload)
        self.validate_response(response, "Unable to create record")

        return response.json()["RequestedObject"]["Id"], app.alias

    def update_incident(self, content_id, title=None, description=None, status=None, owner=None, priority=None,
                        category=None, custom_fields=None, app_name=None, map_file_path=None, remote_file=False):
        """
        Update an incident
        :param content_id: {str} The content ID of the incident
        :param title: {str} The incident summary (incident title)
        :param description: {str} The incident description (incident details)
        :param status: {str} The incident status
        :param owner: {str} The username of the incident's owner
        :param priority: {str} The priority of the incident
        :param category: {str} The incident's category
        :param custom_fields: {dict} Dictionary of custom fields
        :param app_name: {str} The name of the application
        :param map_file_path: {str} Mapping File path
        :param remote_file: {bool} Indicates whether the map file path is a url
        :return: {bool} Tru if successful, exception otherwise.
        """
        url = "{}/api/core/content".format(self.api_root)

        app = self.get_app_by_name(app_name=app_name)
        if not app:
            raise NotFoundApplicationError(u"Action wasn't able to update the incident. Reason: {} application "
                                           u"was not found.".format(app_name))

        levels = self.get_levels_for_application_id(app.id)

        if not levels:
            raise RSAArcherManagerError(
                "No levels found for application {}".format(
                    app.id))

        level = levels[0]

        payload = {
            "Content": {
                'Id': content_id,
                "LevelId": level["Id"],
                "FieldContents": self.construct_content(title=title,
                                                        description=description,
                                                        status=status,
                                                        priority=priority,
                                                        owner=owner,
                                                        category=category,
                                                        custom_fields=custom_fields,
                                                        app_id=app.id,
                                                        map_file_path=map_file_path,
                                                        remote_file=remote_file),
                'SubformFieldId': content_id
            }
        }

        response = self.json_session.put(url, json=payload)
        self.validate_response(response, "Unable to update record"), app.alias

        return app.alias

    def get_incident_by_id(self, incident_id, alias, check_content=False):
        """
        Get Incident details
        :param incident_id: The id of the incident
        :param alias: The alias of current app
        :param check_content: If true, will check for errors during validation
        :return: Incident Json
        """
        request_url = "{}/contentapi/{}({})".format(self.api_root, alias, incident_id)
        response = self.json_session.get(request_url)
        try:
            self.validate_response(response=response, error_msg="Unable to get Incident details", check_content=check_content)
        except Exception as e:
            if response.status_code == 404:
                raise RSAArcherManagerError(u"Action wasn't able to return information about the incident with ID {0} "
                                            u"in RSA Archer. Reason: Incident with ID {0} was not found.".
                                            format(incident_id))
            raise Exception(e)
        return self.parser.build_incident_object(raw_json=response.json())

    def get_levels_for_application_id(self, application_id):
        """
        Get levels of a given application
        :param application_id: {int} The application id
        :return: {list} The application's levels
        """
        url = "{}/api/core/system/level/module/{}".format(self.api_root,
                                                          application_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get levels for application {}".format(application_id))

        # Results are a list of dicts, each dict's real data is in
        # "RequestedObject" field
        return [level["RequestedObject"] for level in response.json()]

    def get_all_levels(self):
        """
        Get all available levels
        :return: {list} The found levels
        """
        url = "{}/api/core/system/level".format(self.api_root)
        response = self.json_session.get(url)
        self.validate_response(response,
                               "Unable to get levels")

        return [level["RequestedObject"] for level in response.json()]

    def create_mapping_name_to_field_id(self, levels):
        """
        Create a mapping between the field names to field types and ids of fields of given levels
        :param levels: {list} The levels to map fields from
        :return: {dict} The fields map
        """
        mappings = {}

        for level in levels:
            url = "{}/api/core/system/fielddefinition/level/{}".format(self.api_root, level)
            response = self.json_session.get(url)

            self.validate_response(response,
                                   "Unable to create mapping to levels")

            # If single - response.json() is a dict, otherwise is a list.
            fields_level_info = response.json() if isinstance(response.json(), list) else [response.json()]

            for field in fields_level_info:
                mappings[field["RequestedObject"]["Name"]] = {
                    "Type": field["RequestedObject"]["Type"],
                    "Id": field["RequestedObject"]["Id"],
                    "level": level
                }

        return mappings

    def construct_content(self, title=None, description=None, status=None, priority=None, owner=None, category=None,
                          custom_fields=None, app_id=None, map_file_path=None, remote_file=False):
        """
        Construct a payload for incidents creation / update
        :param title: {str} The incident summary (incident title)
        :param description: {str} The incident description (incident details)
        :param status: {str} The incident status
        :param owner: {str} The username of the incident's owner
        :param priority: {str} The priority of the incident
        :param category: {str} The incident's category
        :param custom_fields: {dict} Dictionary of custom fields
        :param app_id: {int} Id of the application
        :param map_file_path: {str} Mapping File path
        :param remote_file: {bool} Indicates whether the map file path is a url
        :return: {dict} The constructed payload
        """
        levels = self.get_levels_for_application_id(app_id)
        mapping = self.create_mapping_name_to_field_id([level["Id"] for level in levels])

        content = {}

        # Each field type has its own payload structure. See XML docs above
        # for more details.
        if priority:
            content.update({mapping["Priority"]["Id"]: {
                'Type': LIST_FIELD_TYPE,
                'FieldId': mapping["Priority"]["Id"],
                'Value': {
                    'ValuesListIds': [self.get_option_id_by_name(priority, mapping["Priority"]["Id"])],
                    'OtherText': None
                }
            }})

        if title:
            content.update({mapping["Incident Summary"]["Id"]: {
                'Type': TEXT_FIELD_TYPE,
                'FieldId': mapping["Incident Summary"]["Id"],
                'Value': title
            }})

        if description:
            content.update({mapping["Incident Details"]["Id"]: {
                'Type': TEXT_FIELD_TYPE,
                'FieldId': mapping["Incident Details"]["Id"],
                'Value': description
            }})

        if category:
            content.update({mapping["Category"]["Id"]: {
                'Type': LIST_FIELD_TYPE,
                'FieldId': mapping["Category"]["Id"],
                'Value': {
                    'ValuesListIds': [self.get_option_id_by_name(category, mapping["Category"]["Id"])],
                    'OtherText': None
                }
            }})

        if status:
            content.update({mapping["Incident Status"]["Id"]: {
                'Type': LIST_FIELD_TYPE,
                'FieldId': mapping["Incident Status"]["Id"],
                'Value': {
                    'ValuesListIds': [self.get_option_id_by_name(status, mapping["Incident Status"]["Id"])],
                    'OtherText': None
                }
            }})

        if owner:
            content.update({mapping["Incident Owner"]["Id"]: {
                'Type': USER_GROUP_LIST_FIELD_TYPE,
                'FieldId': mapping["Incident Owner"]["Id"],
                'Value': {
                    'UserList': [
                        {
                            "ID": self.get_user_by_name(owner)["Id"]
                        }
                    ]
                }
            }})

        if custom_fields:
            for field, value in custom_fields.items():
                if field in mapping:
                    field_id = mapping.get(field, {}).get("Id")
                    value_type = mapping.get(field, {}).get("Type")
                    if value_type == LIST_FIELD_TYPE:
                        field_value = {
                            'ValuesListIds': [self.get_option_id_by_name(option_name=value, field_id=field_id,
                                                                         field_name=field)],
                            'OtherText': ""
                        }
                    elif value_type == USER_GROUP_LIST_FIELD_TYPE:
                        try:
                            field_value = {
                                'UserList': [
                                    {
                                        "ID": self.get_user_by_name(value).get("Id")
                                    }
                                ]
                            }
                        except Exception:
                            self.siemplify_logger.info("Specified user was not found, trying to find a group.")
                            field_value = {
                                'GroupList': [
                                    {
                                        "ID": self.get_group_by_name(value).get("Id")
                                    }
                                ]
                            }
                        
                    elif value_type == CROSS_REFERENCE_FIELD_TYPE:
                        content_value = self.map_custom_value(map_file_path=map_file_path, field_name=field,
                                                              field_value=value,
                                                              remote_file=remote_file) if map_file_path else None
                        content_id, level_id = self.get_custom_content_details(content_value=content_value) if \
                            content_value else self.get_reference_id_by_value(option_name=value, field_id=field_id,
                                                                              field_name=field)
                        field_value = [
                            {
                                "ContentId": content_id,
                                "LevelId": level_id
                            }
                        ]
                    else:
                        field_value = value
                    content.update({field_id: {
                        'Type': value_type,
                        'FieldId': field_id,
                        'Value': field_value
                    }})
                else:
                    raise InvalidArgumentsError(u"{} field was not found.".format(field))

        return content

    ########## PREPERATION FOR GENERIC CONTENT BUILDER #########
    # def create_fields_content(self, fields, mapping):
    #     content = {}
    #     for field_name, field_value in fields.items():
    #         if mapping.get(field_name):
    #             field_mapping = mapping.get(field_name)
    #
    #             if field_mapping.get("Type") == 1:
    #                 content[field_mapping.get("Id")] = self.create_field_content(1, field_mapping.get("Id"), field_value)
    #
    #             elif field_mapping.get("Type") == 2:
    #                 content[field_mapping.get("Id")] = self.create_field_content(2, field_mapping.get("Id"), field_value)
    #
    #             elif field_mapping.get("Type") == 3:
    #                 content[field_mapping.get("Id")] = self.create_field_content(3, field_mapping.get("Id"), field_value)
    #
    #             elif field_mapping.get("Type") == 19:
    #                 content[field_mapping.get("Id")] = self.create_field_content(19, field_mapping.get("Id"), field_value)
    #
    #             elif field_mapping.get("Type") == 4:
    #                 # field_value is a list
    #                 values_list = []
    #
    #                 available_values_of_field = self.get_available_values_of_field(field_mapping.get("Id"))
    #
    #                 if not isinstance(field_value, list):
    #                     field_value = [field_value]
    #
    #                 for value in field_value:
    #                     for available_value in available_values_of_field:
    #                         if available_value.get("Name") == value:
    #                             values_list.append(available_value.get('Id'))
    #
    #                 content[field_mapping.get("Id")] = self.create_field_content(
    #                     4, field_mapping.get("Id"), {
    #                         'ValuesListIds': values_list,
    #                         'OtherText': None}
    #                     )
    #
    # @staticmethod
    # def create_field_content(type, field_id, value):
    #     return {
    #         'Type': type,
    #         'FieldId': field_id,
    #         'Value': value
    #     }

    def load_mapping_json(self, map_file_path):
        """
        Getting custom mapping json
        :param map_file_path: {str} Mapping File path
        :return: {dict} Mapping file json
        """
        if os.path.isfile(map_file_path):
            try:
                with open(map_file_path, 'r') as map_file:
                    mapping = json.loads(map_file.read())
            except Exception as e:
                raise RSAArcherManagerError(u"Unable to read mapping file: {}".format(str(e)))
        else:
            raise RSAArcherManagerError(u"Mapping file doesn't exist")

        if not isinstance(mapping, dict):
            raise RSAArcherManagerError(u"Mapping file is not in valid format. Custom fields will not be mapped.")

        return mapping

    def map_custom_value(self, map_file_path, field_name, field_value, remote_file=False):
        """
        Map given field to custom value
        :param map_file_path: {str} Mapping File path
        :param field_name: {str} Name of the field to be mapped
        :param field_value: {str} Value of the field to be mapped
        :param remote_file: {bool} Indicates whether the map file path is a url
        :return: {str} Mapped value
        """
        if remote_file:
            try:
                response = self.json_session.get(map_file_path)
                response.raise_for_status()
                map_file_path = os.path.join(self.siemplify.run_folder, "custom_mapping_file.json")
                with open(map_file_path, 'w') as map_file:
                    map_file.write(json.dumps(json.loads(response.text)))
                    self.siemplify_logger.info(
                        u"Custom mapping file was saved at {}".format(map_file_path))
            except requests.HTTPError as error:
                raise RSAArcherManagerError(
                    "{error_msg}: {error} - {text}".format(
                        error_msg='An error occurred',
                        error=error,
                        text=error.response.content)
                )

        map_json = self.load_mapping_json(map_file_path)
        if map_json:
            type_dict = map_json.get(u'type_9', {})
            if type_dict:
                if type_dict.get(field_name):
                    if type_dict.get(field_name, {}).get(field_value):
                        return type_dict.get(field_name, {}).get(field_value)
                    else:
                        self.siemplify_logger.error(u"Mapping file does not contain key {}".format(field_value))
                else:
                    self.siemplify_logger.error(u"Mapping file does not contain field {}".format(field_name))
            else:
                self.siemplify_logger.error(u"Mapping file is not valid. Custom fields will not be mapped.")

    def get_custom_content_details(self, content_value):
        """
        Fetching field value with custom mapping
        :param content_value: {str} Name of the field to be mapped
        :return: {int, int} The id and level_id of the option
        """
        url = "{}/api/core/content/{}".format(self.api_root, content_value)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get content details")
        reference = self.parser.build_reference_object(raw_json=response.json())
        return reference.id, reference.level_id

    def get_all_users(self):
        """
        Get a list of values corresponding to a specific field id
        :return:
        """
        url = "{}/api/core/system/user".format(self.api_root)
        # Some methods required special headers. Add it here.
        self.json_session.headers.update(
            {'X-Http-Method-Override': 'GET'}
        )
        response = self.json_session.post(url)

        # Remove the header.
        self.json_session.headers.update(
            {'X-Http-Method-Override': None}
        )

        self.validate_response(response, "Unable to get users")

        return [level["RequestedObject"] for level in response.json()]
    
    def get_all_groups(self):
        """
        Function that fetches all the available groups in RSA
        :return: {List} List of groups will all the details
        """
        url = "{}/api/core/system/group/?$select=Id,Name,DisplayName".format(self.api_root)
        # Some methods required special headers. Add it here.
        self.json_session.headers.update(
            {'X-Http-Method-Override': 'GET'}
        )
        response = self.json_session.post(url)

        # Remove the header.
        self.json_session.headers.update(
            {'X-Http-Method-Override': None}
        )

        self.validate_response(response, "Unable to get groups")

        return [level["RequestedObject"] for level in response.json()]
    
    def get_group_by_name(self, name):
        """
        Function that gets group by name
        :param name: {string} Group Name
        :return: {dict} Dictionary containing matched Group
        """
        groups = self.get_all_groups()

        for group in groups:
            if group["DisplayName"].lower() == name.lower():
                return group

        raise InvalidArgumentsError(u"Username/Group {0} was not found.".format(name))


    def get_user_by_name(self, name):
        """
        GET user id by name
        :param name: {string}
        :return: 
        """
        users = self.get_all_users()

        for user in users:
            if user["DisplayName"].lower() == name.lower():
                return user

        raise InvalidArgumentsError(u"Username/Group {0} was not found.".format(name))

    def get_option_id_by_name(self, option_name, field_id, field_name=None):
        """
        Get an option id (from available values, like a select) by the option name, from a given field (by id)
        :param option_name: {str} The option name
        :param field_id: {str} The field ID
        :param field_name: {str} The custom field name
        :return: {int} The id of the option
        """
        options = self.get_available_values_of_field(field_id)
        if isinstance(options, dict):
            options = [options]

        for option in options:
            if option.get(u'Name', u'') == option_name:
                return option.get(u'Id')
            else:
                for sub_option in option.get(u'SelectDefValues', {}).get(u'SelectDefValue', []):
                    if sub_option.get(u'Name', u'') == option_name:
                        return sub_option.get(u'Id')

        if field_name:
            raise InvalidArgumentsError(u"{} field contains an invalid value.".format(field_name))
        else:
            raise RSAArcherManagerError(u"Option {} of field {} was not found".format(option_name, field_id))

    def get_reference_id_by_value(self, option_name, field_id, field_name):
        """
        Get a reference id (from available values, like a select) by the option name, from a given field (by id)
        :param option_name: {str} The option name
        :param field_id: {str} The field ID
        :param field_name: {str} The custom field name
        :return: {int, int} The id and level_id of the option
        """
        references = self.get_available_references_of_field(field_id)

        for reference in references:
            if reference.value == option_name:
                return reference.id, reference.level_id

        raise InvalidArgumentsError(u"{} field contains an invalid value.".format(field_name))

    def get_available_references_of_field(self, field_id):
        """
        Get a list of available reference values corresponding to a specific field id
        :param field_id: {int} The field ID
        :return: {[Reference]} The available references
        """
        url = "{}/api/core/content/referencefield/{}".format(self.api_root, field_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get references")
        return [self.parser.build_reference_object(raw_json=reference_data) for reference_data in response.json()]

    def get_available_values_of_field(self, field_id):
        """
        Get a list of available values corresponding to a specific field id
        :param field_id: {int} The field ID
        :return: {list} The available values
        """
        url = "{}/ws/field.asmx".format(self.api_root)
        soap_action = 'http://archer-tech.com/webservices/GetValueListForField'

        payload = """<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchemainstance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetValueListForField xmlns="http://archer-tech.com/webservices/"><sessionToken>{}</sessionToken><fieldId>{}</fieldId></GetValueListForField></soap:Body> </soap:Envelope>""".format(self.token, field_id)

        self.xml_session.headers.update({
            'SOAPAction': soap_action
        })

        response = self.xml_session.post(url, data=payload)

        self.validate_xml_response(response,
                               "Unable to get values for field {}".format(field_id))

        xml_results = xmltodict.parse(response.content, dict_constructor=dict)

        # The results are an xml string - parse it and get the actual results.
        results = xmltodict.parse(
            xml_results['soap:Envelope']['soap:Body']['GetValueListForFieldResponse']['GetValueListForFieldResult'],
            dict_constructor=dict
        )

        return results['SelectDef']['SelectDefValues']['SelectDefValue']

    def get_alerts(self, existing_ids, limit, start_timestamp, process_security_alerts, process_incident_journal,
                   time_format):
        """
        Get siemplify alerts
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for results
        :param start_timestamp: {int} The timestamp for oldest incident to fetch
        :param process_security_alerts: {bool} Specifies whether process Security Alerts related to the Security Incident or no
        :param process_incident_journal: {bool} Specifies whether process Incident Journal related to the Security Incident or no
        :param time_format: {str} Specifies time format for the searching of Security Incidents
        :return: {list} The list of filtered Alert objects.
        """
        security_incidents = self.get_security_incidents(existing_ids, limit, start_timestamp, time_format)
        incident_full_details = []
        devices = []

        for security_incident in security_incidents:
            self.siemplify_logger.info("Getting details for {} security incident".format(security_incident.content_id))
            security_incident_details = self.get_security_incident_details(security_incident.content_id)
            devices.extend(security_incident_details.get("Destination_Device__Enterprise_Managemen", []))
            devices.extend(security_incident_details.get("Source_Device__Enterprise_Management_Con", []))
            security_alerts_details, security_events_details, incident_journals_details = [], [], []

            if process_security_alerts:
                security_alerts_details, security_events_details, item_devices = self.process_security_alerts_or_events(
                    security_incident_details.get("Security_Alerts", [])
                )

                devices.extend(item_devices)

            if process_incident_journal:
                incident_journals_details = [self.get_incident_journal_details(incident_journal_id)
                                             for incident_journal_id in security_incident_details.get("Incident_Journal", [])]

            incident_full_details.append((
                security_incident_details,
                security_alerts_details,
                security_events_details,
                incident_journals_details
            ))

        devices_details = self.get_filtered_devices(devices) if devices else {}

        return [
            self.parser.build_alert_object(
                incident, security_alerts, security_events, journals, devices_details, self.siemplify_logger
            )
            for incident, security_alerts, security_events, journals in incident_full_details]

    def process_security_alerts_or_events(self, security_item_ids):
        """
        Process security alerts or security events
        :param security_item_ids: List of security item ids
        :return: {tuple} Raw data of security alerts details, raw data of security events details and list of destination and source devices
        """
        configs = read_configs(self.siemplify)
        security_alerts_details, security_events_details, item_devices = [], [], []

        if configs.get("security_alert_application") == SECURITY_ALERT:
            security_alerts_details, item_devices = self.process_security_alerts(security_item_ids)
        elif configs.get("security_alert_application") == SECURITY_EVENT:
            security_events_details, item_devices = self.process_security_events(security_item_ids)
        else:
            try:
                security_alerts_details, item_devices = self.process_security_alerts(security_item_ids)
                configs["security_alert_application"] = SECURITY_ALERT
            except Exception:
                security_events_details, item_devices = self.process_security_events(security_item_ids)
                configs["security_alert_application"] = SECURITY_EVENT

            write_configs(self.siemplify, configs)

        return security_alerts_details, security_events_details, item_devices

    def process_security_alerts(self, security_alert_ids):
        """
        Get security alerts details and process the devices
        :param security_alert_ids: List of security alert ids
        :return: {tuple} Raw data of security alerts details and list of destination and source devices
        """
        security_alerts_details = []
        devices = []

        for security_alert_id in security_alert_ids:
            security_alert_details = self.get_security_alert_details(security_alert_id)
            security_alerts_details.append(security_alert_details)
            devices.extend(security_alert_details.get("Destination_Device", []))
            devices.extend(security_alert_details.get("Source_Device", []))

        return security_alerts_details, devices

    def process_security_events(self, security_event_ids):
        """
        Get security events details and process the devices
        :param security_event_ids: List of security event ids
        :return: {tuple} Raw data of security events details and list of destination and source devices
        """
        security_events_details = []
        devices = []

        for security_event_id in security_event_ids:
            security_event_details = self.get_security_event_details(security_event_id)
            security_events_details.append(security_event_details)
            devices.extend(security_event_details.get("Destination_Device_Enterprise_Management", []))
            devices.extend(security_event_details.get("Source_Device__Enterprise_Management_Con", []))

        return security_events_details, devices

    def get_paginated_security_incidents(self, application_id, date_created_field_id, limit, start_timestamp,
                                         time_format, page_number=1):
        """
        Get security incidents per page
        :param application_id: {int} The application id
        :param date_created_field_id: {int} The date_created field id
        :param limit: {int} The limit for results
        :param start_timestamp: {int} The timestamp for oldest incident to fetch
        :param time_format: {str} Specifies time format for the searching of Security Incidents
        :param page_number: {int} The page number
        :return: {list} The list of filtered SecurityIncident objects.
        """
        url = u"{}/ws/search.asmx".format(self.api_root)
        payload = """<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ExecuteSearch xmlns="http://archer-tech.com/webservices/"><sessionToken>{token}</sessionToken><searchOptions><![CDATA[<SearchReport><PageSize>{limit}</PageSize><DisplayFields><DisplayField name="Date_Created">{date_created_field_id}</DisplayField></DisplayFields><Criteria><Filter><Conditions><DateRangeFilterCondition><Operator>Between</Operator><Field>{date_created_field_id}</Field><BeginValue>{start_time}</BeginValue><EndValue>{end_time}</EndValue><TimeZoneId>{timezone}</TimeZoneId><IsTimeIncluded>TRUE</IsTimeIncluded></DateRangeFilterCondition></Conditions></Filter><ModuleCriteria><Module>{application_id}</Module><SortFields><SortField><Field>{date_created_field_id}</Field><SortType>Ascending</SortType></SortField></SortFields></ModuleCriteria></Criteria></SearchReport> ]]></searchOptions><pageNumber>{page_number}</pageNumber></ExecuteSearch></soap:Body></soap:Envelope>""" \
            .format(
                token=self.token,
                limit=max(limit, DEFAULT_LIMIT),
                start_time=self.build_date_filter(start_timestamp, time_format),
                end_time=self.build_date_filter(unix_now(), time_format),
                timezone="UTC",
                application_id=application_id,
                date_created_field_id=date_created_field_id,
                page_number=page_number
            )

        response = self.xml_session.post(url, data=payload)
        self.validate_xml_response(response, u"Unable to get security incidents")
        xml_content = xmltodict.parse(response.content, dict_constructor=dict)
        xml_results = xml_content.get(u"soap:Envelope", {}).get(u"soap:Body", {}).get(u"ExecuteSearchResponse", {}) \
            .get(u"ExecuteSearchResult", "")

        # The results are an xml string - parse it and get the actual results.
        results = xmltodict.parse(xml_results, dict_constructor=dict) if xml_results else {}
        return self.parser.build_security_incident_objects(results)

    def get_security_incidents(self, existing_ids, limit, start_timestamp, time_format):
        """
        Get security incidents
        :param existing_ids: {list} The list of existing ids
        :param limit: {int} The limit for results
        :param start_timestamp: {int} The timestamp for oldest incident to fetch
        :param time_format: {str} Specifies time format for the searching of Security Incidents
        :return: {list} The list of filtered SecurityIncident objects
        """
        application_id, date_created_field_id = self.get_app_configs()
        page_number = 1
        results = self.get_paginated_security_incidents(application_id, date_created_field_id, limit, start_timestamp,
                                                        time_format, page_number)
        filtered_security_incidents = filter_old_alerts(self.siemplify_logger, results, existing_ids, u"content_id")

        while len(filtered_security_incidents) < max(limit, DEFAULT_LIMIT):
            page_number += 1
            current_results = self.get_paginated_security_incidents(application_id, date_created_field_id, limit,
                                                                    start_timestamp, time_format, page_number)

            if not current_results:
                break

            results.extend(current_results)
            filtered_security_incidents = filter_old_alerts(self.siemplify_logger, results, existing_ids, u"content_id")

        self.siemplify_logger.info("Found {} security incidents with ids - {}".format(
            len(filtered_security_incidents), ",".join([str(incident.content_id) for incident in filtered_security_incidents])
        ))
        return filtered_security_incidents

    def build_date_filter(self, timestamp, time_format):
        """
        Build date filter by specified format
        :param timestamp: {int} The timestamp
        :param time_format: {str} The time format
        :return: {str} The date in the specified format
        """
        return datetime.fromtimestamp(timestamp / 1000).strftime(time_format)

    def get_security_incident_details(self, incident_id):
        """
        Get incident details by id
        :param incident_id: The incident id
        :return: {dict} The raw data of incident details
        """
        url = u"{}/contentapi/Security_Incidents({})".format(self.api_root, incident_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get {} incident details".format(incident_id), check_content=False)
        return response.json()

    def get_incident_journal_app_id(self):
        """
        Funtion that gets the Incident Journal application ID 
        :return: {str} application_id
        """
        url = u"{}/api/core/system/application".format(self.api_root)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get incident journal app id.", check_content=False)

        return self.parser.get_application_id(response.json())

    def get_security_incident_id(self, application_id):
        """
        Funtion that gets the details related to the security indident for given application
        :param application_id: {str} Application ID
        :return: {dict} Request details
        """
        url = u"{}/api/core/system/fielddefinition/application/{}".format(self.api_root, application_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get a security incident ID for application with ID: {} ".format(application_id), check_content=False)

        return self.parser.get_security_incident_id(response.json())
    
    def get_security_incident_level(self):
        """
        Funtion that gets the security incident level id
        :return: {str} Security Incident Level
        """
        url = u"{}/api/core/system/level".format(self.api_root)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get a security incident field ID.", check_content=False)

        return self.parser.get_security_incident_level(response.json())    

    def add_journal_entry(self, destination_content_id, text, request_details):
        """
        Funtion that adds journal entry to an incident
        :param destination_content_id: {str} The incident id
        :param text: {str} Text to add
        :param request_details: {str} Details for the request
        :return: {dict} 
        """
        url = u"{}/api/core/content".format(self.api_root)
        payload = {
            "Content": {
                "LevelId": request_details["level_id"],
                "FieldContents": {
                    request_details["security_incident_id"]: {
                        "Type": 9,
                        "Value": [
                            {
                                "ContentId": destination_content_id,
                                "LevelId": request_details["security_incident_level_id"]
                            }
                        ],
                        "FieldId": request_details["security_incident_id"]
                    },
                    request_details["journal_entity_id"]: {
                        "Type": 1,
                        "Value": u"<p>{}</p>".format(text),
                        "FieldId": request_details["journal_entity_id"]
                    }
                }
            }
        }
        
        response = self.json_session.post(url, json=payload)
        self.validate_response(response, u"Unable to add journal entry to {}.".format(destination_content_id), check_content=True)
        return response.json()

    def get_security_alert_details(self, security_alert_id):
        """
        Get security alert details by provided id
        :param security_alert_id: The security alert id
        :return: {dict} The raw data of security alert details
        """
        url = u"{}/contentapi/Security_Alerts({})".format(self.api_root, security_alert_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get {} security alert details".format(security_alert_id),
                               check_content=False)
        return response.json()

    def get_security_event_details(self, security_event_id):
        """
        Get security event details by provided id
        :param security_event_id: The security event id
        :return: {dict} The raw data of security event details
        """
        url = u"{}/contentapi/Security_Events({})".format(self.api_root, security_event_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get {} security event details".format(security_event_id),
                               check_content=False)
        return response.json()

    def get_filtered_devices(self, devices_ids):
        """
        Get filtered devices
        :param devices_ids: {list} The list of device ids
        :return: {dict} The devices details
        """
        page_number = 1
        devices_ids = list(set(devices_ids))
        devices = {}
        devices.update(self.get_paginated_devices(page_number))
        filtered_devices = {key: devices[key] for key in devices.keys() if key in devices_ids}

        while len(list(filtered_devices.keys())) < len(devices_ids):
            page_number += 1
            results = self.get_paginated_devices(page_number)

            if not results:
                break

            devices.update(results)
            filtered_devices = {key: devices[key] for key in devices.keys() if key in devices_ids}

        return filtered_devices

    def get_paginated_devices(self, page_number=None):
        """
        Get paginated devices
        :param page_number: The page number
        :return: {dict} Devices raw data
        """
        url = u"{}/contentapi/Devices".format(self.api_root)
        params = {"skip": page_number - 1} if page_number > 1 else {}
        response = self.json_session.get(url, params=params)
        self.validate_response(response, "Unable to get devices", check_content=False)
        return self.parser.get_devices(response.json())

    def get_incident_journal_details(self, incident_journal_id):
        """
        Get incident journal details by provided id
        :param incident_journal_id: The incident journal id
        :return: {dict} The raw data of incident journal details
        """
        url = u"{}/contentapi/Incident_Journal({})".format(self.api_root, incident_journal_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get {} incident journal details".format(incident_journal_id),
                               check_content=False)
        return response.json()

    def get_filed_id_by_name(self, application_id, field_name):
        """
        Get filed id by filed name
        :param application_id: The application id
        :param field_name: The field name
        :return: {int} The id of filed
        """
        return next(field.id for field in self.get_fields(application_id) if field.alias == field_name)

    def get_fields(self, application_id):
        """
        Get fields by application id
        :param application_id: The application id
        :return: {list} The list of Field objects
        """
        url = u"{}/api/core/system/fielddefinition/application/{}".format(self.api_root, application_id)
        response = self.json_session.get(url)
        self.validate_response(response, "Unable to get fields for {} application".format(application_id),
                               check_content=False)
        return self.parser.build_field_objects(response.json())

    def get_app_configs(self):
        """
        Read configs from config file or get them from api and write them in configs file
        :return: {tuple} The application id and date_created field id
        """
        configs = read_configs(self.siemplify)

        if configs:
            return configs.get("module_id"), configs.get("date_created_field_id")

        application = self.get_app_by_name(SECURITY_INCIDENTS_APP_NAME)
        date_created_field_id = self.get_filed_id_by_name(application.id, DATE_CREATED_FIELD_NAME)

        write_configs(self.siemplify, {
            "module_id": application.id,
            "date_created_field_id": date_created_field_id
        })

        return application.id, date_created_field_id

    @staticmethod
    def validate_response(response, error_msg="An error occurred", check_content=True):
        try:
            if response.status_code == 404:
                raise SecurityIncidentDoesntExistError("Security Incident wasn't found in RSA Archer")
            
            response.raise_for_status()

        except requests.HTTPError as error:
            # Not a JSON - return content
            raise RSAArcherManagerError(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

        if check_content:
            if isinstance(response.json(), dict):
                if not response.json()["IsSuccessful"]:
                    error_messages = ", ".join([message['MessageKey'] for message in
                                                response.json()["ValidationMessages"]])
                    raise RSAArcherManagerError(
                        "{error_msg}: {error}".format(
                            error_msg=error_msg,
                            error=error_messages)
                    )

            elif isinstance(response.json(), list):
                error_messages = []
                for result in response.json():
                    if not result["IsSuccessful"]:
                        error_messages.extend(
                            [message['MessageKey'] for message in
                             result["ValidationMessages"]])

                if error_messages:
                    raise RSAArcherManagerError(
                        "{error_msg}: {error}".format(
                            error_msg=error_msg,
                            error=", ".join(error_messages))
                    )

    @staticmethod
    def validate_xml_response(response, error_msg="An error occurred"):
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            # Not a JSON - return content
            raise RSAArcherManagerError(
                "{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )

# CR: Add big image