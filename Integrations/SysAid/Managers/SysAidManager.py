# ============================================================================#
# title           :SysAidManager.py
# description     :This Module contain all SysAid operations functionality
# author          :avital@siemplify.co
# date            :25-11-2018
# python_version  :2.7
# libreries       :requests
# requirments     :
# product_version :SysAid ITSM v18.3.24 b1 (The REST API is supported by SysAid versions 15.4 and up.)
# ============================================================================#

# ============================= IMPORTS ===================================== #

import requests


# ============================== CONSTS ===================================== #


# ============================= CLASSES ===================================== #


class SysAidManagerError(Exception):
    """
    General Exception for ProofPoint TAP manager
    """
    pass


class SysAidManager(object):
    """
    SysAid Manager
    """

    def __init__(self, server_address, username, password, verify_ssl=False):
        self.server_address = server_address
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.login(username, password)

    def login(self, username, password):
        """
        Login to SysAid
        :return: {bool} True if successful, exception otherwise.
        """
        url = "{}/login".format(self.server_address)
        response = self.session.post(url, json={
            "user_name": username,
            "password": password
        })

        self.validate_response(response, "Unable to login to SysAid")
        return True

    def get_users(self):
        """
        List all users
        :return: {list} The users
        """
        url = "{}/users".format(self.server_address)
        response = self.session.get(url)

        self.validate_response(response, "Unable to list users")
        return [self.format_object(user, "info") for user in response.json()]

    def get_user(self, user_id):
        """
        Get a user by id
        :param user_id: {str} The id of the user
        :return: {dict} The user
        """
        url = "{}/users/{}".format(self.server_address, user_id)
        response = self.session.get(url)

        self.validate_response(response, "Unable to get user {}".format(user_id))
        return self.format_object(response.json(), "info")

    def get_user_by_name(self, username):
        """
        Get a user by username
        :param username: {str} The username
        :return: {dict} The user
        """
        users = self.get_users()
        for user in users:
            if user.get("name").lower() == username:
                return user

        raise SysAidManagerError("User {} was not found".format(username))

    def get_user_permissions(self, user_id):
        """
        Get the permissions of a user
        :param user_id: {str} The id of the user
        :return: {list} The user's permissions
        """
        url = "{}/users/{}/permission".format(self.server_address, user_id)
        response = self.session.get(url)

        self.validate_response(response, "Unable to get user {} permissions".format(user_id))
        return self.format_object(response.json(), "permissions")

    def get_filters(self):
        """
        Get all the available filters
        :return: {list} The filters
        """
        url = "{}/filters".format(self.server_address)
        response = self.session.get(url)

        self.validate_response(response, "Unable to list filters")
        return response.json()

    def get_filter(self, filter):
        """
        Get a filter info and options map
        :param filter: {str} The filter name
        :return: {dict} The filter info
        """
        url = "{}/filters/{}".format(self.server_address, filter)
        response = self.session.get(url)

        self.validate_response(response, "Unable to get filter {}".format(filter))
        return response.json()

    def parse_filter_value(self, filter, value):
        """
        Parse a filter value to the option'd id
        :param filter: {str} The name of the filter
        :param value: {str} The value to parse
        :return: {str} The id of the option matching the given value in the filter
        """
        filter_values = self.get_filter(filter).get(u"values")

        for filter_value in filter_values:
            if filter_value.get(u"caption", u"").lower() == value.lower():
                return filter_value.get(u"id")

        raise SysAidManagerError(u"Value {} is not valid for filter {}".format(value, filter))

    def list_service_requests(self, sr_type=None, get_archived=0, status=None,
                              priority=None,
                              assignee=None, urgency=None, request_user=None,
                              category=None, sub_category=None,
                              third_category=None, assigned_group=None):
        """
        List service requests
        :param sr_type: {str} The requested service record type.
            Available values are {incident,request,problem,change,all}.
            Multiple values can be sent, comma separated.
            For example: incident,request.
            If not specified, it defaults to all views created on the incident
            list.
        :param get_archived: {int} Whether to return archived SRs.
            Value can be 1 or 0
        :param status: {str} The status of the requested service record.
        :param priority: {str} The priority of the requested service record.
        :param assignee: {str} The assignee of the requested service record.
        :param urgency: {str} The urgency of the requested service record.
        :param request_user: {str} The request user of the requested service record.
        :param category: {str} The category of the requested service record.
        :param sub_category: {str} The sub category of the requested service record.
        :param third_category: {str} The third category of the requested service record.
        :param assigned_group: {str} The assigned group of the requested service record.
        :return:
        """
        url = "{}/sr".format(self.server_address)
        params = {
            "type": sr_type,
            "archive": get_archived,
            "status": self.parse_filter_value("status", status) if status else None,
            "priority": self.parse_filter_value("priority", priority) if priority else None,
            "responsibility": self.parse_filter_value("responsibility", assignee) if assignee else None,
            "urgency": self.parse_filter_value("urgency", urgency) if urgency else None,
            "request_user": self.parse_filter_value("request_user", request_user) if request_user else None,
            "problem_type": "_".join([x for x in [category, sub_category, third_category] if x]),
            "assigned_group": self.parse_filter_value("assigned_group", assigned_group) if assigned_group else None
        }

        # TODO: Add pagination
        params = {k: v for k, v in params.items() if v}
        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to list service requests")
        return [self.format_object(sr, "info") for sr in response.json()]

    def get_service_request(self, sr_id):
        """
        Get a service requests by id
        :param sr_id: {str} The id of the service request
        :return:
        """
        url = "{}/sr".format(self.server_address)
        params = {
            "ids": sr_id
        }
        response = self.session.get(url, params=params)
        self.validate_response(response, "Unable to get service request {}".format(sr_id))
        if response.json():
            return self.format_object(response.json()[0], "info")

        raise SysAidManagerError("Service request {} was not found".format(sr_id))

    def update_service_request(self, sr_id=None, status=None, priority=None,
                               assignee=None, urgency=None, request_user=None,
                               category=None, sub_category=None,
                               third_category=None, assigned_group=None):
        """
        Update service request
        :param sr_id: {str} The id of the service request
        :param status: {str} The status of the requested service record.
        :param priority: {str} The priority of the updated service record.
        :param assignee: {str} The assignee of the updated service record.
        :param urgency: {str} The urgency of the updated service record.
        :param request_user: {str} The request user of the updated service record.
        :param category: {str} The category of the updated service record.
        :param sub_category: {str} The sub category of the updated service record.
        :param third_category: {str} The third category of the updated service record.
        :param assigned_group: {str} The assigned group of the updated service record.
        :return: True if successful, exception otherwise
        """
        url = "{}/sr/{}".format(self.server_address, sr_id)
        payload = {
            "id": sr_id,
            "info": [
                {"key": "status", "value": self.parse_filter_value("status", status) if status else None},
                {"key": "priority", "value": self.parse_filter_value("priority", priority) if priority else None},
                {"key": "responsibility",
                 "value": self.parse_filter_value("responsibility", assignee) if assignee else None},
                {"key": "urgency", "value": self.parse_filter_value("urgency", urgency) if urgency else None},
                {"key": "request_user",
                 "value": self.parse_filter_value("request_user", request_user) if request_user else None},
                {"key": "problem_type", "value": "_".join(
                    [x for x in [category, sub_category, third_category] if x])
                 },
                {"key": "assigned_group",
                 "value": self.parse_filter_value("assigned_group", assigned_group) if assigned_group else None}
            ]
        }
        payload["info"] = [item for item in payload["info"] if item.get("value")]
        response = self.session.put(url, json=payload)
        self.validate_response(response, "Unable to update service request {}".format(sr_id))
        return True

    def close_service_request(self, sr_id, solution):
        """
        Close a service requests by id
        :param sr_id: {str} The id of the service request
        :return: True if successful, exception otherwise
        """
        url = "{}/sr/{}/close".format(self.server_address, sr_id)
        payload = {
            "solution": solution
        }
        response = self.session.put(url, json=payload)
        self.validate_response(response, "Unable to close service request {}".format(sr_id))
        return True

    def delete_service_request(self, sr_id):
        """
        Delete a service requests by id
        :param sr_id: {str} The id of the service request
        :return: True if successful, exception otherwise
        """
        url = "{}/sr".format(self.server_address)
        params = {
            "ids": sr_id
        }
        response = self.session.delete(url, params=params)
        self.validate_response(response, "Unable to delete service request {}".format(sr_id))
        return True

    def create_service_request(self, title, description, assignee, request_user=None,
                               sr_type=None, due_date=None, status=u"New", priority=u"Low",
                               urgency=u"Low", category=None, sub_category=None,
                               third_category=None, assigned_group=None):
        """
        Create a service request
        :param title: {str} The title of the new service record.
        :param description: {str} The status of the new service record.
        :param assignee: {str} The assignee of the new service record.
        :param request_user: {str} The request user of the new service record.
        :param sr_type: {str} The new service record type.
            Available values are {incident,request,problem,change,all}.
            Multiple values can be sent, comma separated.
            For example: incident,request.
            If not specified, it defaults to all views created on the incident
            list.
        :param due_date: {str} The due_date of the new service record (in milliseconds).
        :param status: {str} The status of the new service record.
        :param priority: {str} The priority of the new service record.
        :param urgency: {str} The urgency of the new service record.
        :param category: {str} The category of the new service record.
        :param sub_category: {str} The sub category of the new service record.
        :param third_category: {str} The third category of the new service record.
        :param assigned_group: {str} The assigned group of the new service record.
        :return: {str} The id of the new service request
        """
        payload = {
            u"info": [
                {u"key": u"title", u"value": title},
                {u"key": u"description", u"value": description},
                {u"key": u"due_date", u"value": due_date},
                {u"key": u"sr_type", u"value": sr_type},
                {u"key": u"status", u"value": self.parse_filter_value(u"status", status) if status else None},
                {u"key": u"priority", u"value": self.parse_filter_value(u"priority", priority) if priority else None},
                {u"key": u"responsibility",
                 u"value": self.parse_filter_value(u"responsibility", assignee) if assignee else None},
                {u"key": u"urgency", u"value": self.parse_filter_value(u"urgency", urgency) if urgency else None},
                {u"key": u"request_user",
                 u"value": self.parse_filter_value(u"request_user", request_user) if request_user else None},
                {u"key": u"problem_type",
                 u"value": u"_".join([x for x in [category, sub_category, third_category] if x])},
                {u"key": u"assigned_group",
                 u"value": self.parse_filter_value(u"assigned_group", assigned_group) if assigned_group else None}
            ]
        }
        url = u"{}/sr".format(self.server_address)
        payload[u"info"] = [item for item in payload[u"info"] if item.get(u"value")]
        response = self.session.post(url, json=payload)
        self.validate_response(response, u"Unable to create service request {}")
        return response.json().get(u"id")

    @staticmethod
    def format_object(obj, key):
        """
        Format a given object to a human readable format
        :param obj: {dict} The object to format
        :param key: {str} The key in the obj to format
        :return: {dict} The formatted obj
        """
        info = {}
        for property in obj.get(key, {}):
            property_key = property.get("key")
            property_value = property.get("value")
            info[property_key] = property_value

        obj[key] = info

        return obj

    @staticmethod
    def validate_response(response, error_msg=u"An error occurred"):
        """
        Validate a response
        :param response: {requests.Response} The response to validate
        :param error_msg: {str} The error message to display
        """
        try:
            response.raise_for_status()

        except requests.HTTPError as error:
            if response.status_code == 429:
                raise SysAidManagerError(
                    u"The user has made too many requests over the past 24 hours and has been throttled.")

            raise SysAidManagerError(
                u"{error_msg}: {error} - {text}".format(
                    error_msg=error_msg,
                    error=error,
                    text=error.response.content)
            )