from TIPCommon import dict_to_flat, add_prefix_to_dict

class BaseModel(object):
    """
    Base model for inheritance
    """

    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data


class Client(BaseModel):
    def __init__(self, raw_data, device_id, os, users):
        super(Client, self).__init__(raw_data)
        self.device_id = device_id
        self.os = os
        self.users = users

    def to_table_data(self):
        return {
            "Device ID": self.device_id,
            "OS ": self.os,
            "Users": self.users
        }
        
class User(BaseModel):
    def __init__(self, raw_data, username):
        super(User, self).__init__(raw_data)
        self.username = username
