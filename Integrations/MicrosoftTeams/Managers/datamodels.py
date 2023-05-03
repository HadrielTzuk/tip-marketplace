
from TIPCommon import dict_to_flat, add_prefix_to_dict

class BaseModel:
    """
    Base model for inheritance
    """
    def __init__(self, raw_data):
        self.raw_data = raw_data

    def to_json(self):
        return self.raw_data

    def to_csv(self):
        return dict_to_flat(self.to_json())

    def to_enrichment_data(self, prefix=None):
        data = dict_to_flat(self.raw_data)
        return add_prefix_to_dict(data, prefix) if prefix else data


class Message(BaseModel):
    def __init__(self, raw_data, message_id, created_date):
        super(Message, self).__init__(raw_data)
        self.message_id = message_id
        self.created_date = created_date

class Me(BaseModel):
    def __init__(self, raw_data, display_name, email, user_id):
        super(Me, self).__init__(raw_data)
        self.display_name = display_name
        self.email = email
        self.user_id = user_id

        
class Chat(BaseModel):
    def __init__(self, raw_data, topic=None, chat_id=None, chat_type=None, members=None):
        super(Chat, self).__init__(raw_data)
        self.topic = topic
        self.chat_id = chat_id
        self.chat_type = chat_type
        self.members = ",".join(members) if members else "N/A"
        
    def to_table(self):
        return {
            "ID": self.chat_id,
            "Type": self.chat_type,
            "Topic": self.topic,
            "Members": self.members
        }


class Channel(BaseModel):
    def __init__(self, raw_data):
        super(Channel, self).__init__(raw_data)


class User(BaseModel):
    def __init__(self, raw_data, user_id, display_name, email):
        super(User, self).__init__(raw_data)
        self.user_id = user_id
        self.display_name = display_name
        self.email = email
