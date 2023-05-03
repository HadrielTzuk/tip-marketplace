from datamodels import *
from SiemplifyDataModel import EntityTypes
from MicrosoftConstants import EMAIL_REGEX, EQUAL_FILTER, CONTAINS_FILTER, FILTER_KEY_TOPIC, FILTER_KEY_MEMBER_EMAIL,FILTER_KEY_MEMBER_DISPLAY_NAME 
import re


class MicrosoftTeamsParser(object):
    def build_message_object(self, raw_json):
        return Message(
            raw_data=raw_json,
            message_id=raw_json.get('id'),
            created_date=raw_json.get('createdDateTime')
        )
        
    def build_me_object(self, raw_json):
        return Me(
            raw_data=raw_json,
            display_name=raw_json.get('displayName'),
            email=raw_json.get('mail'),
            user_id=raw_json.get('id')
        )
        
    def get_chat_ids(self, raw_json, entity_identifier):
        for chat in raw_json.get("value"):
            members = chat.get("members")
            for member in members:
                if bool(re.search(EMAIL_REGEX, entity_identifier)):
                    if member.get("email") == entity_identifier:
                        return chat.get("id")
                elif member.get("displayName") == entity_identifier:
                    return chat.get("id")


    def build_chat_objects(self, raw_json, filter_key, filter_value, filter_logic, limit):
        
        filtered_chats = []
        for chat in raw_json.get("value"):
            append_chat = False
            raw_data=chat
            topic=chat.get('topic')
            chat_id=chat.get('id')
            chat_type=chat.get('chatType')
            members=chat.get('members')            
                
            if filter_logic == EQUAL_FILTER:
                
                if filter_key == FILTER_KEY_TOPIC and topic:
                    if topic == filter_value:
                        append_chat = True
                    
                if filter_key == FILTER_KEY_MEMBER_EMAIL and members:
                    for member in members:
                        if member.get("email") == filter_value:
                            append_chat = True
                
                if filter_key == FILTER_KEY_MEMBER_DISPLAY_NAME and members:                    
                    for member in members:
                        if member.get("displayName") == filter_value:
                            append_chat = True               
                            
            elif filter_logic == CONTAINS_FILTER: 
            
                if filter_key == FILTER_KEY_TOPIC and topic:
                    if filter_value in topic:
                        append_chat = True
                    
                if filter_key == FILTER_KEY_MEMBER_EMAIL and members:
                    for member in members:
                        member_email = member.get("email") if member.get("email") else ""
                        if filter_value in member_email:
                            append_chat = True 
                
                if filter_key == FILTER_KEY_MEMBER_DISPLAY_NAME and members:                    
                    for member in members:
                        if filter_value in member.get("displayName"):
                            append_chat = True
                            
            else:
                append_chat = True
                            
            if append_chat:
                filtered_chats.append(
                  Chat(
                    raw_data=raw_data,
                    topic=topic,
                    chat_id=chat_id,
                    chat_type=chat_type,
                    members=[member.get("displayName") for member in members] if members else []
                )  
                )
                
        return filtered_chats[:limit] if limit else filtered_chats

    @staticmethod
    def build_channel_object(raw_data):
        return Channel(
            raw_data=raw_data
        )

    def build_user_objects(self, raw_data):
        return [self.build_user_object(item) for item in raw_data]

    @staticmethod
    def build_user_object(raw_data):
        return User(
            raw_data=raw_data,
            user_id=raw_data.get("id"),
            display_name=raw_data.get("displayName"),
            email=raw_data.get("email")
        )

    @staticmethod
    def build_chat_object(raw_data):
        return Chat(
            raw_data=raw_data,
            topic=raw_data.get("topic"),
            chat_id=raw_data.get("id"),
            chat_type=raw_data.get("chatType"),
            members=raw_data.get("members")
        )

