from datamodels import User, Group, Policy


class AWSIAMParser(object):
    @staticmethod
    def build_users_obj(objects_data):
        return [AWSIAMParser.build_user_obj({'User': user}) for user in objects_data]

    @staticmethod
    def build_user_obj(objects_data):
        data = objects_data.get('User')
        return User(
            raw_data=data,
            **data
        )

    @staticmethod
    def build_groups_obj(objects_data):
        return [AWSIAMParser.build_group_obj({'Group': group}) for group in objects_data]

    @staticmethod
    def build_group_obj(objects_data):
        data = objects_data.get('Group')
        return Group(
            raw_data=data,
            **data
        )

    @staticmethod
    def build_policy_obj(raw_data):
        data = raw_data.get("Policy", {})
        return Policy(
            raw_data=data,
            **data
        )

    @staticmethod
    def build_policy_raw_obj(raw_data):
        return Policy(
            raw_data,
            **raw_data
        )
