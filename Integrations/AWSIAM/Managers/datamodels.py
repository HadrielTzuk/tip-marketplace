class User(object):
    """
    User data model
    """

    def __init__(self, raw_data, Path=None,
                 UserName=None,
                 UserId=None,
                 Arn=None,
                 CreateDate=None, **kwargs):
        self.raw_data = raw_data
        self.path = Path
        self.username = UserName
        self.user_id = UserId
        self.arn = Arn
        self.create_date = CreateDate

    def as_json(self):
        return {
            'Arn': self.arn,
            'CreateDate': self.create_date,
            'Path': self.path,
            'UserId': self.user_id,
            'UserName': self.username
        }

    def as_csv(self):
        return {
            'User Name': self.username,
            'User ID': self.user_id,
            'ARN': self.arn,
            'Creation Date': self.create_date

        }


class Group(object):
    """
    Group data model
    """

    def __init__(self, raw_data, Path=None,
                 GroupName=None,
                 GroupId=None,
                 Arn=None,
                 CreateDate=None, **kwargs):
        self.raw_data = raw_data
        self.path = Path
        self.group_name = GroupName
        self.group_id = GroupId
        self.arn = Arn
        self.create_date = CreateDate

    def as_json(self):
        return {
            'Arn': self.arn,
            'CreateDate': self.create_date,
            'Path': self.path,
            'GroupId': self.group_id,
            'GroupName': self.group_name
        }

    def as_csv(self):
        return {
            'Group Name': self.group_name,
            'Group ID': self.group_id,
            'ARN': self.arn,
            'Creation Date': self.create_date
        }


class Policy(object):
    """
    AWS IAM Policy data model.
    """

    def __init__(self, raw_data, PolicyName=None, PolicyId=None, Arn=None, Path=None, DefaultVersionId=None, AttachmentCount=None,
                 PermissionsBoundaryUsageCount=None, IsAttachable=None, Description=None, CreateDate=None, UpdateDate=None):
        self.raw_data = raw_data
        self.policy_name = PolicyName
        self.policy_id = PolicyId
        self.arn = Arn
        self.path = Path
        self.default_version_id = DefaultVersionId
        self.attachment_count = AttachmentCount
        self.permission_boundary_usage_count = PermissionsBoundaryUsageCount
        self.is_attachable = IsAttachable
        self.description = Description
        self.create_date = CreateDate  # datetime.datetime object
        self.update_date = UpdateDate  # datetime.datetime object

    def as_json(self):
        return {
            'PolicyName': self.policy_name,
            'PolicyId': self.policy_id,
            'Arn': self.arn,
            'Path': self.path,
            'DefaultVersionId': self.default_version_id,
            'AttachmentCount': self.attachment_count,
            'PermissionsBoundaryUsageCount': self.permission_boundary_usage_count,
            'IsAttachable': self.is_attachable,
            'Description': self.description,
            'CreateDate': self.create_date,
            'UpdateDate': self.update_date
        }

    def as_csv(self):
        return {
            'Policy Name': self.policy_name,
            'Policy ID': self.policy_id,
            'Create Date': self.create_date,
            'Update Date': self.update_date
        }
