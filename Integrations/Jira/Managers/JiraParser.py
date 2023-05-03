from datamodels import Issue, ServerInfo, User, RelationType


class JiraParser(object):
    """
    Jira Transformation Layer.
    """

    @staticmethod
    def build_issue_obj(raw_data):
        return Issue(raw_data=raw_data,
                     id=raw_data.get("id"),
                     expand=raw_data.get("expand"),
                     raw_fields=raw_data.get("fields"),
                     key=raw_data.get("key"),
                     project_id=raw_data.get("fields", {}).get("project", {}).get("id"),
                     project_key=raw_data.get("fields", {}).get("project", {}).get("key"),
                     project_name=raw_data.get("fields", {}).get("project", {}).get("name"),
                     project_type_key=raw_data.get("fields", {}).get("project", {}).get("projectTypeKey"),
                     created=raw_data.get("fields", {}).get("created"),
                     updated=raw_data.get("fields", {}).get("updated"),
                     priority=raw_data.get("fields", {}).get("priority", {}).get("name"),
                     attachments=JiraParser.build_issue_attachment_list_obj(raw_data.get("fields", {}).get("attachment", [])),
                     comments=JiraParser.build_issue_comment_obj_list(raw_data.get("fields", {}).get("comment", {}).get("comments", [])))

    @staticmethod
    def build_issue_attachment_obj(raw_data):
        return Issue.Attachment(raw_data=raw_data,
                                filename=raw_data.get("filename"),
                                author_account_id=raw_data.get("author", {}).get("accountId"),
                                created=raw_data.get("created"),
                                size=raw_data.get("size"),
                                content_link=raw_data.get("content"))

    @staticmethod
    def build_issue_attachment_list_obj(raw_data):
        return [JiraParser.build_issue_attachment_obj(raw_attachment) for raw_attachment in raw_data]

    @staticmethod
    def build_issue_obj_list(raw_data):
        return [JiraParser.build_issue_obj(raw_issue) for raw_issue in raw_data]

    @staticmethod
    def build_server_info_obj(raw_data):
        return ServerInfo(raw_data=raw_data, base_url=raw_data.get("baseUrl"), version=raw_data.get("version"),
                          deployment_type=raw_data.get("deploymentType"), build_number=raw_data.get("buildNumber"),
                          server_time=raw_data.get("serverTime"), build_date=raw_data.get("buildDate"))

    @staticmethod
    def build_issue_comment_obj_list(raw_data):
        return [JiraParser.build_issue_comment_obj(raw_comment) for raw_comment in raw_data]

    @staticmethod
    def build_issue_comment_obj(raw_comment):
        return Issue.Comment(raw_data=raw_comment, created=raw_comment.get("created"), updated=raw_comment.get("updated"),
                             body=raw_comment.get("body"), id=raw_comment.get("id"))

    @staticmethod
    def build_user_obj_list(raw_data):
        return [JiraParser.build_user_obj(raw_user) for raw_user in raw_data]

    @staticmethod
    def build_user_obj(raw_user):
        return User(raw_data=raw_user,
                    _self_user=raw_user.get("self"),
                    accountId=raw_user.get("accountId"),
                    accountType=raw_user.get("accountType"),
                    avatarUrls=raw_user.get("avatarUrls"),
                    displayName=raw_user.get("displayName"),
                    active=raw_user.get("active"),
                    locale=raw_user.get("locale"),
                    emailAddress=raw_user.get("emailAddress"))

    def build_relation_type_objects(self, raw_data):
        return [self.build_relation_type_object(item) for item in raw_data.get("issueLinkTypes", [])]

    @staticmethod
    def build_relation_type_object(raw_data):
        return RelationType(
            raw_data=raw_data,
            name=raw_data.get("name"),
            inward=raw_data.get("inward"),
            outward=raw_data.get("outward")
        )
