from datamodels import OrgUnit, Group, User, Member, AccessToken


class GSuiteParser(object):
    """
    GSuite parser
    """

    @staticmethod
    def build_ou_obj(raw_data):
        return OrgUnit(
            raw_data=raw_data,
            **raw_data
        )

    @staticmethod
    def build_group_obj(raw_data):
        return Group(
            raw_data=raw_data,
            **raw_data
        )

    @staticmethod
    def build_user_phone_obj(raw_data):
        return User.Phone(
            value=raw_data.get("value"),
            type=raw_data.get("type"),
            is_primary=raw_data.get("primary")
        )

    @staticmethod
    def build_user_obj(raw_data):
        return User(
            raw_data=raw_data,
            given_name=raw_data.get("name", {}).get("givenName"),
            family_name=raw_data.get("name", {}).get("familyName"),
            phones_objs=[GSuiteParser.build_user_phone_obj(phone) for phone in raw_data.get("phones", [])],
            gender_type=raw_data.get("gender", {}).get("type"),
            **raw_data
        )

    @staticmethod
    def build_org_units_objs(raw_data):
        return [GSuiteParser.build_ou_obj(ou_raw) for ou_raw in raw_data.get("organizationUnits", [])]

    @staticmethod
    def build_member_obj(raw_data):
        return Member(
            raw_data=raw_data,
            **raw_data
        )

    @staticmethod
    def build_token_obj(raw_data):
        return AccessToken(
            raw_data=raw_data,
            **raw_data
        )