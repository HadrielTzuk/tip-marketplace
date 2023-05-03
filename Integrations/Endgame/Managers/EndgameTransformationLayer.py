from datamodels import Endpoint, Group, Sensor, TaskCompletion, Investigation, IsolationRuleComment, IsolationRule, \
    HostIsolationConfig
from copy import deepcopy


class EndgameTransformationLayer(object):
    """
    Endgame Transformation Layer.
    """

    @staticmethod
    def build_siemplify_group_obj(group_data):
        return Group(raw_data=group_data, **group_data)

    @staticmethod
    def build_siemplify_sensor_obj(sensor_data):
        return Sensor(raw_data=sensor_data, **sensor_data)

    @staticmethod
    def build_siemplify_investigation_obj(investigation_data):
        task_completions = []

        for task_name, task_completion_info in investigation_data.get(u"task_completions_by_type", {}).items():
            task_completions.append(
                TaskCompletion(
                    task_name=task_name,
                    completed_tasks=task_completion_info.get("completed_tasks"),
                    total_tasks=task_completion_info.get("total_tasks")
                )
            )

        created_by_username = investigation_data.get(u"user_display_name")

        if not created_by_username:
            created_by_username = investigation_data.get(u"created_by", {}).get(u"username")

        return Investigation(raw_data=investigation_data, created_by_username=created_by_username,
                             task_completions=task_completions,
                             completed_tasks=investigation_data.get("task_completion", {}).get("completed_tasks"),
                             total_tasks=investigation_data.get("task_completion", {}).get("total_tasks"),
                             **investigation_data)

    @staticmethod
    def build_siemplify_endpoint_obj(endpoint_data):
        temp_data = deepcopy(endpoint_data)

        # Extract groups  and sensors from the data and parse them to matching data models
        groups = temp_data.pop(u"groups") if u"groups" in endpoint_data else []
        sensors = temp_data.pop(u"sensors") if u"sensors" in endpoint_data else []

        groups = [EndgameTransformationLayer.build_siemplify_group_obj(group) for group in groups]
        sensors = [EndgameTransformationLayer.build_siemplify_sensor_obj(sensor) for sensor in sensors]

        return Endpoint(raw_data=endpoint_data, groups=groups, sensors=sensors, **temp_data)

    @staticmethod
    def build_siemplify_host_isolation_config_obj(host_isolation_config_data):
        isolation_rules = []

        for isolation_rule in host_isolation_config_data:
            rule_comments = []

            for comment in isolation_rule.get("comments", []):
                rule_comments.append(
                    IsolationRuleComment(
                        comment, **comment
                    )
                )

            isolation_rules.append(
                IsolationRule(
                    isolation_rule,
                    rule_comments = rule_comments,
                    **isolation_rule
                )
            )

        return HostIsolationConfig(raw_data=host_isolation_config_data, isolation_rules=isolation_rules)
