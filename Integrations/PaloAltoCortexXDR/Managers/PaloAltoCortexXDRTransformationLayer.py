from datamodels import Endpoint, DeviceViolation, AgentReport


class PaloAltoCortexXDRTransformationLayer(object):
    """
    Palo Alto Cortex XDR Transformation Layer.
    Class for object building from raw_data with static methods build_siemplify_{object}_obj.
    """

    @staticmethod
    def build_siemplify_endpoint_obj(endpoint_data):
        return Endpoint(raw_data=endpoint_data, **endpoint_data)

    @staticmethod
    def build_siemplify_device_violation_obj(device_violation_data):
        return DeviceViolation(raw_data=device_violation_data, **device_violation_data)

    @staticmethod
    def build_siemplify_agent_report_obj(agent_report_data):
        return AgentReport(raw_data=agent_report_data, **agent_report_data)