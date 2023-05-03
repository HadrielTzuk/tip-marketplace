from typing import List

from datamodels import (
    Instance,
    InstanceNetworkInterface,
    InstanceIAMPolicy,
    OperationResource
)


class GoogleCloudComputeParser(object):
    """
    Google Cloud Compute Transformation Layer.
    """

    @staticmethod
    def build_instances_objs(response_json) -> List[Instance]:
        return [GoogleCloudComputeParser.build_instance_obj(item) for item in response_json.get('items', [])]

    @staticmethod
    def build_instance_obj(instance_raw_data) -> Instance:
        network_interfaces = None
        if instance_raw_data.get("networkInterfaces"):
            network_interfaces = GoogleCloudComputeParser.build_instance_network_interfaces_objs(
                instance_raw_data.get("networkInterfaces"))
        return Instance(
            raw_data=instance_raw_data,
            network_interfaces=network_interfaces,
            **instance_raw_data
        )

    @staticmethod
    def build_instance_network_interfaces_objs(network_interfaces) -> List[InstanceNetworkInterface]:
        return [GoogleCloudComputeParser.build_instance_network_interface_obj(item) for item in network_interfaces]

    @staticmethod
    def build_instance_network_interface_obj(network_interfaces) -> InstanceNetworkInterface:
        return InstanceNetworkInterface(
            raw_data=network_interfaces,
            **network_interfaces
        )

    @staticmethod
    def build_instance_iam_policy_obj(raw_data) -> InstanceIAMPolicy:
        return InstanceIAMPolicy(
            raw_data,
            **raw_data
        )

    @staticmethod
    def build_operation_resource_obj(raw_data) -> OperationResource:
        return OperationResource(
            raw_data=raw_data,
            zone=raw_data.get("zone")
        )
