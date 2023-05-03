from typing import Optional

from datamodels import KubeCluster, KubeClusterOperation, KubeClusterNodePool


class GoogleGKEParser(object):
    """
    Google Kubernetes Engine Transformation Layer
    """

    @staticmethod
    def parse_response_error(response: dict):
        error = response.get("error", {})
        return error.get("code"), error.get("message"), error.get("status")

    @staticmethod
    def build_kube_cluster_obj_list(raw_response: dict):
        return [GoogleGKEParser.build_kube_cluster_obj(cluster) for cluster in raw_response.get("clusters", [])]

    @staticmethod
    def build_kube_cluster_obj(raw_cluster: dict):
        return KubeCluster(
            raw_data=raw_cluster,
            cluster_id=raw_cluster.get("id"),
            name=raw_cluster.get("name"),
            description=raw_cluster.get("description"),
            cluster_network=raw_cluster.get("network"),
            cluster_ipv4_cidr=raw_cluster.get("clusterIpv4Cidr"),
            labels=raw_cluster.get("resourceLabels", {}),
            cluster_endpoint=raw_cluster.get("endpoint"),
            status=raw_cluster.get("status"),
            location=raw_cluster.get("location"),
            zone=raw_cluster.get("zone"),
            initial_cluster_version=raw_cluster.get("initialClusterVersion"),
            current_master_version=raw_cluster.get("currentMasterVersion"),
            current_node_version=raw_cluster.get("currentNodeVersion"),
            create_time=raw_cluster.get("createTime"),
            label_fingerprint=raw_cluster.get("labelFingerprint")
        )

    @staticmethod
    def build_kube_cluster_operation_obj_list(raw_response: dict):
        return [GoogleGKEParser.build_kube_cluster_operation_obj(operation) for operation in raw_response.get("operations", [])]

    @staticmethod
    def build_kube_cluster_operation_obj(raw_operation: dict, cluster_name: Optional[str] = None):
        return KubeClusterOperation(
            raw_data=raw_operation,
            name=raw_operation.get("name"),
            operation_type=raw_operation.get("operationType"),
            status=raw_operation.get("status"),
            zone=raw_operation.get("zone"),
            start_time=raw_operation.get("startTime"),
            end_time=raw_operation.get("endTime"),
            target_link=raw_operation.get("targetLink"),
            self_link=raw_operation.get("selfLink"),
            cluster_name=cluster_name
        )

    @staticmethod
    def build_kube_cluster_node_pool_obj_list(raw_response: dict):
        return [GoogleGKEParser.build_kube_cluster_node_pool_obj(raw_node_pool) for raw_node_pool in raw_response.get("nodePools", [])]

    @staticmethod
    def build_kube_cluster_node_pool_obj(raw_node_pool: dict):
        return KubeClusterNodePool(
            raw_data=raw_node_pool,
            name=raw_node_pool.get("name"),
            status=raw_node_pool.get("status"),
            version=raw_node_pool.get("version"),
            machine_type=raw_node_pool.get("config", {}).get("machineType"),
            service_account=raw_node_pool.get("config", {}).get("serviceAccount"),
            initial_node_count=raw_node_pool.get("initialNodeCount"),
            autoscaling=raw_node_pool.get("autoscaling", {}),
            max_pods_constraint=raw_node_pool.get("maxPodsConstraint", {}),
            tags=raw_node_pool.get("config", {}).get("tags", []),
            locations=raw_node_pool.get("locations", []),
            auto_repair=raw_node_pool.get("management", {}).get("autoRepair"),
            auto_upgrade=raw_node_pool.get("management", {}).get("autoUpgrade")
        )
