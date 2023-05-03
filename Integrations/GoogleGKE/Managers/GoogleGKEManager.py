# ============================================================================#
# title           :GoogleGKEManager.py
# description     :This Module contains all Google Kubernetes Engine operations functionality
# author          :gabriel.munits@siemplify.co
# date            :23-08-2021
# python_version  :3.7
# product_version :1.0
# ============================================================================#
from typing import Optional
from urllib.parse import urljoin

import requests
import requests.adapters
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2 import service_account

from GoogleGKECommon import GoogleGKECommon
from GoogleGKEParser import GoogleGKEParser
from SiemplifyLogger import SiemplifyLogger
from consts import (
    API_URL,
    OAUTH_SCOPES,
    INTEGRATION_DISPLAY_NAME,
    INVALID_ARGUMENT,
    NOT_FOUND,
    PERMISSION_DENIED,
    PROJECT_LOOKUP_ERROR_MESSAGE,
    LOCATION_ERROR_MESSAGE,
    NODE_POOL_ERROR_MESSAGE
)
from exceptions import (
    GoogleGKEManagerError,
    GoogleGKEInvalidZoneError,
    GoogleGKEInvalidRequestArgumentError,
    GoogleGKENotFoundError,
    GoogleGKEInvalidClusterNameError,
    GoogleGKEInvalidNodePoolNameError,
    GoogleGKEInvalidOperationNameError,
    GoogleGKEProjectLookupError,
    GoogleGKEManagerCriticalError,
    MissingParametersException
)
from utils import remove_none_values, parse_string_to_dict


# ============================= CONSTS ===================================== #

ENDPOINTS = {
    "list-clusters": "/v1/projects/{project_id}/locations/{zone_name}/clusters",
    "get-cluster": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}",
    "update-cluster-labels": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}:setResourceLabels",
    "get-operation": "/v1/projects/{project_id}/locations/{zone_name}/operations/{operation_name}",
    "update-cluster-addons": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}:setAddons",
    "get-cluster-node-pool": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}/nodePools/{node_pool_name}",
    "list-cluster-node-pools": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}/nodePools",
    "set-cluster-node-pool-autoscaling": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}/nodePools/{node_pool_name}:setAutoscaling",
    "set-cluster-node-pool-management": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}/nodePools/{node_pool_name}:setManagement",
    "set-cluster-node-pool-node-count": "/v1/projects/{project_id}/locations/{zone_name}/clusters/{cluster_name}/nodePools/{node_pool_name}:setSize",
    "list-operations": "/v1/projects/{project_id}/locations/{zone_name}/operations"
}


# ============================= CLASSES ===================================== #

class GoogleGKEManager(object):
    """
    Google Kubernetes Engine Manager
    """

    def __init__(self, account_type: Optional[str] = None, project_id: Optional[str] = None, private_key_id: Optional[str] = None,
                 private_key: Optional[str] = None, client_email: Optional[str] = None, client_id: Optional[str] = None,
                 auth_uri: Optional[str] = None, token_uri: Optional[str] = None, auth_provider_x509_url: Optional[str] = None,
                 client_x509_cert_url: Optional[str] = None, logger: Optional[SiemplifyLogger] = None,
                 force_test_connectivity: Optional[bool] = False, service_account_json: str = None, verify_ssl: bool = True):

        if service_account_json:
            creds = parse_string_to_dict(service_account_json)
        else:
            creds = {
                "type": account_type,
                "project_id": project_id,
                "private_key_id": private_key_id,
                "private_key": private_key.replace("\\n", "\n") if private_key else None,
                "client_email": client_email,
                "client_id": client_id,
                "auth_uri": auth_uri,
                "token_uri": token_uri,
                "auth_provider_x509_cert_url": auth_provider_x509_url,
                "client_x509_cert_url": client_x509_cert_url
            }
            if any(param is None for param in creds.values()):
                raise MissingParametersException(
                    "Please fill either 'Service Account Json File Content' or all other parameters"
                )

        self.project_id = creds["project_id"]
        credentials = service_account.Credentials.from_service_account_info(info=creds, scopes=OAUTH_SCOPES)
        self._session = AuthorizedSession(credentials, auth_request=self.prepare_auth_request(verify_ssl=verify_ssl))
        self._session.verify = verify_ssl

        if force_test_connectivity:
            self.test_connectivity()
        self._parser = GoogleGKEParser()
        self._siemplify_logger = logger

        self.gke_common = GoogleGKECommon()

    @staticmethod
    def prepare_auth_request(verify_ssl: bool = True):
        """
        Prepare an authenticated request.

        Note: This method is a duplicate of the same method in the AuthorizedSession class. The only change is
        that created session is using verify_ssl parameter to allow self-signed certificates.
        """
        auth_request_session = requests.Session()
        auth_request_session.verify = verify_ssl

        # Using an adapter to make HTTP requests robust to network errors.
        # This adapter retries HTTP requests when network errors occur
        # and the requests seems safely retryable.
        retry_adapter = requests.adapters.HTTPAdapter(max_retries=3)
        auth_request_session.mount("https://", retry_adapter)

        # Do not pass `self` as the session here, as it can lead to
        # infinite recursion.
        return Request(auth_request_session)

    def _get_full_url(self, url_key: str, **kwargs) -> str:
        """
        Get full url from url key.
        :param url_id: {str} The key of url
        :param kwargs: {dict} Key value arguments passed for string formatting
        :return: {str} The full url
        """
        if "project_id" not in kwargs:
            kwargs["project_id"] = self.project_id
        return urljoin(API_URL, ENDPOINTS[url_key].format(**kwargs))

    @classmethod
    def validate_response(cls, response: requests.Response, error_msg: str = "An error occurred"):
        """
        Validate API response.
        :param response: {requests.Response} The response to validate
        :param error_msg: {str} Default message to display on error
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            try:
                response_json = response.json()
                code, message, status = GoogleGKEParser.parse_response_error(response_json)
                if status == PERMISSION_DENIED and PROJECT_LOOKUP_ERROR_MESSAGE in message:
                    raise GoogleGKEProjectLookupError(
                        f"{error_msg}: {error} {message or response.text}"
                    )
                if status == INVALID_ARGUMENT and all(err in message for err in LOCATION_ERROR_MESSAGE):
                    raise GoogleGKEInvalidZoneError(
                        f"{error_msg}: {error} {message or response.text}"
                    )
                if ((status == INVALID_ARGUMENT and all(err in message for err in NODE_POOL_ERROR_MESSAGE)) or
                        (status == NOT_FOUND and all(err.lower() in message for err in NODE_POOL_ERROR_MESSAGE)) or
                        (status == INVALID_ARGUMENT and "Unable to find node pool" in message)):
                    raise GoogleGKEInvalidNodePoolNameError(
                        f"{error_msg}: {error} {message or response.text}"
                    )
                if status == INVALID_ARGUMENT:
                    raise GoogleGKEInvalidRequestArgumentError(
                        f"{error_msg}: {error} {message or response.text}"
                    )
                if status == NOT_FOUND:
                    raise GoogleGKENotFoundError(
                        f"{error_msg}: {error} {message or response.text}"
                    )
                raise GoogleGKEManagerError(
                    f"{error_msg}: {error} {message or response.text}"
                )
            except (GoogleGKEManagerError, GoogleGKEManagerCriticalError):
                raise
            except:
                raise GoogleGKEManagerCriticalError(
                    f"{error_msg}: {error} {response.text}"
                )

    def test_connectivity(self):
        """
        Test connectivity with Google GKE
            raise Exception if failed to test connectivity
        """
        response = self._session.get(self._get_full_url("list-clusters", project_id=self.project_id, zone_name="europe-central2-a"))
        self.validate_response(response, error_msg=f"Failed to test connectivity with {INTEGRATION_DISPLAY_NAME}")

    def list_clusters(self, zone_name: str):
        """
        Lists all clusters owned by a project in either the specified zone or all zones.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the clusters resides, or "-" for all zones.
        :return: {[KubeCluster]} List of Kubernetes cluster data models
        """
        response = self._session.get(self._get_full_url("list-clusters", project_id=self.project_id, zone_name=zone_name))
        self.validate_response(response, error_msg=f"Failed to list clusters from zone \"{zone_name}\" in {INTEGRATION_DISPLAY_NAME}")
        return self._parser.build_kube_cluster_obj_list(response.json())

    def get_cluster(self, zone_name: str, cluster_name: str):
        """
        Gets the details of a specific cluster.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster to retrieve
        :return: {KubeCluster} Kubernetes cluster data model
        """
        response = self._session.get(self._get_full_url("get-cluster", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name))
        try:
            self.validate_response(
                response, error_msg=f"Failed to get cluster \"{cluster_name}\" from zone \"{zone_name}\" in {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidClusterNameError(f"Provided cluster name \"{cluster_name}\" was not found.")
        return self._parser.build_kube_cluster_obj(response.json())

    def update_cluster_labels(self, zone_name: str, cluster_name: str, label_fingerprint: str, labels: dict):
        """
        Update labels of a specific cluster.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster to update
        :param label_fingerprint: {str} The fingerprint of the previous set of labels for this resource
        :param labels: {dict} The labels to set for that cluster.
        :return: {KubeClusterOperation} Kubernetes cluster operation data model
        """
        response = self._session.post(
            self._get_full_url("update-cluster-labels", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name),
            json={
                "resourceLabels": labels,
                "labelFingerprint": label_fingerprint
            }
        )
        self.validate_response(response, error_msg=f"Failed to update cluster \"{cluster_name}\" from zone \"{zone_name}\" with labels {labels} in"
                                                   f" {INTEGRATION_DISPLAY_NAME}")
        return self._parser.build_kube_cluster_operation_obj(response.json(), cluster_name=cluster_name)

    def get_operation(self, zone_name: str, operation_name: str, cluster_name: Optional[str] = None):
        """
        Gets the specified operation.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param operation_name: {str} The server-assigned name of the operation.
        :param cluster_name: {str} The cluster name the operation is running on.
        :return: {KubeClusterOperation} Kubernetes cluster operation data model
        """
        response = self._session.get(
            self._get_full_url("get-operation", project_id=self.project_id, zone_name=zone_name, operation_name=operation_name))
        try:
            self.validate_response(
                response, error_msg=f"Failed to get operation \"{operation_name}\" from zone \"{zone_name}\" in {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidOperationNameError(f"Provided operation name \"{operation_name}\" was not found.")
        return self._parser.build_kube_cluster_operation_obj(response.json(), cluster_name=cluster_name)

    def update_cluster_addons(self, zone_name: str, cluster_name: str, http_load_balancing_disabled: Optional[bool] = None,
                              horizontal_pod_autoscaling_disabled: Optional[bool] = None, network_policy_config_disabled: Optional[bool] = None,
                              cloud_run_config_disabled: Optional[bool] = None, cloud_run_config_load_balancer_type: Optional[str] = None,
                              dns_cache_config_enabled: Optional[bool] = None, config_connector_config_enabled: Optional[bool] = None,
                              gce_persistent_disk_csi_driver_config_enabled: Optional[bool] = None):
        """
        Update the addons for a specific cluster.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster to update
        :param http_load_balancing_disabled: {bool} Whether the HTTP Load Balancing controller is disabled in the cluster.
        :param horizontal_pod_autoscaling_disabled: {bool} Whether the Horizontal Pod Autoscaling feature is disabled in the cluster.
        :param network_policy_config_disabled: {str} Configuration for NetworkPolicy. This only tracks whether the addon is disabled or not on the
            Master, it does not track whether network policy is enabled for the nodes.
        :param cloud_run_config_disabled: {bool} Whether the Cloud Run addon disable or not in the cluster. If enabled,
            cloud_run_config_load_balancer_type must be provided
        :param cloud_run_config_load_balancer_type: {str} Load balancer type of ingress service of Cloud Run. Possible Values:
            LOAD_BALANCER_TYPE_UNSPECIFIED, LOAD_BALANCER_TYPE_EXTERNAL or LOAD_BALANCER_TYPE_INTERNAL.
            NOTE - cloud_run_config_disabled parameter must be provided if this parameter is provided
        :param dns_cache_config_enabled: {bool} Whether NodeLocal DNSCache is enabled for this cluster.
        :param config_connector_config_enabled: {bool} Whether Cloud Connector is enabled for this cluster.
        :param gce_persistent_disk_csi_driver_config_enabled: {bool} Whether the Compute Engine PD CSI driver is enabled for this cluster.
        :return: {KubeClusterOperation} Kubernetes cluster operation data model
        """
        response = self._session.post(
            self._get_full_url("update-cluster-addons", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name),
            json={
                "addonsConfig": remove_none_values({
                    "httpLoadBalancing": {
                        "disabled": http_load_balancing_disabled
                    } if isinstance(http_load_balancing_disabled, bool) else None,
                    "horizontalPodAutoscaling": {
                        "disabled": horizontal_pod_autoscaling_disabled
                    } if isinstance(horizontal_pod_autoscaling_disabled, bool) else None,
                    "networkPolicyConfig": {
                        "disabled": network_policy_config_disabled
                    } if isinstance(network_policy_config_disabled, bool) else None,
                    "cloudRunConfig": remove_none_values({
                        "disabled": cloud_run_config_disabled,
                        "loadBalancerType": cloud_run_config_load_balancer_type
                    }) if isinstance(cloud_run_config_disabled, bool) else None,
                    "dnsCacheConfig": {
                        "enabled": dns_cache_config_enabled,
                    } if isinstance(dns_cache_config_enabled, bool) else None,
                    "configConnectorConfig": {
                        "enabled": config_connector_config_enabled,
                    } if isinstance(config_connector_config_enabled, bool) else None,
                    "gcePersistentDiskCsiDriverConfig": {
                        "enabled": gce_persistent_disk_csi_driver_config_enabled,
                    } if isinstance(gce_persistent_disk_csi_driver_config_enabled, bool) else None,
                })
            }
        )
        try:
            self.validate_response(response,
                                   error_msg=f"Failed to update cluster \"{cluster_name}\" from zone \"{zone_name}\" with specified addons in"
                                             f" {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidClusterNameError(f"Provided cluster name \"{cluster_name}\" was not found.")
        return self._parser.build_kube_cluster_operation_obj(response.json(), cluster_name=cluster_name)

    def list_cluster_node_pools(self, zone_name: str, cluster_name: str):
        """
        Lists the node pools for a cluster.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster to list node pools from
        :return: {[KubeClusterNodePool]} List of Kubernetes cluster's node pools data models
        """
        response = self._session.get(
            self._get_full_url("list-cluster-node-pools", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name))
        try:
            self.validate_response(response, error_msg=f"Failed to list cluster's \"{cluster_name}\" node pools from zone \"{zone_name}\" in"
                                                       f" {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidClusterNameError(f"Provided cluster name \"{cluster_name}\" was not found.")
        return self._parser.build_kube_cluster_node_pool_obj_list(response.json())

    def set_cluster_node_pool_autoscaling(self, zone_name: str, cluster_name: str, node_pool_name: str, autoscaling_enabled: Optional[bool] = None,
                                          min_node_count: Optional[int] = None, max_node_count: Optional[int] = None):
        """
        Sets the autoscaling settings for the specified node pool.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster the node pool belongs to
        :param node_pool_name: {str} The name of the node pool to set autoscaler settings for
        :param autoscaling_enabled: {bool} Is autoscaling enabled for this node pool
        :param min_node_count: {int} Minimum number of nodes in the NodePool. Must be >= 1 and <= maxNodeCount
        :param max_node_count: {int} Maximum number of nodes in the NodePool. Must be >= minNodeCount. There has to be enough quota to scale up the cluster
        :return: {KubeClusterOperation} Kubernetes cluster operation data model
        """
        response = self._session.post(
            self._get_full_url("set-cluster-node-pool-autoscaling", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name,
                               node_pool_name=node_pool_name),
            json={
                "autoscaling": remove_none_values({
                    "enabled": autoscaling_enabled,
                    "minNodeCount": min_node_count,
                    "maxNodeCount": max_node_count,
                    "autoprovisioned": False
                })
            }
        )

        try:
            self.validate_response(response,
                                   error_msg=f"Failed to update cluster's \"{cluster_name}\" node pool \"{node_pool_name}\" with autoscaler settings in"
                                             f" {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKEInvalidNodePoolNameError:
            raise GoogleGKEInvalidNodePoolNameError(f"Provided node pool name \"{node_pool_name}\" was not found.")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidClusterNameError(f"Provided cluster name \"{cluster_name}\" was not found.")
        return self._parser.build_kube_cluster_operation_obj(response.json(), cluster_name=cluster_name)

    def get_cluster_node_pool(self, zone_name: str, cluster_name: str, node_pool_name: str):
        """
        Retrieves the requested node pool.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster to retrieve the node pool from
        :param node_pool_name: {str} The name of the node pool to retrieve
        :return: {KubeClusterNodePool} Kubernetes cluster node pool data model
        """
        response = self._session.get(
            self._get_full_url("get-cluster-node-pool", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name,
                               node_pool_name=node_pool_name))
        try:
            self.validate_response(response,
                                   error_msg=f"Failed to get cluster's \"{cluster_name}\" node pool \"{node_pool_name}\" from zone \"{zone_name}\" in"
                                             f" {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKEInvalidNodePoolNameError:
            raise GoogleGKEInvalidNodePoolNameError(f"Provided node pool name \"{node_pool_name}\" was not found.")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidClusterNameError(f"Provided cluster name \"{cluster_name}\" was not found.")
        return self._parser.build_kube_cluster_node_pool_obj(response.json())

    def set_cluster_node_pool_management(self, zone_name: str, cluster_name: str, node_pool_name: str, auto_upgrade: Optional[bool] = None,
                                         auto_repair: Optional[bool] = None):
        """
        Sets the node management options for the specified node pool.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster the node pool belongs to
        :param node_pool_name: {str} The name of the node pool to set management settings for
        :param auto_upgrade: {bool} A flag that specifies whether node auto-upgrade is enabled for the node pool.
            If enabled, node auto-upgrade helps keep the nodes in your node pool up to date with the latest release version of Kubernetes.
        :param auto_repair: {bool} A flag that specifies whether the node auto-repair is enabled for the node pool.
            If enabled, the nodes in this node pool will be monitored and, if they fail health checks too many times, an automatic repair action will be triggered.
        :return: {KubeClusterOperation} Kubernetes cluster operation data model
        """
        response = self._session.post(
            self._get_full_url("set-cluster-node-pool-management", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name,
                               node_pool_name=node_pool_name),
            json={
                "management": remove_none_values({
                    "autoUpgrade": auto_upgrade,
                    "autoRepair": auto_repair
                })
            }
        )

        try:
            self.validate_response(response,
                                   error_msg=f"Failed to set cluster's \"{cluster_name}\" node pool \"{node_pool_name}\" with management "
                                             f"settings in {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKEInvalidNodePoolNameError:
            raise GoogleGKEInvalidNodePoolNameError(f"Provided node pool name \"{node_pool_name}\" was not found.")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidClusterNameError(f"Provided cluster name \"{cluster_name}\" was not found.")
        return self._parser.build_kube_cluster_operation_obj(response.json(), cluster_name=cluster_name)

    def set_cluster_node_pool_count(self, zone_name: str, cluster_name: str, node_pool_name: str, node_count: int):
        """
        Sets the size for a specific node pool. The new size will be used for all replicas, including future replicas created by modifying NodePool.locations.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the cluster resides
        :param cluster_name: {str} The name of the cluster the node pool belongs to
        :param node_pool_name: {str} The name of the node pool to set the size fore
        :param node_count: {int} The desired node count for the pool.
        :return: {KubeClusterOperation} Kubernetes cluster operation data model
        """
        response = self._session.post(
            self._get_full_url("set-cluster-node-pool-node-count", project_id=self.project_id, zone_name=zone_name, cluster_name=cluster_name,
                               node_pool_name=node_pool_name),
            json={
                "nodeCount": node_count
            }
        )

        try:
            self.validate_response(response,
                                   error_msg=f"Failed to set cluster's \"{cluster_name}\" node pool \"{node_pool_name}\" node count to {node_count} in {INTEGRATION_DISPLAY_NAME}")
        except GoogleGKEInvalidNodePoolNameError:
            raise GoogleGKEInvalidNodePoolNameError(f"Provided node pool name \"{node_pool_name}\" was not found.")
        except GoogleGKENotFoundError:
            raise GoogleGKEInvalidClusterNameError(f"Provided cluster name \"{cluster_name}\" was not found.")
        return self._parser.build_kube_cluster_operation_obj(response.json(), cluster_name=cluster_name)

    def list_operations(self, zone_name: str):
        """
        Lists all operations in a project in a specific zone or all zones.
        :param zone_name: {str} The name of the Google Compute Engine zone in which the clusters resides, or "-" for all zones.
        :return: {[KubeClusterOperation]} List of Kubernetes cluster operation data models
        """
        response = self._session.get(self._get_full_url("list-operations", project_id=self.project_id, zone_name=zone_name))
        self.validate_response(response, error_msg=f"Failed to list operations in {INTEGRATION_DISPLAY_NAME}")
        return self._parser.build_kube_cluster_operation_obj_list(response.json())
