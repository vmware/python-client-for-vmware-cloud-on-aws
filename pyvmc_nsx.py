# NSX Python library for PyVMC

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import sys
import json
from weakref import proxy
import requests
from requests.sessions import session
from requests.auth import HTTPBasicAuth

# ============================
# Search
# ============================
def search_nsx_json(proxy, session_token, object_type):
    """Leverages NSX Search API to return inventory via either NSX or policy API"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/search?query=resource_type:{object_type}"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

# ============================
# Advanced Firewall
# ============================


def get_nsx_ids_cluster_enabled_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def enable_nsx_ids_cluster_json(proxy, session_token, targetID, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs/{targetID}"
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def disable_nsx_ids_cluster_json(proxy, session_token, targetID, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs/{targetID}"
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def enable_nsx_ids_auto_update_json(proxy, session_token, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services"
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def nsx_ids_update_signatures_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/signatures?action=update_signatures"
    response = requests.post(myURL, headers=myHeader)
    if response.status_code == 200:
        return response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def get_ids_signature_versions_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/signature-versions"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_ids_profiles_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/profiles"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_ids_policies_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/domains/cgw/intrusion-service-policies'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


# ============================
# AWS Account and VPC
# ============================


def get_conencted_vpc_json(proxy, session_token):
    """Returns connected VPC information for SDDC via JSON"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/cloud-service/api/v1/infra/linked-vpcs'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_connected_vpc_services_json(proxy, session_token, vpc_id):
    """Returns connected VPC services info via JSON"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/cloud-service/api/v1/infra/linked-vpcs/{vpc_id}/connected-services'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {my_url}.')
        print(json_response['error_message'])



def get_sddc_shadow_account_json(proxy_url, session_token):
    """Returns SDDC shadow account info"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/cloud-service/api/v1/infra/accounts'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {my_url}.')
        print(json_response['error_message'])



def set_connected_vpc_services_json(proxy, session_token, vpc_id, json_data):
    """Based on received value in JSON input, either enables or disables S3 access via connected VPC"""
    my_header = {"Content-Type": "application/json", "Accept": "application/json", 'csp-auth-token': session_token}
    my_url = f'{proxy}/cloud-service/api/v1/infra/linked-vpcs/{vpc_id}/connected-services/s3'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {my_url}.')
        print(response['error_message'])


# ============================
# BGP and Routing
# ============================


def attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json):
    """Creates a new BGP prefix lists for T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
    # json_response = response.json()
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])
    else:
        return response.status_code


def get_sddc_bgp_as_json(proxy_url,sessiontoken):
    """Retrieves BGP Autonomous System Number from DX interface"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/direct-connect/bgp'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_edge_cluster_json(proxy_url, sessiontoken):
    """ Gets the Edge Cluster ID """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/sites/default/enforcement-points/vmc-enforcementpoint/edge-clusters'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_edge_nodes_json(proxy_url, sessiontoken, edge_cluster_id):
    """ Gets the Edge Nodes Path """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/sites/default/enforcement-points/vmc-enforcementpoint/edge-clusters/{edge_cluster_id}/edge-nodes'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_internet_stats_json(proxy_url, sessiontoken, edge_path):
    ### Displays counters for egress interface ###
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/interfaces/public-0/statistics?edge_path={edge_path}&enforcement_point_path=/infra/sites/default/enforcement-points/vmc-enforcementpoint'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_mtu_json(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/external/config'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_t0_advertised_routes_json(proxy, session_token, bgp_neighbor_id):
    """Retrieves BGP learned routes from SDDC T0; applicable to route-based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + bgp_neighbor_id + '/advertised-routes'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_t0_bgp_neighbors_json(proxy, session_token):
    """Retrieves BGP neighbors from SDDC T0 - applicable to route-based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_t0_bgp_single_neighbor_json(proxy, session_token, neighbor_id):
    """Retrives JSON payload describing a single BGP neighbor - applicable to route-based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_bgp_vpn_json(proxy_url, sessiontoken):
    """Retreives preferred path - VPN or DX."""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/direct-connect/bgp'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_t0_learned_routes_json(proxy, session_token, bgp_neighbor_id):
    """Retrieves BGP advertised routes from SDDC T0; applicable to route-based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + bgp_neighbor_id + '/routes'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_t0_prefixlists_json(proxy, session_token):
    """Retrieves BGP prefix lists from SDDC T0; applicable to route-based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_t0_routes_json(proxy, session_token):
    """Retrieves entire route table for SDDC"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/routing-table?enforcement_point_path=/infra/sites/default/enforcement-points/vmc-enforcementpoint'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_t0_static_routes_json(proxy_url, session_token):
    """Retrieves static routes for SDDC"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/static-routes'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def new_bgp_prefix_list_json(proxy, session_token, prefix_list_id, prefix_list):
    """Creates a new BGP prefix lists for T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id
    response = requests.patch(myURL, headers=myHeader, json=prefix_list)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')


def remove_bgp_prefix_list_json(proxy, session_token, prefix_list_id):
    """Removes BGP prefix lists from T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')


def set_sddc_bgp_as_json(proxy,session_token,json_data):
    """Set BGP ASN for DX Interface"""
    myHeader = {'csp-auth-token': session_token}
    proxy_url_short = proxy.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = f'{proxy_url_short}cloud-service/api/v1/infra/direct-connect/bgp'
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')


def set_sddc_mtu_json(proxy_url,sessiontoken,json_data):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/external/config'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')


# ============================
# DNS
# ============================

def get_sddc_dns_services_json(proxy_url,sessiontoken,gw):
    """ Gets the DNS Services. Use 'mgw' or 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = f'{proxy_url_short}policy/api/v1/infra/tier-1s/{gw}/dns-forwarder'
    response = requests.get(myURL, headers=myHeader)
    sddc_dns_service = response.json()
    if response.status_code == 200:
        return sddc_dns_service
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(sddc_dns_service['error_message'])


def get_sddc_dns_zones_json(proxy_url,sessiontoken):
    """ Retreives the SDDC DNS zone configurations."""
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = f'{proxy_url_short}policy/api/v1/infra/dns-forwarder-zones'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


# ============================
# Firewall - Gateway
# ============================

# ============================
# Firewall - Distributed
# ============================


def put_sddc_dfw_rule_json(proxy_url, session_token, section, display_name, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section}/rules/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def put_sddc_dfw_section_json(proxy_url, session_token, display_name, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def delete_sddc_dfw_rule_json(proxy_url, session_token, section, rule_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section}/rules/{rule_id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def delete_sddc_dfw_section_json(proxy_url, session_token, section_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section_id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_dfw_rule_json(proxy_url, session_token, section):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section}/rules'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_dfw_section_json(proxy_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


# ============================
# Firewall Service
# ============================


# ============================
# Inventory Groups
# ============================


# ============================
# NAT
# ============================


def get_sddc_nat_info_json(proxy_url, sessiontoken):
    """Returns JSON response with SDDC NAT rules"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_nat_stats_json(proxy_url, sessiontoken, nat_id):
    """Returns JSON response with NAT statistics for selected NAT rule"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/{nat_id}/statistics'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def new_sddc_nat_json(proxy_url, session_token, display_name, json_data):
    my_header = {"Content-Type": "application/json", "Accept": "application/json", 'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {my_url}.')
        print(json_response['error_message'])


def remove_sddc_nat_json(proxy_url, session_token, nat_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/{nat_id}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {my_url}.')
        print(response['error_message'])


# ============================
# Public IP Addressing
# ============================


def put_sddc_public_ip_json(proxy_url, session_token, ip_id, json_data):
    myHeader = {"Content-Type": "application/json", "Accept": "application/json", 'csp-auth-token': session_token}
    # proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/public-ips/{ip_id}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def delete_sddc_public_ip_json(proxy_url, session_token, ip_id):
    myHeader = {"Content-Type": "application/json", "Accept": "application/json", 'csp-auth-token': session_token}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/public-ips/{ip_id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_public_ip_json(proxy_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/public-ips'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


# ============================
# SDDC - SDCC
# ============================


def get_vms_json(proxy_url, session_token):
    """Returns list of compute VMs via JSON"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/realized-state/enforcement-points/vmc-enforcementpoint/virtual-machines'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {my_url}.')
        print(json_response['error_message'])


# ============================
# Segments
# ============================


def get_cgw_segments_json(proxy_url, sessiontoken):
    """Returns JSON response with all CGW segments in the SDDC"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def new_sddc_networks_json(proxy_url, sessiontoken, display_name, json_data):
    """ Creates a new SDDC Network. L2 VPN networks are not currently supported. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments/" + display_name)
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        sys.exit(json_response['error_message'])


def new_sddc_stretched_networks_json(proxy_url, sessiontoken, display_name, json_data):
    """ Creates a new stretched/extended Network. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        sys.exit(json_response['error_message'])


def remove_sddc_networks_json(proxy_url, sessiontoken, network_id):
    """ Remove an SDDC Network """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments/{network_id}'
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        sys.exit(f'API call failed with status code {response.status_code}. URL: {myURL}.')

# ============================
# VPN
# ============================


def vpn_public_ip_json(proxy_url, sessiontoken):
    """Returns JSON response with SDDC User Config"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/sddc-user-config'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_sddc_vpn_info_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN session info"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_vpn_ipsec_profile_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN IPSEC profiles for the SDDC"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_vpn_ike_profile_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN IKE profiles for the SDDC"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_l2vpn_service_json(proxy_url, sessiontoken):
    """Returns JSON response with L2VPN services"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_l2vpn_session_json(proxy_url, sessiontoken):
    """Returns JSON response with L2VPN session"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_vpn_stats_json(proxy_url, session_token, tunnel_id):
    """returns JSON response with VPN statistics"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{tunnel_id}/statistics'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_ipsec_vpn_services(proxy_url, session_token, vpn_id):
    """returns JSON response with VPN services"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{vpn_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_ipsec_vpn_endpoints(proxy_url, session_token):
    """returns JSON response with IPSEC VPN endpoints"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def new_ipsec_vpn_session_json(proxy_url, session_token, json_data, display_name):
    """Creates new IPSEC VPN session and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def new_ipsec_vpn_profile_json(proxy_url, session_token, display_name, json_data):
    """Creates new IPSEC VPN Profile and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def new_ipsec_vpn_ike_profile_json(proxy_url, session_token, display_name, json_data):
    """Creates new IPSEC VPN IKE profile and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def new_l2vpn_json (proxy_url, session_token, display_name, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response['error_message'])


def delete_ipsec_vpn_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{vpn_id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def delete_l2vpn_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions/{vpn_id}'
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')


def delete_ipsec_vpn_profile_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/{vpn_id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def delete_ipsec_vpn_ike_profile_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles/{id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])
