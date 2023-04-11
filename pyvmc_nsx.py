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
# Global error handling
# ============================

def nsx_error_handling(fxn_response):
    code = fxn_response.status_code
    print (f'API call failed with status code {code}.')
    if code == 301:
        print(f'Error {code}: "Moved Permanently"')
        print("Request must be reissued to a different controller node.")
        print("The controller node has been replaced by a new node that should be used for this and all future requests.")
    elif code ==307:
        print(f'Error {code}: "Temporary Redirect"')
        print("Request should be reissued to a different controller node.")
        print("The controller node is requesting the client make further requests against the controller node specified in the Location header. Clients should continue to use the new server until directed otherwise by the new controller node.")
    elif code ==400:
        print(f'Error {code}: "Bad Request"')
        print("Request was improperly formatted or contained an invalid parameter.")
    elif code ==401:
        print(f'Error {code}: "Unauthorized"')
        print("The client has not authenticated.")
        print("It's likely your refresh token is out of date or otherwise incorrect.")
    elif code ==403:
        print(f'Error {code}: "Forbidden"')
        print("The client does not have sufficient privileges to execute the request.")
        print("The API is likely in read-only mode, or a request was made to modify a read-only property.")
        print("It's likely your refresh token does not provide sufficient access.")
    elif code ==409:
        print(f'Error {code}: "Temporary Redirect"')
        print("The request can not be performed because it conflicts with configuration on a different entity, or because another client modified the same entity.")
        print("If the conflict arose because of a conflict with a different entity, modify the conflicting configuration. If the problem is due to a concurrent update, re-fetch the resource, apply the desired update, and reissue the request.")
    elif code ==412:
        print(f'Error {code}: "Precondition Failed"')
        print("The request can not be performed because a precondition check failed. Usually, this means that the client sent a PUT or PATCH request with an out-of-date _revision property, probably because some other client has modified the entity since it was retrieved. The client should re-fetch the entry, apply any desired changes, and re-submit the operation.")
    elif code ==500:
        print(f'Error {code}: "Internal Server Error"')
        print("An internal error occurred while executing the request. If the problem persists, perform diagnostic system tests, or contact your support representative.")
    elif code ==503:
        print(f'Error {code}: "Service Unavailable"')
        print("The request can not be performed because the associated resource could not be reached or is temporarily busy. Please confirm the ORG ID and SDDC ID entries in your config.ini are correct.")
    else:
        print(f'Error: {code}: Unknown error')
    try:
        json_response = fxn_response.json()
        if 'error_message' in json_response:
            print(json_response['error_message'])
        if 'related_errors' in json_response:
            print("Related Errors")
            for r in json_response['related_errors']:
                print(r['error_message'])
    except:
        print("No additional information in the error response.")
    return None


# ============================
# Search
# ============================


def search_nsx_json(proxy, session_token, object_type, object_id):
    """Leverages NSX Search API to return inventory via either NSX or policy API"""
    myHeader = {'csp-auth-token': session_token}
    if object_id == "NULL":
        myURL = f"{proxy}/policy/api/v1/search?query=resource_type:{object_type}"
    else:
        myURL = f"{proxy}/policy/api/v1/search?query=resource_type:{object_type} AND display_name:{object_id}"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def search_nsx_json_cursor(proxy, session_token, object_type, object_id, cursor):
    """Leverages NSX Search API to return inventory via either NSX or policy API"""
    my_header = {'csp-auth-token': session_token}
    if object_id == "NULL":
        my_url = f"{proxy}/policy/api/v1/search?query=resource_type:{object_type}&cursor={cursor}"
    else:
        my_url = f"{proxy}/policy/api/v1/search?query=resource_type:{object_type} AND display_name:{object_id}&cursor={cursor}"
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])


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
        return None


def get_nsx_ids_cluster_config_json(proxy, session_token, cluster_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs/{cluster_id}"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])
        return None


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
        return None



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
        return None


def enable_nsx_ids_auto_update_json(proxy, session_token, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services"
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    status = response.status_code
    if status == 202:
        return response
    else:
        json_response = response.json()
        if status == 400:
            print(f"Error Code {status}: Bad Request.")
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None
        elif status == 403:
            print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None
        elif status == 503:
            print(f"Error Code {status}: Service Unavailable.")
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None
        else:
            print(f'Status code: {status}: Unknown error')
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None

def nsx_ids_update_signatures_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/signatures?action=update_signatures"
    response = requests.post(myURL, headers=myHeader)
    status = response.status_code
    if response.status_code == 202:
        return response
    else:
        json_response = response.json()
        if status == 400:
            print(f"Error Code {status}: Bad Request.")
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None
        elif status == 403:
            print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None
        elif status == 503:
            print(f"Error Code {status}: Service Unavailable.")
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None
        else:
            print(f'Status code: {status}: Unknown error')
            if 'error_message' in json_response:
                print(json_response['error_message'])
            return None

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


def patch_ips_profile_json(proxy, session_token, json_data, display_name):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/profiles/{display_name}'
    response = requests.patch(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 412:
        print(f'There is an issue in URL: {my_url}')
        print(f'Please check your syntax')
    else:
        json_response = response.json()
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])

def delete_ips_profile_json(proxy, session_token, display_name):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/profiles/{display_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 412:
        print(f'There is an issue in URL: {my_url}')
        print(f'Please check your syntax')
    else:
        json_response = response.json()
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])


def put_ids_policy_json(proxy, session_token, json_data, display_name):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/domains/cgw/intrusion-service-policies/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 412:
        print(f'There is an issue in URL: {my_url}')
        print(f'Please check your syntax')
    else:
        json_response = response.json()
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])


def get_ids_rule_json(proxy, session_token, ids_policy_name):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/domains/cgw/intrusion-service-policies/{ids_policy_name}/rules'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    elif response.status_code == 412:
        print(f'There is an issue in URL: {my_url}')
        print(f'Please check your syntax')
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])


def put_ids_rule_json(proxy, session_token, display_name, ids_policy_name, json_data):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/domains/cgw/intrusion-service-policies/{ids_policy_name}/rules/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 412:
        print(f'There is an issue in URL: {my_url}')
        print(f'Please check your syntax')
    else:
        json_response = response.json()
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])


def delete_ids_rule_json(proxy, session_token, display_name, ids_policy_name):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/domains/cgw/intrusion-service-policies/{ids_policy_name}/rules/{display_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 404:
        print(f'There is an issue in URL: {my_url}')
        print(f'Please check your syntax')
    else:
        json_response = response.json()
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])


def delete_ids_policy_json(proxy, session_token, ids_policy_name):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/domains/cgw/intrusion-service-policies/{ids_policy_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 412:
        print(f'There is an issue in URL: {my_url}')
        print(f'Please check your syntax')
    else:
        json_response = response.json()
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        sys.exit(json_response['error_message'])


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
        return None


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
        return None



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
        return None


# ============================
# BGP and Routing
# ============================


def attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json):
    """Creates a new BGP prefix lists for T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
    # json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
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
        return False


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
        return False


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
        return False


def get_sddc_mtu_json(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/external/config'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 504:
        print("Error Code 504: Gateway Timeout: Likely an SDDC ID misconfiguration")
        return False
        
    json_response = response.json()
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
    else:
        json_response = response.json()
        return json_response


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
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
    else:
        json_response = response.json()
        return json_response


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
        return False


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
        return False


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
        sys.exit(1)

def remove_bgp_prefix_list_json(proxy, session_token, prefix_list_id):
    """Removes BGP prefix lists from T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return response.status_code


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
        return False
    else:
        return True


def set_sddc_mtu_json(proxy_url,sessiontoken,json_data):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/external/config'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
    else:
        return True


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

def create_gwfw_rule(proxy, sessiontoken, gw, display_name, json_data):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy}/policy/api/v1/infra/domains/{gw}/gateway-policies/default/rules/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    status = response.status_code
    if status == 200:
        return status
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None

def delete_gwfw_rule(proxy_url, sessiontoken, gw, rule_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/gateway-policies/default/rules/{rule_id}'
    response = requests.delete(myURL, headers=myHeader)
    status = response.status_code
    if status == 200:
        return status
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")

        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        return None

def get_gwfw_rules(proxy, sessiontoken, gw):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy}/policy/api/v1/infra/domains/{gw}/gateway-policies/default/rules'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    status = response.status_code
    if status == 200:
        return json_response
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None


# ============================
# Firewall - Distributed
# ============================


def put_sddc_dfw_rule_json(proxy_url, session_token, section, display_name, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section}/rules/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    status= response.status_code
    if status == 200:
        return status
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None


def put_sddc_dfw_section_json(proxy_url, session_token, display_name, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    status= response.status_code
    if status == 200:
        return status
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None


def delete_sddc_dfw_rule_json(proxy_url, session_token, section, rule_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section}/rules/{rule_id}'
    response = requests.delete(myURL, headers=myHeader)
    status= response.status_code
    if status == 200:
        return status
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        return None

def delete_sddc_dfw_section_json(proxy_url, session_token, section_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section_id}'
    response = requests.delete(myURL, headers=myHeader)
    status= response.status_code
    if status == 200:
        return status
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        return None


def get_sddc_dfw_rule_json(proxy_url, session_token, section):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/{section}/rules'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    status= response.status_code
    if status == 200:
        return json_response
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None

def get_sddc_dfw_section_json(proxy_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/cgw/security-policies/'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    status= response.status_code
    if status == 200:
        return json_response
    elif status == 400:
        print(f"Error Code {status}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 403:
        print(f"Error Code {status}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif status == 503:
        print(f"Error Code {status}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {status}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None


# ============================
# Firewall Service
# ============================

def new_sddc_service_json(proxy,sessiontoken,service_id,json_data, patch_mode=False):
    myHeader = {'csp-auth-token': sessiontoken}
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    proxy_url_short = proxy.rstrip("sks-nsxt-manager")
    myURL = f'{proxy_url_short}policy/api/v1/infra/services/{service_id}'
    if patch_mode:
        response = requests.patch(myURL, headers=myHeader, json=json_data)
    else:
        response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_sddc_service_json(proxy, sessiontoken, service_id):
    myHeader = {'csp-auth-token': sessiontoken}
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    proxy_url_short = proxy.rstrip("sks-nsxt-manager")
    myURL = f'{proxy_url_short}policy/api/v1/infra/services/{service_id}'
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None

def get_sddc_services_json(proxy_url,sessiontoken):
    """ Gets the SDDC Services """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = f'{proxy_url_short}policy/api/v1/infra/services'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        return response
    else:
        nsx_error_handling(response)
        return None

def get_sddc_single_service_json(proxy_url,sessiontoken, service_id):
    """ Returns a single SDDC Service """
    myHeader = {'csp-auth-token': sessiontoken}
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    myURL = f'{proxy_url_short}policy/api/v1/infra/services/{service_id}'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        return response
    else:
        nsx_error_handling(response)
        return None


# ============================
# Inventory Groups
# ============================


def put_sddc_inventory_group_json_response(proxy_url, session_token, json_data, gw, group_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def get_sddc_inventory_groups_json(proxy_url, session_token, gw):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_sddc_inventory_group_id_json(proxy_url, session_token, gw, group_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_inventory_group_vm_membership_json(proxy_url, session_token, gw, group_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}/members/virtual-machines'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_inventory_group_ip_address_json(proxy_url, session_token, gw, group_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}/members/ip-addresses'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_inventory_group_segment_json(proxy_url, session_token, gw, group_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}/members/segments'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_inventory_group_segment_port_json(proxy_url, session_token, gw, group_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}/members/segment-ports'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_inventory_group_vif_json(proxy_url, session_token, gw, group_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}/members/vifs'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None

def get_inventory_group_association_json(proxy_url, session_token, gw, group_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/group-service-associations?intent_path=/infra/domains/{gw}/groups/{group_id}'
    response = requests.get(my_url, headers=my_header)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        nsx_error_handling(response)
        return None

def delete_inventory_group_json_response(proxy_url, session_token, gw, group_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/domains/{gw}/groups/{group_id}'
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


# ============================
# NAT
# ============================


def get_sddc_nat_info_json(proxy_url, sessiontoken, tier1_id):
    """Returns JSON response with SDDC NAT rules"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/{tier1_id}/nat/USER/nat-rules'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_nat_stats_json(proxy_url, sessiontoken, nat_id, tier1_id):
    """Returns JSON response with NAT statistics for selected NAT rule"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/{tier1_id}/nat/USER/nat-rules/{nat_id}/statistics'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def new_sddc_nat_json(proxy_url, session_token, display_name, tier1_id, json_data):
    my_header = {"Content-Type": "application/json", "Accept": "application/json", 'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{tier1_id}/nat/USER/nat-rules/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def remove_sddc_nat_json(proxy_url, session_token, nat_id, tier1_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{tier1_id}/nat/USER/nat-rules/{nat_id}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response
    else:
        nsx_error_handling(response)
        return None


# ============================
# Public IP Addressing
# ============================


def put_sddc_public_ip_json(proxy_url, session_token, ip_id, json_data):
    myHeader = {"Content-Type": "application/json", "Accept": "application/json", 'csp-auth-token': session_token}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/public-ips/{ip_id}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    # json_response = response.json()
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 400:
        print(f"Error Code {response.status_code}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif response.status_code == 403:
        print(f"Error Code {response.status_code}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif response.status_code == 503:
        print(f"Error Code {response.status_code}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {response.status_code}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None

def delete_sddc_public_ip_json(proxy_url, session_token, ip_id):
    myHeader = {"Content-Type": "application/json", "Accept": "application/json", 'csp-auth-token': session_token}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/public-ips/{ip_id}'
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code == 200:
        return response.status_code
    elif response.status_code == 400:
        print(f"Error Code {response.status_code}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif response.status_code == 403:
        print(f"Error Code {response.status_code}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif response.status_code == 503:
        print(f"Error Code {response.status_code}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {response.status_code}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None



def get_sddc_public_ip_json(proxy_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/public-ips'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    elif response.status_code == 400:
        print(f"Error Code {response.status_code}: Bad Request.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif response.status_code == 403:
        print(f"Error Code {response.status_code}: You are forbidden to use this operation. See your administrator")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    elif response.status_code == 503:
        print(f"Error Code {response.status_code}: Service Unavailable.")
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None
    else:
        print(f'Status code: {response.status_code}: Unknown error')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None



# ============================
# SDDC - SDCC
# ============================


#
# https://developer.vmware.com/apis/nsx-vmc-policy/latest/policy/api/v1/infra/realized-state/virtual-machines/get/
#

def get_vms_json(proxy_url, session_token):
    """Returns list of compute VMs via JSON"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/realized-state/enforcement-points/vmc-enforcementpoint/virtual-machines'
    response = requests.get(my_url, headers=my_header)
    json_response = None
    if response.status_code != 504:
        # because response is in HTML
        json_response = response.json()

    if response.status_code == 200:
        return json_response
    elif response.status_code == 400:
        print('Bad Request')
    elif response.status_code == 403:
        print("API Call Forbidden")
    elif response.status_code == 404:
        print("API URL Not Found")
    elif response.status_code == 412:
        print("API Pre-Condition Failed")
    elif response.status_code == 500:
        print("Internal Server Error")
    elif response.status_code == 503:
        print("API Server Unavailable")
    elif response.status_code == 504:
        print("API Call Unknown Error. Likely an API timeout due to misconfiguration, or a bad SDDC ID in config.ini")
        print(response.content.decode("utf-8", "ignore") )
        return None
    else:
        print("There was an error. Check the syntax.")
        return None
    
    if 'error_message' in json_response:
        print(json_response['error_message'])
    print (f'API call failed with status code {response.status_code}. URL: {my_url}.')

    return None



# ============================
# T1 Gateways
# ============================

def create_t1_json(proxy_url, sessiontoken, t1_id, json_data):
    """Creates a new T1 Gateway and returns the HTTP status code"""
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1_id}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        sys.exit(1)

def configure_t1_json(proxy_url, sessiontoken, t1_id, json_data):
    """ Configures a Tier1 router as 'ROUTED', 'ISOLATED', or 'NATTED'... Creates a new T1 if it doesn't already exist."""
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1_id}'
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        sys.exit(1)

def delete_t1_json(proxy_url, sessiontoken, t1_id):
    """ Deletes a Tier1 router."""
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1_id}'
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_t1_json(proxy, session_token):
    """Returns JSON body with all SDDC Tier-1 Gateways"""
    my_header = my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


# ============================
# Segments
# ============================

def new_segment_json(proxy_url, sessiontoken, segment_name, segment_type, json_data):
    my_header = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    if segment_type == "fixed":
        myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments/{segment_name}'
    else:
        myURL = f'{proxy_url}/policy/api/v1/infra/segments/{segment_name}'
    response = requests.put(myURL, headers=my_header, json=json_data)
    json_response = response.json()    
    if response.status_code == 200:
        return response.status_code
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])
        return response.status_code


def configure_segment_json(proxy_url, sessiontoken, segment_path, json_data):
    my_header = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1{segment_path}'
    response = requests.patch(myURL, headers=my_header, json=json_data)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
    return response.status_code


def remove_segment_json(proxy_url, sessiontoken, segment_path):
    my_header = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1{segment_path}'
    response = requests.delete(myURL, headers=my_header)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
    return response.status_code


def connect_segment_json(proxy_url, sessiontoken, network_id, json_data):
    """ Connects or disconnects an existing SDDC Network on the default CGW. L2 VPN networks are not currently supported. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments/{network_id}'
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    if response.status_code != 200:
        print("There was an error. Check the syntax.")
        sys.exit(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        
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
        return False


def new_sddc_networks_json(proxy_url, sessiontoken, display_name, json_data):
    """ Creates a new SDDC Network. L2 VPN networks are not currently supported. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments/" + display_name)
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
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


def get_sddc_vpn_info_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN session info"""
    my_header = {'csp-auth-token': sessiontoken}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/ipsec-vpn-services/default/sessions'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_vpn_ipsec_profile_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN IPSEC profiles for the SDDC"""
    my_header = {'csp-auth-token': sessiontoken}
    my_url = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_vpn_ipsec_profile_details_json(proxy, session_token, tunnel_path):
    """Returns JSON body with VPN IPSec Tunnel profile details"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1{tunnel_path}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_vpn_ike_profile_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN IKE profiles for the SDDC"""
    my_header = {'csp-auth-token': sessiontoken}
    my_url = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_vpn_ike_profile_details_json(proxy, session_token, ike_path):
    """Returns the JSON body for a provided VPN IKE profile path"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1{ike_path}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_vpn_dpd_profile_json(proxy, sessiontoken):
    """Returns JSON bosy with VPN DPD profiles for the SDDC"""
    my_header = {'csp-auth-token': sessiontoken}
    my_url = f'{proxy}/policy/api/v1/infra/ipsec-vpn-dpd-profiles'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_vpn_dpd_profile_details_json(proxy, session_token, dpd_path):
    """Returns JSON body with VPN DPD profile data based on supplied path URI"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1{dpd_path}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_l2vpn_session_json(proxy_url, sessiontoken):
    """Returns JSON response with SDDC L2VPN session"""
    my_header = {'csp-auth-token': sessiontoken}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/l2vpn-services/default/sessions'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_ipsec_vpn_endpoints_json(proxy_url, session_token):
    """returns JSON response with IPSEC VPN endpoints"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/ipsec-vpn-services/default/local-endpoints'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)

def get_tier1_ipsec_vpn_services_json(proxy_url, session_token, t1g):
    """Returns JSON body with Tier-1 VPN Services"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_l2vpn_services_json(proxy_url, session_token, t1g):
    """Returns JSON body with Tier-1 l2VPN services"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1g}/l2vpn-services'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_vpn_le_json(proxy, session_token, t1g, ipsec_serv):
    """Returns JSON bosy with Tier-1 Local Endpoint for provided gateway and IPSEC servoce"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{ipsec_serv}/local-endpoints'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_vpn_le_details_json(proxy, session_token, le_path):
    """Returns JSON body containing Local Endpoint data for provided LE path"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1{le_path}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_vpn_session_json(proxy, session_token, t1g, ipsec_serv):
    """Returns JSON body with Tier-1 VPN Sessions for each Tier-1 Gateway"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{ipsec_serv}/sessions'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_le_details_json(proxy, session_token, le_path):
    """Returns JSON body with Local Endpoint data for a supplied Local Endpoint URI path"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1{le_path}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        return None


def get_tier1_vpn_details_json(proxy, session_token, t1g, ipsec_serv, display_name):
    """Returns JSON body with Tier-1 VPN session details"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{ipsec_serv}/sessions/{display_name}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_l2vpn_ipsec_json(proxy, session_token, path):
    """Returns JSON bosy for L2VPN IPsec VPN session with provided path"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1{path}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_l2vpn_json(proxy, session_token, t1g, l2vpn_serv):
    """Returns JSON body with Tier-1 L2VPN sessions for a provided Tier-1 Gateway and L2VPN service"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/l2vpn-services/{l2vpn_serv}/sessions'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def get_tier1_l2vpn_details_json(proxy, session_token, t1g, l2vpn_serv, display_name):
    """Returns JSON bosy with Tier-1 L2VPN session details"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/l2vpn-services/{l2vpn_serv}/sessions/{display_name}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        nsx_error_handling(response)
        sys.exit(1)


def new_sddc_ipsec_session_json(proxy_url, session_token, json_data, display_name):
    """Creates new IPSEC VPN session and returns HTML status code"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/ipsec-vpn-services/default/sessions/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_ipsec_vpn_profile_json(proxy_url, session_token, display_name, json_data):
    """Creates new IPSEC VPN Profile and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_ipsec_vpn_ike_profile_json(proxy_url, session_token, display_name, json_data):
    """Creates new IPSEC VPN IKE profile and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_ipsec_vpn_dpd_profile_json(proxy_url, session_token, json_data, display_name):
    """Creates a new IPSEC VPN DPD Profile and returns the HTML status code"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-dpd-profiles/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_t1_ipsec_vpn_service_json(proxy_url, session_token, json_data, display_name, t1g):
    """Creates a new Tier-1 IPSec VPN service and returns the HTML status code"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_t1_l2vpn_service_json(proxy_url, session_token, json_data, display_name, t1g):
    """Creates a new Tier-1 L2VPN service and returns the HTML status code"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1g}/l2vpn-services/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_t1_local_endpoint_json(proxy_url, session_token, json_data, display_name, t1g, service_id):
    """creates a new Tier-1 local endpoint and returns the HTML status code"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{service_id}/local-endpoints/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_t1_ipsec_session_json(proxy_url, session_token, json_data, display_name, t1g, service_id):
    """Creates a new Tier-1 IPSec VPN session and returns the HTML status code"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{service_id}/sessions/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_t1_l2vpn_session_json(proxy_url, session_token, json_data, display_name, t1g, l2vpn_service):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-1s/{t1g}/l2vpn-services/{l2vpn_service}/sessions/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def new_l2vpn_json(proxy_url, session_token, display_name, json_data):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/l2vpn-services/default/sessions/{display_name}'
    response = requests.put(my_url, headers=my_header, json=json_data)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_ipsec_vpn_json(proxy_url, session_token, vpn_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{vpn_id}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_l2vpn_json(proxy_url, session_token, vpn_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/l2vpn-services/default/sessions/{vpn_id}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None

      
def delete_ipsec_vpn_profile_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/{vpn_id}'
    response = requests.delete(myURL, headers=myHeader)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_ipsec_vpn_ike_profile_json(proxy_url, session_token, id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles/{id}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_ipsec_vpn_dpd_profile_json(proxy_url, session_token, dpd_id):
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-dpd-profiles/{dpd_id}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None

  
def delete_tier1_ipsec_vpn_json(proxy, session_token, display_name, t1g, vpn_service):
    """Deletes a Tier-1 IPSec VPN Session"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{vpn_service}/sessions/{display_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_tier1_l2vpn_json(proxy, session_token, display_name, t1g, vpn_service):
    """Deletes a Tier-1 L2VPN Session"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/l2vpn-services/{vpn_service}/sessions/{display_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_tier1_vpn_le_json(proxy, session_token, display_name, t1g, vpn_service):
    """Deletes a Tier-1 VPN Local Endpoint"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/ipsec-vpn-services/{vpn_service}/local-endpoints/{display_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_tier1_vpn_service_json(proxy, session_token, display_name, t1g, vpn_service):
    """Deletes a Tier-1 VPN service"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/tier-1s/{t1g}/{vpn_service}/{display_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None


def delete_vpn_profile(proxy, session_token, display_name, profile):
    """Deletes a custom VPN Profile"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{proxy}/policy/api/v1/infra/{profile}/{display_name}'
    response = requests.delete(my_url, headers=my_header)
    if response.status_code == 200:
        return response.status_code
    else:
        nsx_error_handling(response)
        return None