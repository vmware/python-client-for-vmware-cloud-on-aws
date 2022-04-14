import json
from weakref import proxy
import requests
from requests.sessions import session
from requests.auth import HTTPBasicAuth


# ============================
# Advanced Firewall
# ============================

def get_nsx_ids_cluster_enabled_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

def enable_nsx_ids_cluster_json(proxy, session_token, targetID, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs/{targetID}"
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    return response, myURL

def disable_nsx_ids_cluster_json(proxy, session_token, targetID, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/cluster-configs/{targetID}"
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    return response, myURL

def enable_nsx_ids_auto_update_json(proxy, session_token, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services"
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    return response, myURL

def nsx_ids_update_signatures_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/signatures?action=update_signatures"
    response = requests.post(myURL, headers=myHeader)
    return response, myURL

def get_ids_signature_versions_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/signature-versions"
    response = requests.get(myURL, headers=myHeader)
    sig_response = response.json()
    return sig_response

def get_ids_profiles_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{proxy}/policy/api/v1/infra/settings/firewall/security/intrusion-services/profiles"
    response = requests.get(myURL, headers=myHeader)
    prof_response = response.json()
    return prof_response

def get_ids_policies_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/domains/cgw/intrusion-service-policies'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

# ============================
# BGP and Routing
# ============================
def attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json):
    """Creates a new BGP prefix lists for T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
    return response

def get_sddc_t0_advertised_routes_json(proxy, session_token, bgp_neighbor_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + bgp_neighbor_id + '/advertised-routes'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def get_sddc_t0_bgp_neighbors_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def detach_sddc_t0_prefix_lists(proxy, session_token, neighbor_id, neighbor_json):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
    if response.status_code != 200:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def get_sddc_t0_bgp_single_neighbor_json(proxy, session_token, neighbor_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.get(myURL, headers=myHeader)
    return response

def get_sddc_t0_learned_routes_json(proxy, session_token, bgp_neighbor_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + bgp_neighbor_id + '/routes'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def get_sddc_t0_prefixlists_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def get_sddc_t0_routes_json(proxy, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/routing-table?enforcement_point_path=/infra/sites/default/enforcement-points/vmc-enforcementpoint'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def new_bgp_prefix_list_json(proxy, session_token, prefix_list_id, prefix_list):
    """Creates a new BGP prefix lists for T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id
    response = requests.patch(myURL, headers=myHeader, json=prefix_list)
    json_response = response.status_code
    return json_response

def remove_bgp_prefix_list_json(proxy, session_token, prefix_list_id):
    """Removes BGP prefix lists from T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.status_code
    return json_response

# ============================
# DNS
# ============================


# ============================
# Firewall - Gateway
# ============================

# ============================
# Firewall - Distributed
# ============================


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
    json_response_status_code = response.status_code
    return json_response, json_response_status_code


def get_nat_stats_json(proxy_url, sessiontoken, nat_id):
    """Returns JSON response with NAT statistics for selected NAT rule"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/{nat_id}/statistics'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code



# ============================
# Public IP Addressing
# ============================


# ============================
# Segments
# ============================


def get_cgw_segments_json(proxy_url, sessiontoken):
    """Returns JSON response with all CGW segments in the SDDC"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


# ============================
# VPN
# ============================


def vpn_public_ip_json(proxy_url, sessiontoken):
    """Returns JSON response with SDDC User Config"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/sddc-user-config'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_sddc_vpn_info_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN session info"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code


def get_vpn_ipsec_profile_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN IPSEC profiles for the SDDC"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_vpn_ike_profile_json(proxy_url, sessiontoken):
    """Returns JSON response with VPN IKE profiles for the SDDC"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_l2vpn_service_json(proxy_url, sessiontoken):
    """Returns JSON response with L2VPN services"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_l2vpn_session_json(proxy_url, sessiontoken):
    """Returns JSON response with L2VPN session"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_vpn_stats_json(proxy_url, session_token, tunnel_id):
    """returns JSON response with VPN statistics"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{tunnel_id}/statistics'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_ipsec_vpn_services(proxy_url, session_token, vpn_id):
    """returns JSON response with VPN services"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{vpn_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_ipsec_vpn_endpoints(proxy_url, session_token):
    """returns JSON response with IPSEC VPN endpoints"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def new_ipsec_vpn_session_json(proxy_url, session_token, json_data, display_name):
    """Creates new IPSEC VPN session and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code


def new_ipsec_vpn_profile_json(proxy_url, session_token, display_name, json_data):
    """Creates new IPSEC VPN Profile and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code


def new_ipsec_vpn_ike_profile_json(proxy_url, session_token, display_name, json_data):
    """Creates new IPSEC VPN IKE profile and returns HTML status code"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code


def new_l2vpn_json (proxy_url, session_token, display_name, json_data):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code


def delete_ipsec_vpn_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/{vpn_id}'
    json_response = requests.delete(myURL, headers=myHeader)
    return json_response


def delete_l2vpn_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions/{vpn_id}'
    json_response = requests.delete(myURL, headers=myHeader)
    return json_response


def delete_ipsec_vpn_profile_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/{vpn_id}'
    json_response = requests.delete(myURL, headers=myHeader)
    return json_response


def delete_ipsec_vpn_ike_profile_json(proxy_url, session_token, vpn_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles/{id}'
    json_response = requests.delete(myURL, headers=myHeader)
    return json_response
