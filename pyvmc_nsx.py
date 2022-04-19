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
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/{neighbor_id}'
    response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, myURL

def detach_sddc_t0_prefix_lists(proxy, session_token, neighbor_id, neighbor_json):
    """Detach all prefix lists from specified BGP neighbor"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/{neighbor_id}'
    response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, myURL

def get_sddc_bgp_as_json(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/direct-connect/bgp'
    response = requests.get(myURL, headers=myHeader)
    sddc_bgp_as_response_status_code = response.status_code
    json_response = response.json()
    sddc_bgp_as = response_json['local_as_num']
    return sddc_bgp_as, json_response, sddc_bgp_as_response_status_code, myURL

def get_sddc_bgp_vpn_json(proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/direct-connect/bgp'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, myURL

def get_sddc_edge_cluster_json(proxy, sessiontoken):
    """ Gets the Edge Cluster ID """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy}/policy/api/v1/infra/sites/default/enforcement-points/vmc-enforcementpoint/edge-clusters'
    response = requests.get(myURL, headers=myHeader)
    edge_json_response_status_code = response.status_code
    edge_json_response = response.json()
    return edge_json_response, edge_json_response_status_code, myURL

def get_sddc_edge_nodes_json(proxy, sessiontoken, edge_cluster_id, edge_id):
    """ Gets the Edge Nodes Path """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy}/policy/api/v1/infra/sites/default/enforcement-points/vmc-enforcementpoint/edge-clusters/{edge_cluster_id}/edge-nodes'
    edge_path_response = requests.get(myURL, headers=myHeader)
    edge_path_response_status_code = edge_path_response.status_code
    edge_path_response_json = edge_path_response.json()
    edge_path = edge_path_response_json['results'][edge_id]['path']
    return edge_path, edge_path_response_json, edge_path_response_status_code, myURL

def get_sddc_internet_stats_json(proxy, sessiontoken, edge_path):
    """ Displays counters for egress interface """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/interfaces/public-0/statistics?edge_path={edge_path}&enforcement_point_path=/infra/sites/default/enforcement-points/vmc-enforcementpoint'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_mtu_json(proxy,sessiontoken):
    """Retrieves the MTU for the DX interface"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy}/cloud-service/api/v1/infra/external/config'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_t0_advertised_routes_json(proxy, session_token, bgp_neighbor_id):
    """Retreives routes advertised by BGP over Route-based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + bgp_neighbor_id + '/advertised-routes'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_t0_bgp_neighbors_json(proxy, session_token):
    """Retreives BGP neighbors to T0 edge gateway"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_t0_bgp_single_neighbor_json(proxy, session_token, neighbor_id):
    """Retreives a single BGP neighbor to T0 edge gateway"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/{neighbor_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_t0_learned_routes_json(proxy, session_token, bgp_neighbor_id):
    """Retreives routes learned by BGP over Route-based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/{bgp_neighbor_id}/routes'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_t0_prefixlists_json(proxy, session_token):
    """Retreives current prefix lists configured for T0 router"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_t0_routes_json(proxy, session_token):
    """Retreives all routes configured on T0 edge router"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/routing-table?enforcement_point_path=/infra/sites/default/enforcement-points/vmc-enforcementpoint'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def get_sddc_t0_static_routes_json(proxy, session_token):
    """Retreives static routes configured on SDDC"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/static-routes'
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def new_bgp_prefix_list_json(proxy, session_token, prefix_list_id, prefix_list):
    """Creates a new BGP prefix lists for T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/{prefix_list_id}'
    response = requests.patch(myURL, headers=myHeader, json=prefix_list)
    json_response_status_code = response.status_code
    return json_response_status_code, myURL
    
def remove_bgp_prefix_list_json(proxy, session_token, prefix_list_id):
    """Removes BGP prefix lists from T0 edge gateway - applicable for route based VPN"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{proxy}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/{prefix_list_id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code, myURL

def set_mtu_json(proxy, sessiontoken, mtu):
    """Sets MTU size used by DX interface"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy}/cloud-service/api/v1/infra/external/config'
    json_data = {
    "intranet_mtu" : mtu
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    json_response = response.json()
    return json_response, json_response_status_code, myURL

def set_sddc_bgp_as_json(proxy_url,sessiontoken,asn_data):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/direct-connect/bgp'
    response = requests.patch(myURL, headers=myHeader, json=asn_data)
    json_response = response.json()
    asn_response_status_code = response.status_code
    return asn_response_status_code, json_response, myURL

# ============================
# DNS
# ============================

def get_sddc_dns_services_json(proxy_url,sessiontoken,gw):
    """Return the DNS service configuration"""
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/tier-1s/" + gw + "/dns-forwarder"
    response = requests.get(myURL, headers=myHeader)
    sddc_dns_service = response.json()
    sddc_dns_service_status_code = response.status_code
    return sddc_dns_service, sddc_dns_service_status_code, myURL

def get_sddc_dns_zones_json(proxy_url,sessiontoken):
    """ Gets the SDDC Zones """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = f'{proxy_url_short}policy/api/v1/infra/dns-forwarder-zones'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, myURL

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

def remove_sddc_networks_json(proxy_url, sessiontoken, network_id):
    """ Remove an SDDC Network """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments/{network_id}'
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code, myURL

def new_sddc_networks_json(proxy_url, sessiontoken, display_name, json_data):
    """Creates a new routed or disconnected segment"""
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, myURL

def new_sddc_stretched_networks_json(proxy_url, sessiontoken, display_name, json_data):
    """ Creates a new stretched/extended Network. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments/{display_name}'
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, myURL

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
