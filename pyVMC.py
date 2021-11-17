#!/usr/bin/env python3
# The shebang above is to tell the shell which interpreter to use. This make the file executable without "python3" in front of it (otherwise I had to use python3 pyvmc.py)
# I also had to change the permissions of the file to make it run. "chmod +x pyVMC.py" did the trick.
# I also added "export PATH="MY/PYVMC/DIRECTORY":$PATH" (otherwise I had to use ./pyvmc.y)
# For git BASH on Windows, you can use something like this #!/C/Users/usr1/AppData/Local/Programs/Python/Python38/python.exe

# Python Client for VMware Cloud on AWS

################################################################################
### Copyright (C) 2019-2021 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################


"""

Welcome to PyVMC ! 

VMware Cloud on AWS API Documentation is available at: https://code.vmware.com/apis/920/vmware-cloud-on-aws
CSP API documentation is available at https://console.cloud.vmware.com/csp/gateway/api-docs
vCenter API documentation is available at https://code.vmware.com/apis/366/vsphere-automation


You can install python 3.8 from https://www.python.org/downloads/windows/ (Windows) or https://www.python.org/downloads/mac-osx/ (MacOs).

You can install the dependent python packages locally (handy for Lambda) with:
pip3 install requests or pip3 install requests -t . --upgrade
pip3 install configparser or pip3 install configparser -t . --upgrade
pip3 install PTable or pip3 install PTable -t . --upgrade

With git BASH on Windows, you might need to use 'python -m pip install' instead of pip3 install

"""

import requests                         # need this for Get/Post/Delete
import configparser                     # parsing config file
import operator
import time
import json
import sys
from prettytable import PrettyTable
from deepdiff import DeepDiff

config = configparser.ConfigParser()
config.read("./config.ini")
strProdURL      = config.get("vmcConfig", "strProdURL")
strCSPProdURL   = config.get("vmcConfig", "strCSPProdURL")
Refresh_Token   = config.get("vmcConfig", "refresh_Token")
ORG_ID          = config.get("vmcConfig", "org_id")
SDDC_ID         = config.get("vmcConfig", "sddc_id")




class data():
    sddc_name       = ""
    sddc_status     = ""
    sddc_region     = ""
    sddc_cluster    = ""
    sddc_hosts      = 0
    sddc_type       = ""

def getAccessToken(myKey):
    """ Gets the Access Token using the Refresh Token """
    params = {'api_token': myKey}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post('https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize', params=params, headers=headers)
    jsonResponse = response.json()
    access_token = jsonResponse['access_token']
    return access_token

def getConnectedAccounts(tenantid, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = strProdURL + "/vmc/api/orgs/" + tenantid + "/account-link/connected-accounts"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    orgtable = PrettyTable(['OrgID'])
    orgtable.add_row([tenantid])
    print(str(orgtable))
    table = PrettyTable(['Account Number','id'])
    for i in jsonResponse:
        table.add_row([i['account_number'],i['id']])
    return table

def getCompatibleSubnets(tenantid,sessiontoken,linkedAccountId,region):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = strProdURL + "/vmc/api/orgs/" + tenantid + "/account-link/compatible-subnets"
    params = {'org': tenantid, 'linkedAccountId': linkedAccountId,'region': region}
    response = requests.get(myURL, headers=myHeader,params=params)
    jsonResponse = response.json()
    vpc_map = jsonResponse['vpc_map']
    table = PrettyTable(['vpc','description'])
    subnet_table = PrettyTable(['vpc_id','subnet_id','subnet_cidr_block','name','compatible'])
    for i in vpc_map:
        myvpc = jsonResponse['vpc_map'][i]
        table.add_row([myvpc['vpc_id'],myvpc['description']])
        for j in myvpc['subnets']:
            subnet_table.add_row([j['vpc_id'],j['subnet_id'],j['subnet_cidr_block'],j['name'],j['compatible']])
    print(table)
    return subnet_table

def getSDDCS(tenantid, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = strProdURL + "/vmc/api/orgs/" + tenantid + "/sddcs"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    orgtable = PrettyTable(['OrgID'])
    orgtable.add_row([tenantid])
    print(str(orgtable))
    table = PrettyTable(['Name', 'Cloud', 'Status', 'Hosts', 'ID'])
    for i in jsonResponse:
        hostcount = 0
        myURL = strProdURL + "/vmc/api/orgs/" + tenantid + "/sddcs/" + i['id']
        response = requests.get(myURL, headers=myHeader)
        mySDDCs = response.json()

        clusters = mySDDCs['resource_config']['clusters']
        if clusters:
            hostcount = 0
            for c in clusters:
                hostcount += len(c['esx_host_list'])
        table.add_row([i['name'], i['provider'],i['sddc_state'], hostcount, i['id']])
    return table


#-------------------- Show hosts in an SDDC
def getCDChosts(sddcID, tenantid, sessiontoken):

    myHeader = {'csp-auth-token': sessiontoken}
    myURL = strProdURL + "/vmc/api/orgs/" + tenantid + "/sddcs/" + sddcID

    response = requests.get(myURL, headers=myHeader)

    # grab the names of the CDCs
    jsonResponse = response.json()

    # get the vC block (this is a bad hack to get the rest of the host name
    # shown in vC inventory)
    cdcID = jsonResponse['resource_config']['vc_ip']
    cdcID = cdcID.split("vcenter")
    cdcID = cdcID[1]
    cdcID = cdcID.split("/")
    cdcID = cdcID[0]

    # get the hosts block
    clusters = jsonResponse['resource_config']['clusters']
    table = PrettyTable(['Cluster', 'Name', 'Status', 'ID'])
    for c in clusters:
        for i in c['esx_host_list']:
            hostName = i['name'] + cdcID
            table.add_row([c['cluster_name'], hostName, i['esx_state'], i['esx_id']])
    print(table)
    return

#-------------------- Display the users in our org
def showORGusers(tenantid, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    #using @ as our search term...
    myURL = strCSPProdURL + "/csp/gateway/am/api/orgs/" + tenantid + "/users/search?userSearchTerm=%40"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    if str(response.status_code) != "200":
        print("\nERROR: " + str(jsonResponse))
    else:
        # get the results block
        users = jsonResponse['results']
        table = PrettyTable(['First Name', 'Last Name', 'User Name'])
        for i in users:
            table.add_row([i['user']['firstName'],i['user']['lastName'],i['user']['username']])
        print(table)
    return

def getSDDCVPNInternetIP(proxy_url, sessiontoken):
    """ Gets the Public IP used for VPN by the SDDC """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "cloud-service/api/v1/infra/sddc-user-config"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    vpn_internet_IP = json_response['vpn_internet_ips'][0]
    return vpn_internet_IP

def getSDDCState(org_id, sddc_id, sessiontoken):
    """ Gets the overall status of the SDDDC """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = "{}/vmc/api/orgs/{}/sddcs/{}".format(strProdURL, org_id, sddc_id)
    response = requests.get(myURL, headers=myHeader)
    sddc_state = response.json()
    table = PrettyTable(['Name', 'Id', 'Status', 'Type', 'Region', 'Deployment Type'])
    table.add_row([sddc_state['name'], sddc_state['id'], sddc_state['sddc_state'], sddc_state['sddc_type'], sddc_state['resource_config']['region'], sddc_state['resource_config']['deployment_type']])
    return table

def getNSXTproxy(org_id, sddc_id, sessiontoken):
    """ Gets the Reverse Proxy URL """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = "{}/vmc/api/orgs/{}/sddcs/{}".format(strProdURL, org_id, sddc_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    proxy_url = json_response['resource_config']['nsx_api_public_endpoint_url']
    return proxy_url

def getSDDCnetworks(proxy_url, sessiontoken):
    """ Gets the SDDC Networks """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_networks = json_response['results']
    table = PrettyTable(['Name', 'id', 'Type', 'Network', 'Default Gateway'])
    table_extended = PrettyTable(['Name', 'id','Tunnel ID'])
    for i in sddc_networks:
        if ( i['type'] == "EXTENDED"):
            table_extended.add_row([i['display_name'], i['id'], i['l2_extension']['tunnel_id']])
        elif ( i['type'] == "DISCONNECTED"):
            table.add_row([i['display_name'], i['id'], i['type'],"-", "-"])
        else: 
            table.add_row([i['display_name'], i['id'], i['type'], i['subnets'][0]['network'], i['subnets'][0]['gateway_address']])
    print("Routed Networks:")
    print(table)
    print("Extended Networks:")
    print(table_extended)

def newSDDCnetworks(proxy_url, sessiontoken, display_name, gateway_address, dhcp_range, domain_name, routing_type):
    """ Creates a new SDDC Network. L2 VPN networks are not currently supported. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments/" + display_name)
    # print(myURL)
    if routing_type == "DISCONNECTED" :
        json_data = {
                "subnets":[{"gateway_address":gateway_address}],
                "type":routing_type,
                "display_name":display_name,
                "advanced_config":{"connectivity":"OFF"},
                "id":display_name
                }
        response = requests.put(myURL, headers=myHeader, json=json_data)
        json_response_status_code = response.status_code
        if json_response_status_code == 200 :
            print("The following network has been created:")
            table = PrettyTable(['Name', 'Gateway', 'Routing Type'])
            table.add_row([display_name, gateway_address, routing_type])
            return table
        else :
            print("There was an error. Try again.")
            return
    else:
        if dhcp_range == "none" :
            json_data = {
                "subnets":[{"gateway_address":gateway_address}],
                "type":routing_type,
                "display_name":display_name,
                "advanced_config":{"connectivity":"ON"},
                "id":display_name
                }
            response = requests.put(myURL, headers=myHeader, json=json_data)
            json_response_status_code = response.status_code
            if json_response_status_code == 200 :
                print("The following network has been created:")
                table = PrettyTable(['Name', 'Gateway', 'Routing Type'])
                table.add_row([display_name, gateway_address, routing_type])
                return table
            else :
                print("There was an error. Try again.")
                return
        else :
            json_data = {
                "subnets":[{"dhcp_ranges":[dhcp_range],
                "gateway_address":gateway_address}],
                "type":routing_type,
                "display_name":display_name,
                "domain_name":domain_name,
                "advanced_config":{"connectivity":"ON"},
                "id":display_name
                }
            response = requests.put(myURL, headers=myHeader, json=json_data)
            json_response_status_code = response.status_code
            if json_response_status_code == 200 :
                print("The following network has been created:")
                table = PrettyTable(['Name', 'Gateway', 'DHCP', 'Domain Name', 'Routing Type'])
                table.add_row([display_name, gateway_address, dhcp_range, domain_name, routing_type])
                return table
            else :
                print("There was an error. Try again.")
                return

def newSDDCStretchednetworks(proxy_url, sessiontoken, display_name, tunnel_id, l2vpn_path):
    """ Creates a new stretched/extended Network. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments/" + display_name)
    print(myURL)
    json_data = {
                "type":"EXTENDED",
                "display_name":display_name,
                "id":display_name,
                "advanced_config":{"connectivity":"ON"},
                "l2_extension": {
                "l2vpn_paths": [
                l2vpn_path
                ],
                "tunnel_id": tunnel_id}
    }
    print(json_data)
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    if json_response_status_code == 200 :
        print("The following network has been created:")
        table = PrettyTable(['Name', 'Tunnel ID', 'Routing Type'])
        table.add_row([display_name, tunnel_id, "extended"])
        return table
    else :
        print("There was an error. Try again.")
        return

def removeSDDCNetworks(proxy_url, sessiontoken, network_id):
    """ Remove an SDDC Network """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments/" + network_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.status_code
    # print(json_response)
    # Unfortunately, the response status code is always 200 whether or not we delete an existing or non-existing network segment.
    if json_response == 200 :
        print("The network " + network_id + " has been deleted")
    else :
        print("There was an error. Try again.")
    return

def getSDDCNAT(proxy_url, sessiontoken):
    """ Gets the SDDC Nat Rules """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    if json_response_status_code == 200:
        sddc_NAT = json_response['results']
        table = PrettyTable(['ID', 'Name', 'Public IP', 'Ports', 'Internal IP', 'Enabled?'])
        for i in sddc_NAT:
            if 'destination_network' in i:
                table.add_row([i['id'], i['display_name'], i['destination_network'], i['translated_ports'], i['translated_network'], i['enabled']])
            else:
                table.add_row([i['id'], i['display_name'], i['translated_network'], "any", i['source_network'], i['enabled']])
        return table
    else:
        print("There was an issue. Try again.")
        return

def getSDDCNATStatistics(proxy_url, sessiontoken, nat_id):
    ### Displays stats for a specific NAT rule. Note the results are a table with 2 entries.  ###
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/" + nat_id + "/statistics" )
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response = response.json()
    json_response_status_code = response.status_code
    if json_response_status_code == 200:
        sddc_NAT_stats = json_response['results'][0]['rule_statistics']
        table = PrettyTable(['NAT Rule', 'Active Sessions', 'Total Bytes', 'Total Packets'])
        for i in sddc_NAT_stats:
            #  For some reason, the API returns an entry with null values and one with actual data. So I am removing this entry. 
            if (i['active_sessions'] == 0) and (i['total_bytes'] == 0) and (i['total_packets'] == 0):
                # What this code does is simply check if all entries are empty and skip (pass below) before writing the stats.
                pass
            else:
                table.add_row([nat_id, i['active_sessions'], i['total_bytes'], i['total_packets']])
        return table
    else:
        print("There was an issue.")
        return

def newSDDCNAT(proxy_url, sessiontoken, display_name, action, translated_network, source_network, service, translated_port, logging, status):
    """ Creates a new NAT rule """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/" + display_name)
    if action == "any" or action == "REFLEXIVE":
        json_data = {
        "action": "REFLEXIVE",
        "translated_network": translated_network,
        "source_network": source_network,
        "sequence_number": 0,
        "logging": logging,
        "enabled": status,
        "scope":["/infra/labels/cgw-public"],
        "firewall_match":"MATCH_INTERNAL_ADDRESS",
        "id": display_name}
        response = requests.put(myURL, headers=myHeader, json=json_data)
        json_response_status_code = response.status_code
        return json_response_status_code
    else:
        json_data = {
        "action": "DNAT",
        "destination_network": translated_network,
        "translated_network": source_network,
        "translated_ports": translated_port,
        "service":("/infra/services/"+service),
        "sequence_number": 0,
        "logging": logging,
        "enabled": status,
        "scope":["/infra/labels/cgw-public"],
        "firewall_match":"MATCH_INTERNAL_ADDRESS",
        "id": display_name}
        response = requests.put(myURL, headers=myHeader, json=json_data)
        json_response_status_code = response.status_code
        return json_response_status_code

def removeSDDCNAT(proxy_url, sessiontoken, id):
    """ Remove a NAT rule """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/" + id)
    response = requests.delete(myURL, headers=myHeader)
    return response

def getSDDCVPN(proxy_url, sessiontoken):
    """ Gets the configured Site-to-Site VPN """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    if json_response_status_code == 200:
        sddc_VPN = json_response['results']
        table = PrettyTable(['Name', 'ID', 'Local Address', 'Remote Address'])
        for i in sddc_VPN:
            table.add_row([i['display_name'], i['id'], i['local_endpoint_path'].strip("/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints/"), i['peer_address']])
        return table
    else:
        print("There was an issue.")
        return

def removeSDDCVPN(proxy_url, sessiontoken, id):
    """ Remove a VPN session rule """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/" + id)
    response = requests.delete(myURL, headers=myHeader)
    return response

def newSDDCIPSecVpnIkeProfile(proxy_url, sessiontoken, display_name):
    """ Creates the configured IPSec VPN Ike Profile """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/ipsec-vpn-ike-profiles/" + display_name)
    print("PUT API call to "+myURL)
    json_data = {
    "resource_type":"IPSecVpnIkeProfile",
    "display_name": display_name,
    "id": display_name,
    "encryption_algorithms":["AES_128"],
    "digest_algorithms":["SHA2_256"],
    "dh_groups":["GROUP14"],
    "ike_version":"IKE_V2"
    }
    print("Payload Content:")
    print(json_data)
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCIPSecVpnIkeProfile(proxy_url, sessiontoken, id):
    """ Remove a VPN session rule """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/ipsec-vpn-ike-profiles/" + id)
    response = requests.delete(myURL, headers=myHeader)
    return response

def newSDDCIPSecVpnTunnelProfile(proxy_url, sessiontoken, display_name):
    """ Creates the configured IPSec VPN Tunnel Profile """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/" + display_name)
    print("PUT API call to "+myURL)
    json_data = {
    "resource_type":"IPSecVpnTunnelProfile",
    "display_name": display_name,
    "id": display_name,
    "encryption_algorithms":["AES_GCM_128"],
    "digest_algorithms":[],
    "dh_groups":["GROUP14"],
    "enable_perfect_forward_secrecy":True
    }
    print("Payload Content:")
    print(json_data)
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCIPSecVpnTunnelProfile(proxy_url, sessiontoken, id):
    """ Remove a VPN Tunnel Profile  rule """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/ipsec-vpn-tunnel-profiles/" + id)
    response = requests.delete(myURL, headers=myHeader)
    return response

def newSDDCIPSecVpnSession(proxy_url, sessiontoken, display_name, endpoint, peer_ip):
    """ Creates the configured IPSec VPN Tunnel Profile """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/" + display_name)
    print("PUT API call to "+myURL)
    json_data = {
    "resource_type":"RouteBasedIPSecVpnSession",
    "display_name": display_name,
    "id": display_name,
    "tcp_mss_clamping":{"direction":"NONE"},
    "peer_address":peer_ip,
    "peer_id":peer_ip,
    "psk":"None",
    "tunnel_profile_path": ("/infra/ipsec-vpn-tunnel-profiles/" + display_name),
    "ike_profile_path":("/infra/ipsec-vpn-ike-profiles/" + display_name),
    "local_endpoint_path":"/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints/" + endpoint,
    "tunnel_interfaces":[
        {
        "ip_subnets":[
            {
                "ip_addresses":[
                    "169.254.31.249"
                ],
                "prefix_length":30
            }
        ]
        }]
    }
    print("Payload Content:")
    print(json_data)
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code   

def newSDDCL2VPN(proxy_url, sessiontoken, display_name):
    """ Creates the configured L2 VPN """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions/" + display_name)
    print("PUT API call to "+myURL)
    json_data = {
    "transport_tunnels": [
        "/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/" + display_name
    ],
    "resource_type": "L2VPNSession",
    "id": display_name,
    "display_name": "L2VPN",
}
    print("Payload Content:")
    print(json_data)
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCL2VPN(proxy_url, sessiontoken, id):
    """ Remove a L2VPN """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions/" + id)
    response = requests.delete(myURL, headers=myHeader)
    return response

def getSDDCVPNIpsecProfiles(proxy_url, sessiontoken):
    """ Gets the VPN IKE IPSecProfiles """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/ipsec-vpn-ike-profiles")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_VPN_ipsec_profiles = json_response['results']
    table = PrettyTable(['Name', 'ID', 'IKE Version', 'Digest', 'DH Group', 'Encryption'])
    for i in sddc_VPN_ipsec_profiles:
        table.add_row([i['display_name'], i['id'], i['ike_version'], i['digest_algorithms'], i['dh_groups'], i['encryption_algorithms']])
    return table

def getSDDCVPNIpsecTunnelProfiles(proxy_url, sessiontoken):
    """ Gets the IPSec tunnel Profiles """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/ipsec-vpn-tunnel-profiles")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_VPN_ipsec_tunnel_profiles = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Digest', 'DH Group', 'Encryption'])
    for i in sddc_VPN_ipsec_tunnel_profiles:
        table.add_row([i['display_name'], i['id'], i['digest_algorithms'], i['dh_groups'], i['encryption_algorithms']])
    return table

def getSDDCL2VPNServices(proxy_url, sessiontoken):
    """ Gets the L2VPN services """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default")
    response = requests.get(myURL, headers=myHeader)
    i = response.json()
    table = PrettyTable(['Name', 'ID', 'mode'])
    table.add_row([i['display_name'], i['id'], i['mode']])
    return table

def getSDDCL2VPNSession(proxy_url, sessiontoken):
    """ Gets the L2VPN sessions """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions")
    response = requests.get(myURL, headers=myHeader)
    i = response.json()
    sddc_l2vpn_sessions = i['results']
    table = PrettyTable(['Name', 'ID', 'Enabled?'])
    for i in sddc_l2vpn_sessions:
        table.add_row([i['display_name'], i['id'], i['enabled']])
    return table

def getSDDCL2VPNSessionPath(proxy_url, sessiontoken):
    """ Gets the L2VPN sessions """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions")
    response = requests.get(myURL, headers=myHeader)
    i = response.json()
    sddc_l2vpn_path = i['results'][0]['path']
    return sddc_l2vpn_path


def getSDDCVPNIpsecEndpoints(proxy_url, sessiontoken):
    """ Gets the IPSec Local Endpoints """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_VPN_ipsec_endpoints = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Address'])
    for i in sddc_VPN_ipsec_endpoints:
        table.add_row([i['display_name'], i['id'], i['local_address']])
    return table

def getSDDCCGWRule(proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_CGWrules = json_response['results']
    table = PrettyTable(['id', 'Name','Source','Destination', 'Action', 'Applied To', 'Sequence Number'])
    for i in sddc_CGWrules:
        # a, b and c are used to strip the infra/domain/cgw terms from the strings for clarity.
        a = i['source_groups']
        a = [z.replace('/infra/domains/cgw/groups/','') for z in a]
        a = [z.replace('/infra/tier-0s/vmc/groups/','') for z in a]
        b= i['destination_groups']
        b = [z.replace('/infra/domains/cgw/groups/','') for z in b]
        b = [z.replace('/infra/tier-0s/vmc/groups/','') for z in b]
        c= i['scope']
        c = [z.replace('/infra/labels/cgw-','') for z in c]
        table.add_row([i['id'], i['display_name'], a, b, i['action'], c, i['sequence_number']])
    return table

def getSDDCMGWRule(proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_MGWrules = json_response['results']
    table = PrettyTable(['ID', 'Name', 'Source', 'Destination', 'Services', 'Action', 'Sequence Number'])
    for i in sddc_MGWrules:
        # a and b are used to strip the infra/domain/mgw terms from the strings for clarity.
        a = i['source_groups']
        a = [z.replace('/infra/domains/mgw/groups/','') for z in a]
        b= i['destination_groups']
        b = [z.replace('/infra/domains/mgw/groups/','') for z in b]
        c = i['services']
        c = [z.replace('/infra/services/','') for z in c]
        table.add_row([i['id'], i['display_name'], a, b, c, i['action'], i['sequence_number']])
    return table

def getSDDCDFWSection(proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/security-policies/")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_DFWsection = json_response['results']
    table = PrettyTable(['id', 'Name','Category', 'Sequence Number'])
    for i in sddc_DFWsection:
        table.add_row([i['id'], i['display_name'], i['category'], i['sequence_number']])
    return table

def newSDDCDFWSection(proxy_url, sessiontoken, display_name, category):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/security-policies/" + display_name)
    json_data = {
    "resource_type":"SecurityPolicy",
    "display_name": display_name,
    "id": display_name,
    "category": category,
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCDFWSection(proxy_url, sessiontoken, section_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/security-policies/" + section_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code

def getSDDCDFWRule(proxy_url, sessiontoken, section):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/security-policies/" + section + "/rules")
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    if json_response_status_code != 200:
        print("No section found.")
    else:
        json_response = response.json()
        sddc_DFWrules = json_response['results']
        table = PrettyTable(['ID', 'Name', 'Source', 'Destination', 'Services', 'Action', 'Sequence Number'])
        for i in sddc_DFWrules:
            # a and b are used to strip the infra/domain/mgw terms from the strings for clarity.
            a = i['source_groups']
            a = [z.replace('/infra/domains/cgw/groups/','') for z in a]
            a = [z.replace('/infra/tier-0s/vmc/groups/','') for z in a]
            b= i['destination_groups']
            b = [z.replace('/infra/domains/cgw/groups/','') for z in b]
            b = [z.replace('/infra/tier-0s/vmc/groups/','') for z in b]
            c = i['services']
            c = [z.replace('/infra/services/','') for z in c]
            table.add_row([i['id'], i['display_name'], a, b, c, i['action'], i['sequence_number']])
        return table

def newSDDCDFWRule(proxy_url, sessiontoken, display_name, source_groups, destination_groups, services, action, section, sequence_number):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/security-policies/" + section + "/rules/" + display_name)
    json_data = {
    "action": action,
    "destination_groups": destination_groups,
    "direction": "IN_OUT",
    "disabled": False,
    "display_name": display_name,
    "id": display_name,
    "ip_protocol": "IPV4_IPV6",
    "logged": False,
    "profiles": [ "ANY" ],
    "resource_type": "Rule",
    "services": services,
    "source_groups": source_groups,
    "sequence_number": sequence_number
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCDFWRule(proxy_url, sessiontoken, section, rule_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/security-policies/" + section + "/rules/" + rule_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code

def newSDDCCGWRule(proxy_url, sessiontoken, display_name, source_groups, destination_groups, services, action, scope, sequence_number):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules/" + display_name)
    json_data = {
    "action": action,
    "destination_groups": destination_groups,
    "direction": "IN_OUT",
    "disabled": False,
    "display_name": display_name,
    "id": display_name,
    "ip_protocol": "IPV4_IPV6",
    "logged": False,
    "profiles": [ "ANY" ],
    "resource_type": "Rule",
    "scope": scope,
    "services": services,
    "source_groups": source_groups,
    "sequence_number": sequence_number
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCCGWRule(proxy_url, sessiontoken, rule_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules/" + rule_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code


def newSDDCMGWRule(proxy_url, sessiontoken, display_name, source_groups, destination_groups, services, action, sequence_number):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules/" + display_name)
    json_data = {
    "action": action,
    "destination_groups": destination_groups,
    "direction": "IN_OUT",
    "disabled": False,
    "display_name": display_name,
    "id": display_name,
    "ip_protocol": "IPV4_IPV6",
    "logged": False,
    "profiles": [ "ANY" ],
    "resource_type": "Rule",
    "scope": ["/infra/labels/mgw"],
    "services": services,
    "source_groups": source_groups,
    "sequence_number": sequence_number
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCMGWRule(proxy_url, sessiontoken, rule_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules/" + rule_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code


def getSDDCVPNSTATS(proxy_url, sessiontoken, tunnelID):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/" + tunnelID + "/statistics")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_VPN_statistics = json_response['results'][0]['policy_statistics'][0]['tunnel_statistics']
    table = PrettyTable(['Status', 'Packets In', 'Packets Out'])
    for i in sddc_VPN_statistics:
        table.add_row([i['tunnel_status'], i['packets_in'], i['packets_out']])
    return table

def getSDDCVPNServices(proxy_url, sessiontoken, vpn_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/" + vpn_id)
    response = requests.get(myURL, headers=myHeader)
    print(myURL)
    i = response.json()
    print(i)
    table = PrettyTable(['Name', 'Id', 'Peer'])
    table.add_row([i['display_name'], i['id'], i['peer_address']])
    return table

def getSDDCPublicIP(proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/public-ips")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_public_ips = json_response['results']
    table = PrettyTable(['IP', 'id', 'Notes'])
    for i in sddc_public_ips:
        table.add_row([i['ip'], i['id'], i['display_name']])
    return table

def setSDDCPublicIP(proxy_url, sessiontoken, notes, ip_id):
    """ Update the description of an existing  public IP for compute workloads."""
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/public-ips/" + ip_id)
    json_data = {
    "display_name" : notes
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def newSDDCPublicIP(proxy_url, sessiontoken, notes):
    """ Gets a new public IP for compute workloads. Requires a description to be added to the public IP."""
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    myURL = (proxy_url_short + "cloud-service/api/v1/infra/public-ips/" + notes)
    json_data = {
    "display_name" : notes
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def removeSDDCPublicIP(proxy_url, sessiontoken, ip_id):
    """ Removes a public IP. """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/public-ips/" + ip_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code


def getSDDCMTU(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/external/config")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_MTU = json_response['intranet_mtu']
    return sddc_MTU

def setSDDCMTU(proxy_url,sessiontoken,mtu):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/external/config")
    json_data = {
    "intranet_mtu" : mtu
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def getSDDCShadowAccount(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/accounts")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_shadow_account = json_response['shadow_account']
    return sddc_shadow_account

def getSDDCBGPAS(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/direct-connect/bgp")
    response = requests.get(myURL, headers=myHeader)
    SDDC_BGP = response.json()
    SDDC_BGP_AS = SDDC_BGP['local_as_num']
    return SDDC_BGP_AS

def setSDDCBGPAS(proxy_url,sessiontoken,asn):
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = (proxy_url_short + "cloud-service/api/v1/infra/direct-connect/bgp")
    json_data = {
    "local_as_num": asn
    }
    response = requests.patch(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code
    
def getSDDCBGPVPN(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/direct-connect/bgp")
    response = requests.get(myURL, headers=myHeader)
    SDDC_BGP = response.json()
    SDDC_BGP_VPN = SDDC_BGP['route_preference']
    
    if SDDC_BGP_VPN == "VPN_PREFERRED_OVER_DIRECT_CONNECT":
        return "The preferred path is over VPN, with Direct Connect as a back-up."
    else:
        return "The preferred path is over Direct Connect, with VPN as a back-up."


def getSDDCConnectedVPC(proxy_url,sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/linked-vpcs")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_connected_vpc = json_response['results'][0]
    mySecondURL = (proxy_url + "/cloud-service/api/v1/infra/linked-vpcs/" + sddc_connected_vpc['linked_vpc_id'] + "/connected-services")
    response_second = requests.get(mySecondURL, headers=myHeader)
    sddc_connected_vpc_services = response_second.json()
    table = PrettyTable(['Customer-Owned Account', 'Connected VPC ID', 'Subnet', 'Availability Zone', 'ENI', 'Service Access'])
    table.add_row([sddc_connected_vpc['linked_account'], sddc_connected_vpc['linked_vpc_id'], sddc_connected_vpc['linked_vpc_subnets'][0]['cidr'], sddc_connected_vpc['linked_vpc_subnets'][0]['availability_zone'], sddc_connected_vpc['active_eni'],sddc_connected_vpc_services['results'][0]['enabled']])
    return table

def setSDDCConnectedServices(proxy_url,sessiontoken, value):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/cloud-service/api/v1/infra/linked-vpcs")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_connected_vpc = json_response['results'][0]
    mySecondURL = (proxy_url + "/cloud-service/api/v1/infra/linked-vpcs/" + sddc_connected_vpc['linked_vpc_id'] + "/connected-services/s3")
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    json_data = {
    "name": "s3" ,
    "enabled": value
    }
    thirdresponse = requests.put(mySecondURL, headers=myHeader, json=json_data)
    json_response_status_code = thirdresponse.status_code
    return json_response_status_code

def getSDDCGroups(proxy_url,sessiontoken,gw):
    """ Gets the SDDC Groups. Use 'mgw' or 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups"
    # print(myURL)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # print(json_response)
    sddc_group = json_response['results']
    table = PrettyTable(['ID', 'Name'])
    for i in sddc_group:
        table.add_row([i['id'], i['display_name']])
    # print(table)
    return table

def getSDDCGroup(proxy_url,sessiontoken,gw,group_id):
    """ Gets a single SDDC Group. Use 'mgw' or 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # Checking for groups with defined criteria with the following command. 
    if 'expression' in json_response:
        group_criteria = json_response['expression'][0]
        if group_criteria["resource_type"] == "IPAddressExpression":
            group_IP_list = group_criteria['ip_addresses']
            print("The group " + group_id + " is based on the IP addresses criteria:")
            # print(group_IP_list,sep='\n') would work best with Python3.
            print(group_IP_list)
        elif group_criteria["resource_type"] == "ExternalIDExpression":
            group = json_response['expression']
            if group[0]['member_type'] == "VirtualMachine":
                myNewURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id + "/members/virtual-machines"
                new_response = requests.get(myNewURL, headers=myHeader)
                new_second_response = new_response.json()
                new_second_extra = new_second_response['results']
                new_table = PrettyTable(['Name'])
                for i in new_second_extra:
                    new_table.add_row([i['display_name']])
                print("\n The following Virtual Machines are part of the Group.")
                print(new_table)        
        elif group_criteria["resource_type"] == "Condition":
            group = json_response['expression']
            print("The group " + group_id + " is based on these criteria:")
            table = PrettyTable(['Member Type', 'Key', 'Operator', 'Value'])
            for i in group:
                table.add_row([i['member_type'], i['key'], i['operator'], i['value']])
            print(table)
            if group[0]['member_type'] == "VirtualMachine":
                myNewURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id + "/members/virtual-machines"
                new_response = requests.get(myNewURL, headers=myHeader)
                new_second_response = new_response.json()
                new_second_extra = new_second_response['results']
                new_table = PrettyTable(['Name'])
                for i in new_second_extra:
                    new_table.add_row([i['display_name']])
                print("\n The following Virtual Machines are part of the Group.")
                print(new_table)
            else:
                myNewURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id + "/members/ip-addressesa"
                new_response = requests.get(myNewURL, headers=myHeader)
                new_second_response = new_response.json()
                new_second_extra = new_second_response['results']
                new_table = PrettyTable(['Name'])
                for i in new_second_extra:
                    new_table.add_row([i['display_name']])
                print("\n The following IP addresses are part of the Group.")
                print(new_table)
        else:
            print("Incorrect syntax. Try again.")
    else:
        print("This group has no criteria defined.")
    return


def getSDDCGroupAssociation(proxy_url,sessiontoken,gw,group_id):
    """ Find where a SDDC Group is being used. Use 'mgw' or 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/group-service-associations?intent_path=/infra/domains/" + gw +"/groups/" + group_id
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    json_response = response.json()
    # print(json_response)
    if response.status_code != 200:
        print( f'API Call Status {response.status_code}, text:{response.text}')
    else:
        sddc_group = json_response['results']
        if len(sddc_group) == 0:
            print("No object is associated with this group.")
        else:
            table = PrettyTable(['ID', 'Name'])
            for i in sddc_group:
                table.add_row([i['target_id'], i['target_display_name']])
            print(table)
            
def removeSDDCGroup(proxy_url, sessiontoken, gw, group_id):
    """ Remove an SDDC Group """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.status_code
    print(json_response)
    if json_response == 200 :
        print("The group " + group_id + " has been deleted")
    else :
        print("There was an error. Try again.")
    return json_response

def newSDDCGroupIPaddress(proxy_url,sessiontoken,gw,group_id,ip_addresses):
    """ Creates a single SDDC Group based on IP addresses. Use 'mgw' or 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id
    json_data = {
    "expression" : [ {
      "ip_addresses" : ip_addresses,
      "resource_type" : "IPAddressExpression"
    } ],
    "id" : group_id,
    "display_name" : group_id,
    "resource_type" : "Group"}
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def newSDDCGroupCriteria(proxy_url,sessiontoken,gw,group_id,member_type,key,operator,value):
    """ Creates a single SDDC Group based on a criteria. Use 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id
    json_data = {
    "expression" : [ {
      "member_type" : member_type,
      "key" : key,
      "operator" : operator,
      "value" : value,
      "resource_type" : "Condition"
    } ],
    "id" : group_id,
    "display_name" : group_id,
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

def getVMExternalID(proxy_url,sessiontoken,vm_name):
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    VMlist_url = (proxy_url_short + "policy/api/v1/infra/realized-state/enforcement-points/vmc-enforcementpoint/virtual-machines")
    response = requests.get(VMlist_url, headers=myHeader)
    response_dictionary = response.json()
    extracted_dictionary = response_dictionary['results']
    # Below, we're extracting the Python dictionary for the specific VM and then we extract the external_ID/ Instance UUID from the dictionary.
    extracted_VM = next(item for item in extracted_dictionary if item["display_name"] == vm_name)
    extracted_VM_external_id = extracted_VM['external_id']
    return extracted_VM_external_id

def getVMs(proxy_url,sessiontoken):
    """ Gets a list of all compute VMs, with their power state and their external ID. """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    VMlist_url = (proxy_url_short + "policy/api/v1/infra/realized-state/enforcement-points/vmc-enforcementpoint/virtual-machines")
    response = requests.get(VMlist_url, headers=myHeader)
    response_dictionary = response.json()
    extracted_dictionary = response_dictionary['results']
    table = PrettyTable(['Display_Name', 'Status', 'External_ID'])
    for i in extracted_dictionary:
        table.add_row([i['display_name'], i['power_state'], i['external_id']])
    return table

def newSDDCGroupGr(proxy_url,sessiontoken,gw,group_id,member_of_group):
    """ Creates a single SDDC group and adds 'member_of_group' to the group membership"""
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id
    # Example JSON data
    #json_data = {
    #"expression" : [ {
    #    "paths": [ "/infra/domains/cgw/groups/Group1", "/infra/domains/cgw/groups/Group2"],
    #    "resource_type": "PathExpression",
    #    "parent_path": "/infra/domains/cgw/groups/" + group_id
    #} ],
    #"extended_expression": [],
    #"id" : group_id,
    #"resource_type" : "Group",
    #"display_name" : group_id,
    #}

    # Split the group members into a list
    group_list = member_of_group.split(',')
    group_list_with_path = []
    for item in group_list:
        group_list_with_path.append('/infra/domains/cgw/groups/' + item)

    #The data portion of the expression key is a dictionar
    expression_data = {}
    expression_data["paths"] = group_list_with_path
    expression_data["resource_type"] = "PathExpression"
    expression_data["parent_path"] = "/infra/domains/cgw/groups/" + group_id

    #The expression key itself is a list
    expression_list = []
    expression_list.append(expression_data)

    #Build the JSON object
    json_data = {}
    json_data["expression"] = expression_list
    json_data["extended_expression"] = []
    json_data["id"] = group_id
    json_data["resource_type"] = "Group"
    json_data["display_name"] = group_id

    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    #print(response.text)
    return json_response_status_code

def newSDDCGroupVM(proxy_url,sessiontoken,gw,group_id,vm_list):
    """ Creates a single SDDC Group based on a list of VM external_id. Use 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/domains/" + gw + "/groups/" + group_id
    json_data = {
    "expression" : [ {
        "member_type" : "VirtualMachine",
        "external_ids" : vm_list,
        "resource_type" : "ExternalIDExpression"
    } ],
    "id" : group_id,
    "display_name" : group_id,
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code
    
def getSDDCServices(proxy_url,sessiontoken):
    """ Gets the SDDC Services """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/services"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_services = json_response['results']
    table = PrettyTable(['ID', 'Name'])
    for i in sddc_services:
        table.add_row([i['id'], i['display_name']])
    return table

def getSDDCService(proxy_url,sessiontoken,service_id):
    """ Gets the SDDC Services """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/services/" + service_id 
    response = requests.get(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    if json_response_status_code != 200:
        print("This service does not exist.")
    else:
        json_response = response.json()
        service_entries = json_response['service_entries']
        table = PrettyTable(['ID', 'Name', 'Protocol', 'Source Ports', 'Destination Ports'])
        for i in service_entries:
            table.add_row([i['id'], i['display_name'], i['l4_protocol'], i['source_ports'], i['destination_ports']])
        return table

def newSDDCService(proxy_url,sessiontoken,service_id,service_entries):
    """ Create a new SDDC Service based on service_entries """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/services/" + service_id 
    json_data = {
    "service_entries":service_entries,
    "id" : service_id,
    "display_name" : service_id,
    }
    response = requests.put(myURL, headers=myHeader, json=json_data)
    json_response_status_code = response.status_code
    return json_response_status_code

# def newSDDCServiceEntry(proxy_url,sessiontoken,service_entry_id,source_port,destination_port,l4_protocol):
#    """ Create a new SDDC Service Entry """
#    myHeader = {'csp-auth-token': sessiontoken}
#    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
#    # removing 'sks-nsxt-manager' from proxy url to get correct URL
#    myURL = proxy_url_short + "policy/api/v1/infra/services/" + service_id
#    json_data = {
#    "l4_protocol": l4_protocol,
#    "source_ports": source_port_list,
#    "destination_ports" : destination_port_list,
#    "resource_type" : "L4PortSetServiceEntry",
#    "id" : service_entry_id,
#    "display_name" : service_entry_id     }


def removeSDDCService(proxy_url, sessiontoken,service_id):
    """ Remove an SDDC Service """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/services/" + service_id
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.status_code
    print(json_response)
    if json_response == 200 :
        print("The group " + service_id + " has been deleted")
    else :
        print("There was an error. Try again.")
    return


def getSDDCDNS_Zones(proxy_url,sessiontoken):
    """ Gets the SDDC Zones """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/dns-forwarder-zones"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    sddc_dns = json_response['results']
    table = PrettyTable(['ID', 'Name','DNS Domain Names','upstream_servers'])
    for i in sddc_dns:
        table.add_row([i['id'], i['display_name'], i['dns_domain_names'], i['upstream_servers']])
    return table

def getSDDCDNS_Services(proxy_url,sessiontoken,gw):
    """ Gets the DNS Services. Use 'mgw' or 'cgw' as the parameter """
    myHeader = {'csp-auth-token': sessiontoken}
    proxy_url_short = proxy_url.rstrip("sks-nsxt-manager")
    # removing 'sks-nsxt-manager' from proxy url to get correct URL
    myURL = proxy_url_short + "policy/api/v1/infra/tier-1s/" + gw + "/dns-forwarder"
    response = requests.get(myURL, headers=myHeader)
    sddc_dns_service = response.json()
    table = PrettyTable(['ID', 'Name', 'Listener IP'])
    table.add_row([sddc_dns_service['id'], sddc_dns_service['display_name'], sddc_dns_service['listener_ip']])
    return table

def createLotsNetworks(proxy_url, sessiontoken,network_number):
    """ Creates lots of networks! """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    for x in range(0,network_number):
        display_name = "network-name"+str(x)
        myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments/" + display_name)
    #  '/tier-1s/cgw' might only be applicable for multi tier-1s architecture. To be confirmed.
    # print(myURL)
        json_data = {
                "subnets":[{"gateway_address":"10.200."+str(x)+".1/24"}],
                "type":"ROUTED",
                "display_name":display_name,
                "advanced_config":{"connectivity":"ON"},
                "id":"network-test"+str(x)
                }
        response = requests.put(myURL, headers=myHeader, json=json_data)
        json_response_status_code = response.status_code

def addUsersToCSPGroup(csp_url, session_token):
    myHeader = {'csp-auth-token': session_token,'Content-Type': 'application/json'}

    if len(sys.argv) < 4:
        print('Usage: add-users-to-csp-group [groupID] [comma separated email addresses')
        sys.exit()

    groupId = sys.argv[2]
    usernamesToAdd = sys.argv[3].split(',')

    myURL = csp_url + f'/csp/gateway/am/api/orgs/{ORG_ID}/groups/{groupId}/users'
    params = {
            'notifyUsers': 'false',
            'usernamesToAdd': usernamesToAdd
    }
    response = requests.post(myURL,data=json.dumps(params), headers=myHeader)
    response_json = response.json()
    if response.status_code == 200:
        print(f"Added: {response_json['succeeded']}" )
        print(f"Failed: {response_json['failed']}" )
    else:
        print (f'Operation failed with status code {response.status_code}. URL: {myURL}. Body: {params}')

def getCSPServiceRoles(csp_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = csp_url + f'/csp/gateway/am/api/loggedin/user/orgs/{ORG_ID}/service-roles'
    response = requests.get(myURL,headers=myHeader)
    json_response = response.json()
    #print(json.dumps(json_response, indent=4))
    for svc_def in json_response['serviceRoles']:
        for svc_role in svc_def['serviceRoleNames']:
            print(svc_role)

def findCSPUserByServiceRole(csp_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    if len(sys.argv) < 3:
        print('Usage: find-csp-user-by-service-role [role]')
        sys.exit()

    role_name= sys.argv[2]
    myURL = csp_url + f'/csp/gateway/am/api/v2/orgs/{ORG_ID}/users'
    response = requests.get(myURL,headers=myHeader)
    json_response = response.json()
    users = json_response['results']
    table = PrettyTable(['Email','Service Role', 'Org Role'])
    for user in users:
        for servicedef in user['serviceRoles']:
            for role in servicedef['serviceRoles']:
                if role['name'] == role_name:
                    display_role = ''
                    for orgrole in user['organizationRoles']:
                        display_role = display_role + orgrole['name'] + ' '
                    table.add_row([user['user']['email'],role_name,display_role])
    print(table)

def getCSPGroupDiff(csp_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    if len(sys.argv) < 3:
        print('Usage: show-csp-group-diff [groupID] [showall|skipmembers|skipowners]')
        sys.exit()

    # Optional filter for org owners and members
    SKIP_MEMBERS = False
    SKIP_OWNERS = False

    if len(sys.argv) == 4:
        if sys.argv[3] == "skipmembers":
            SKIP_MEMBERS = True
            print('Skipping members...')
        elif sys.argv[3] == "skipowners":
            SKIP_OWNERS = True
            print('Skipping owners...')

    groupId = sys.argv[2]
    myURL = csp_url + f'/csp/gateway/am/api/orgs/{ORG_ID}/groups/{groupId}'
    response = requests.get(myURL,headers=myHeader)
    json_response = response.json()
    grouproles = json_response['serviceRoles']

    myURL = csp_url + f'/csp/gateway/am/api/v2/orgs/{ORG_ID}/users'
    response = requests.get(myURL,headers=myHeader)
    json_response = response.json()
    users = json_response['results']
    grouprolelist = []
    for role in grouproles:
        for rname in role['serviceRoleNames']:
            grouprolelist.append(rname)


    print('Group role list:')
    print(grouprolelist)
    i = 0
    for user in users:
        IS_OWNER = False
        for orgrole in user['organizationRoles']:
            if orgrole['name'] == 'org_owner':
                IS_OWNER = True
                break

        IS_MEMBER = False
        for orgrole in user['organizationRoles']:
            if orgrole['name'] == 'org_member':
                IS_MEMBER = True
                break

        if IS_OWNER and SKIP_OWNERS:
            continue

        if IS_MEMBER and SKIP_MEMBERS:
            continue

        i += 1
        if i % 25 == 0:
            wait = input("Press Enter to show more users, q to quit: ")
            if wait == 'q':
                sys.exit()

            print('Group role list:')
            print(grouprolelist)

        print(user['user']['email'],f'({i} of {len(users)})')
        print(f'Member: {IS_MEMBER}, Owner: {IS_OWNER}')
        userrolelist = []
        for servicedef in user['serviceRoles']:
            for role in servicedef['serviceRoles']:
                userrolelist.append(role['name'])
        print('User role list:')
        print(userrolelist)
        diff = DeepDiff(grouprolelist,userrolelist,ignore_order=True)
        print('Role Differences:')
        print(diff)
        print("------------- ")

def getCSPOrgUsers(csp_url,session_token):
    if len(sys.argv) < 3:
        print('Usage: show-csp-org-users [searchTerms]')
    else:
        myHeader = {'csp-auth-token': session_token,'Content-Type': 'application/json'}
        searchTerm = sys.argv[2]
        myURL = csp_url + f'/csp/gateway/am/api/orgs/{ORG_ID}/users/search'
        params = {
            'userSearchTerm': searchTerm
        }
        #response = requests.post(myURL,data=json.dumps(body), headers=myHeader)
        response = requests.get(myURL,headers=myHeader, params=params)
        if response.status_code == 200:
            response_json = response.json()
            users = response_json['results']
            if len(users) >= 20:
                print("Search API is limited to 20 results, refine your search term for accurate results.")
            table = PrettyTable(['Username','First Name', 'Last Name','Email','userId'])
            for user in users:
                table.add_row([user['user']['username'],user['user']['firstName'],user['user']['lastName'],user['user']['email'],user['user']['userId']])

            print(table)
        else:
            print (f'Search failed with status code {response.status_code}. URL: {myURL}. Body: {body}')


def getCSPGroups(csp_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = csp_url + f'/csp/gateway/am/api/orgs/{ORG_ID}/groups'
    response = requests.get(myURL,headers=myHeader)
    json_response = response.json()
    groups = json_response['results']
    table = PrettyTable(['ID','Name', 'Group Type','User Count'])
    for grp in groups:
        table.add_row([grp['id'],grp['displayName'], grp['groupType'], grp['usersCount']])

    print(table)

def getCSPGroupMembers(csp_url, session_token):
    if len(sys.argv) < 3:
        print('Usage: show-csp-group-members [groupID]')
    groupid = sys.argv[2]
    myHeader = {'csp-auth-token': session_token}
    myURL = csp_url + f'/csp/gateway/am/api/orgs/{ORG_ID}/groups/{groupid}/users'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    users = json_response['results']
    table = PrettyTable(['Username','First Name', 'Last Name','Email','userId'])
    for user in users:
        table.add_row([user['username'],user['firstName'],user['lastName'],user['email'],user['userId']])

    print(table)

def getSDDCT0PrefixLists(csp_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{csp_url}/policy/api/v1/infra/tier-0s/vmc/prefix-lists'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        prefixlists = json_response['results']
        # clear results for any prefix lists found that contain "System created prefix list"
        # this will return empty dictionaries for any containing the above string
        for prefix in prefixlists:
            if prefix['description'].__contains__('System created prefix list'):
                prefix.clear()
        # remove empty dictionaries
        while {} in prefixlists:
            prefixlists.remove({})
        # print a nicely formatted list of only user-uploaded prefix lists; system created lists were eliminated in above code
        if len(prefixlists) != 0: 
            for prefixlist in prefixlists:
                prefixlisttable = PrettyTable(['ID','Display Name','Description'])
                prefixlisttable.add_row([prefixlist["id"],prefixlist["display_name"],prefixlist["description"]])
                print("PREFIX:")
                print(prefixlisttable)
                prefixtable = PrettyTable(['Sequence','Network','Comparison', 'Action'])
                i = 0
                if prefixlist.get('prefixes'): 
                    for prefix in prefixlist['prefixes']:
                        i+=1
                        if prefix.get('ge'):
                            comparison = "ge (greater-than-or-equal)"
                        elif prefix.get('le'):
                            comparison = "le (less-than-or-equal)"
                        else:
                            comparison = '-'
                        prefixtable.add_row([i,prefix['network'],comparison,prefix['action']])
                    print(f'PREFIX ENTRIES FOR {prefixlist["id"]}:')
                    print(prefixtable)
                    print("")
            if len(sys.argv) == 3:
                if sys.argv[2] == "showjson":
                    print('RAW JSON:')
                    print(json.dumps(prefixlists,indent=2))
        else:
            print("No user created prefixes found.")
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def newBGPprefixlist(csp_url, session_token):
    myHeader = {'Authorization': f'Bearer {session_token}', 'Content-type': 'application/json'}
#   capture details for new prefix list
    description= input('Enter a description name for the prefix list:  ')
    display_name= input('Enter a display name for the prefix list:  ')
    prefix_list_id= input('Enter an ID string for the prefix list:  ')
#   create python dictionary to contain the prefix list
    prefix_list = {}
    prefix_list['description'] = description
    prefix_list["display_name"] = display_name
    prefix_list["id"] = prefix_list_id
    prefix_list["prefixes"] = []
    myURL = f'{csp_url}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id
#   append individual prefixes to the list
#   begin input loop
    test = ''
    while test != "1":
        print("\nPlease select an option:")
        print("\t1- Commit changes")
        print("\t2- Add a new prefix")
        print("\t3- Review")
        print("\t4- Abort")
        print("\n")
        test=input('What would you like to do? ')
        if test== "2":
#           capture details of new prefix from user
            cidr = input('Enter "ANY" or a network or IP address in CIDR format:  ')
            action= input('Enter the action (PERMIT or DENY):  ')
            if action == "PERMIT" or action == "DENY":
                scope= input('Optional - Enter either le or ge:  ')
                if scope != "":
                    length= int(input('Required - Enter the length of the mask to apply:  '))
            else:
                print('Action must be either "PERMIT" or "DENY"')
                break
#           build new prefix as unique dictionary
            new_prefix = {}
            new_prefix["action"] = action
            new_prefix["network"] = cidr
            if scope !="" and length != "":
                new_prefix[scope] = length
#           append new prefix to list of prefixes in prefix_list
            prefix_list["prefixes"].append(new_prefix)
        elif test == "3":
            print("Please review the prefix list carefully... be sure you are not going to block all traffic!")
            print(prefix_list)
        elif test == "1":
            response = requests.patch(myURL, headers=myHeader, json=prefix_list)
            if response.status_code == 200:
                print("prefix list added")
            else:
                print(response.status_code)
                print(response.json())
                print()
        elif test == "4":
            break
        else:
            print("Please choose 1, 2, 3 or 4 - Try again or check the help.")

def attachT0BGPprefixlist(csp_url, session_token, neighbor_id):
    myHeader = {'Authorization': f'Bearer {session_token}', 'Content-type': 'application/json'}
    myURL = f'{csp_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        neighbor_json = json_response
        for key in list(neighbor_json.keys()):
            if key.startswith('_'):
                del neighbor_json[key]
#   while loop (as above in new prefix list function) - present user with choices - add prefix list, clear prefix lists, commit changes, abort.
#   begin input loop
    test = ''
    while test != "5":
        print("\nPlease select an option:")
        print("\t1- Review neighbor config ")
        print("\t2- Add in_route_filter (only one allowed) ")
        print("\t3- Add out_route_filter (only one allowed) ")
        print("\t4- Clear all prefix lists")
        print("\t5- Commit changes")
        print("\t6- Abort")
        print("\n")
        test=input('What would you like to do? ')
        if test == "1":
            pretty_json = json.dumps(json_response, indent=2)
            print(pretty_json)
            print()
        elif test == "2":
            prefix_list_id = input('Please enter the prefix list ID exactly ')
            neighbor_json['route_filtering'][0]["in_route_filters"] = ['/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id]
            print()
            print("Prefix list " + prefix_list_id + " has been added to in_route_filters in JSON for neighbor id " + neighbor_id + ". Don't forget to review and commit.")
            print()
        elif test =="3":
            prefix_list_id = input('Please enter the prefix list ID exactly ')
            neighbor_json['route_filtering'][0]["out_route_filters"] = ['/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id]
            print()
            print("Prefix list " + prefix_list_id + " has been added to out_route_filters in JSON for neighbor id " + neighbor_id + ". Don't forget to review and commit.")
            print()
        elif test =="4":
            if neighbor_json.get("in_route_filters"):
                del neighbor_json["in_route_filters"]
            if neighbor_json.get("out_route_filters"):
                del neighbor_json["out_route_filters"]
            neighbor_json['route_filtering'] = [{'enabled': True, 'address_family': 'IPV4'}]
        elif test == "5":
            response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
            if response.status_code == 200:
                print("Complete")
                print()
                pretty_json = json.dumps(json_response, indent=2)
                print(pretty_json)
                print()
            else:
                print(response.status_code)
                print(response.json())
                print()
        elif test == "6":
            break
        else:
            print("Please choose 1, 2, 3 or 4 - Try again or check the help.")

def detachT0BGPprefixlists(csp_url, session_token, neighbor_id):
    myHeader = {'Authorization': f'Bearer {session_token}', 'Content-type': 'application/json'}
    myURL = f'{csp_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors/' + neighbor_id
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        neighbor_json = json_response
        for key in list(neighbor_json.keys()):
            if key.startswith('_'):
                del neighbor_json[key]
        neighbor_json['route_filtering'] = [{'enabled': True, 'address_family': 'IPV4'}]
        response = requests.patch(myURL, headers=myHeader, json = neighbor_json)
        if response.status_code == 200:
            print("Prefix lists detached from " + neighbor_id)
        else:
            print(response.status_code)
            print(response.json())
            print()
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def removeBPGprefixlist(csp_url, session_token, prefix_list_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{csp_url}/policy/api/v1/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id
    response = requests.delete(myURL, headers=myHeader)
    json_response = response.status_code
    if json_response == 200 :
        print("The BGP prefix list " + prefix_list_id + " has been deleted")
    else :
        print("Error " + json_response + ". Please try again.")
    return json_response

def getSDDCT0BGPneighbors(csp_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{csp_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/bgp/neighbors'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        bgp_neighbors = json_response['results']
        bgp_table = PrettyTable(['ID','Remote AS Num','Remote Address','In_route_filter','Out_route_filter'])
        for neighbor in bgp_neighbors:
            if neighbor.get("in_route_filters"):
                in_filter = neighbor['in_route_filters']
            else:
                in_filter = "-"
            if neighbor.get("out_route_filters"):
                out_filter = neighbor['out_route_filters']
            else:
                out_filter = "-"
            bgp_table.add_row([neighbor['id'],neighbor['remote_as_num'],neighbor['neighbor_address'],in_filter, out_filter])
        print('NEIGHBORS:')
        print(bgp_table)
        if len(sys.argv) == 3:
            if sys.argv[2] == "showjson":
                print('RAW JSON:')
                print(json.dumps(bgp_neighbors,indent=2))
    else:
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')

def getSDDCT0routes(proxy_url, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/policy/api/v1/infra/tier-0s/vmc/routing-table?enforcement_point_path=/infra/sites/default/enforcement-points/vmc-enforcementpoint".format(proxy_url)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    t0_routes = json_response['results'][1]['route_entries']
    route_table = PrettyTable(['Route Type', 'Network', 'Admin Distance', 'Next Hop'])
    for routes in t0_routes:
        route_table.add_row([routes['route_type'],routes['network'],routes['admin_distance'],routes['next_hop']])
    print ('T0 Routes')
    print ('Route Type Legend:')
    print ('t0c - Tier-0 Connected\nt0s - Tier-0 Static\nb   - BGP\nt0n - Tier-0 NAT\nt1s - Tier-1 Static\nt1c - Tier-1 Connected\nisr: Inter-SR')
    print (route_table.get_string(sort_key = operator.itemgetter(1,0), sortby = "Network", reversesort=True))

def getSDDCEdgeCluster(proxy_url, sessiontoken):
    """ Gets the Edge Cluster ID """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/sites/default/enforcement-points/vmc-enforcementpoint/edge-clusters")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    edge_cluster_id = json_response['results'][0]['id']
    return edge_cluster_id

def getSDDCEdgeNodes(proxy_url, sessiontoken, edge_cluster_id,edge_id):
    """ Gets the Edge Nodes Path """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = proxy_url + "/policy/api/v1/infra/sites/default/enforcement-points/vmc-enforcementpoint/edge-clusters/" + edge_cluster_id + "/edge-nodes"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    if json_response_status_code == 200:
        edge_path = json_response['results'][edge_id]['path']
        return edge_path
    else:
        print("fail")

def getSDDCInternetStats(proxy_url, sessiontoken, edge_path):
    ### Displays counters for egress interface ###
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/tier-0s/vmc/locale-services/default/interfaces/public-0/statistics?edge_path=" + edge_path + "&enforcement_point_path=/infra/sites/default/enforcement-points/vmc-enforcementpoint")
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    if json_response_status_code == 200:
        total_bytes = json_response['per_node_statistics'][0]['tx']['total_bytes']
        return total_bytes      
    else:
        print("fail")

def getHelp():
    print("\nWelcome to PyVMC !")
    print("\nHere are the currently supported commands: ")
    print("\nAWS Account and VPC")
    print("\tset-sddc-connected-services: change whether to use S3 over the Internet or via the ENI")
    print("\tshow-compatible-subnets [LINKEDACCOUNTID] [REGION]: show compatible native AWS subnets connected to the SDDC")
    print("\tshow-connected-accounts: show native AWS accounts connected to the SDDC")
    print("\tshow-sddc-connected-vpc: show the VPC connected to the SDDC")
    print("\tshow-shadow-account: show the Shadow AWS Account VMC is deployed in")
    print("\nBGP and Networking")
    print("\tattach-t0-prefix-list [BGP NEIGHBOR ID]: attach a BGP Prefix List to a T0 BGP neighbor")
    print("\tdetach-t0-prefix-lists [BGP NEIGHBOR ID]: detach all prefix lists from specified neighbor")
    print("\tnew-t0-prefix-list: create a new T0 BGP Prefix List")
    print("\tremove-t0-prefix-list [PREFIX LIST ID]: you can see current prefix list with 'show-t0-prefix-lists': remove a T0 BGP Prefix List")
    print("\tset-bgp-as [ASN]: update the BGP AS number")
    print("\tset-mtu: set the MTU configured over the Direct Connect")
    print("\tshow-mtu: show the MTU configured over the Direct Connect")
    print("\tshow-egress-interface-counters: show current Internet interface egress counters")
    print("\tshow-sddc-bgp-as: show the BGP AS number")
    print("\tshow-sddc-bgp-vpn: show whether DX is preferred over VPN")
    print("\tshow-t0-bgp-neighbors: show T0 BGP neighbors")
    print("\tshow-t0-prefix-lists: show T0 prefix lists")
    print("\tshow-t0-routes: show routes at the T0 router")
    print("\nDNS ")
    print("\tshow-dns-services: show DNS services")
    print("\tshow-dns-zones: show DNS zones")
    print("\nInventory Groups")
    print("\tnew-group [CGW/MGW] [Group_ID]: create a new group")
    print("\tremove-group [CGW/MGW][Group_ID]: remove a group")
    print("\tshow-group [CGW/MGW] [Group_ID]: show existing groups")
    print("\tshow-group-association [CGW/MGW] [Group_ID]: show security rules used by a groups")
    print("\nFirewall - Distributed")
    print("\tnew-dfw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SECTION] [SEQUENCE-NUMBER]: create a new DFW security rule")
    print("\tnew-dfw-section [NAME][CATEGORY]: create a new DFW section")
    print("\tremove-dfw-rule [SECTION_ID][RULE_ID]: delete a DFW rule")
    print("\tremove-dfw-section [RULE_ID]: delete a DFW section")
    print("\tshow-dfw-section: show the DFW sections")
    print("\tshow-dfw-section-rules [SECTION]: show the DFW security rules within a section")
    print("\nFirewall - T0")
    print("\tnew-cgw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SCOPE] [SEQUENCE-NUMBER]: create a new CGW security rule")
    print("\tnew-mgw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SEQUENCE-NUMBER]: create a new MGW security rule")
    print("\tremove-cgw-rule [RULE_ID]: delete a CGW security rule")
    print("\tremove-mgw-rule [RULE_ID]: delete a MGW security rule")
    print("\tshow-cgw-rule: show the CGW security rules")
    print("\tshow-mgw-rule: show the MGW security rules")
    print("\nFirewall Services")
    print("\tnew-service: create a new service")
    print("\tremove-service [SERVICE-ID]: remove a service")
    print("\tshow-services [SERVICE-ID]: show a specific service")
    print("\tshow-services: show services")
    print("\nNAT")
    print("\tnew-nat-rule: To create a new NAT rule")
    print("\tremove-nat-rule: remove a NAT rule")
    print("\tshow-nat: show the configured NAT rules")
    print("\tshow-nat [NAT-RULE-ID] for statistics of a rule: show the statistics for a specific NAT rule")
    print("\nPublic IP addressing")
    print("\tnew-sddc-public-ip: request a new public IP")
    print("\tremove-sddc-public-ip: remove an existing public IP")
    print("\tset-sddc-public-ip: update the description of an existing public IP")
    print("\tshow-sddc-public-ip: show the public IPs")
    print("\nSDDC")
    print("\tget-access-token: show your access token")  
    print("\tshow-sddc-state: get a view of your selected SDDC")
    print("\tshow-sddcs: display a lit of your SDDCs")
    print("\tshow-vms: get a list of your VMs")
    print("\nUser and Group management")
    print("\tadd-users-to-csp-group [GROUP_ID] [EMAILS]: CSP user to a group")
    print("\tshow-csp-group-diff [GROUP_ID] [showall|skipmembers|skipowners]: this compares the roles in the specified group with every user in the org and prints out a user-by-user diff")
    print("\tshow-csp-group-members [GROUP_ID]: show CSP group members")
    print("\tshow-csp-groups: To show CSP groups")
    print("\tshow-csp-org-users [email]: show a CSP user")
    print("\tshow-csp-service-roles: show CSP service roles for the currently logged in user")
    print("\tfind-csp-user-by-service-role [service role name]: search for CSP users with a specific service role")
    print("\tshow-org-users: show the list of organization users")
    print("\nVirtual Machine Networking")
    print("\tshow-network: show your current networks")
    print("\tnew-network [NAME] [DISCONNECTED] [GATEWAY_ADDRESS]  for a disconnected network")
    print("\tnew-network [NAME] [EXTENDED] [GATEWAY_ADDRESS] [TUNNEL_ID] for an extended network")
    print("\tnew-network [NAME] [ROUTED] [GATEWAY_ADDRESS] [DHCP_RANGE] [DOMAIN_NAME] for a DHCP network")
    print("\tnew-network [NAME] [ROUTED] [GATEWAY_ADDRESS] for a static network")
    print("\tremove-network: remove a network")
    print("\nVPN")
    print("\tnew-l2vpn [NAME] [LOCAL_ENDPOINT] [REMOTE_PEER]: create a new L2VPN")
    print("\tremove-l2VPN [ID]: remove a L2VPN")
    print("\tremove-vpn [VPN-ID]: remove a VPN")
    print("\tremove-vpn-ike-profile [ID]: remove a VPN IKE profile")
    print("\tremove-vpn-ipsec-tunnel-profile [ID]: To remove a VPN IPSec Tunnel profile")
    print("\tshow-l2vpn: show l2 vpn")
    print("\tshow-l2vpn-services: show l2 vpn services")
    print("\tshow-vpn: show the configured VPN")
    print("\tshow-vpn [VPN_ID]: show the VPN statistics")
    print("\tshow-vpn-ike-profile: show the VPN IKE profiles")
    print("\tshow-vpn-internet-ip: show the public IP used for VPN services")
    print("\tshow-vpn-ipsec-tunnel-profile: show the VPN tunnel profile")
    print("\tshow-vpn-ipsec-endpoints: show the VPN IPSec endpoints")


# --------------------------------------------
# ---------------- Main ----------------------
# --------------------------------------------

if len(sys.argv) > 1:
    intent_name = sys.argv[1].lower()
else:
    intent_name = ""

session_token = getAccessToken(Refresh_Token)
proxy = getNSXTproxy(ORG_ID, SDDC_ID, session_token)

if intent_name == "create-lots-networks":
    number = int(sys.argv[2])
    createLotsNetworks(proxy,session_token,number)
elif intent_name == "add-users-to-csp-group":
    addUsersToCSPGroup(strCSPProdURL,session_token)
elif intent_name == "show-csp-group-diff":
    getCSPGroupDiff(strCSPProdURL,session_token)
elif intent_name == "show-csp-groups":
    getCSPGroups(strCSPProdURL,session_token)
elif intent_name == "show-csp-group-members":
        getCSPGroupMembers(strCSPProdURL,session_token)
elif intent_name == "show-csp-org-users":
    getCSPOrgUsers(strCSPProdURL,session_token)
elif intent_name == "show-csp-service-roles":
    getCSPServiceRoles(strCSPProdURL,session_token)
elif intent_name == "find-csp-user-by-service-role":
    findCSPUserByServiceRole(strCSPProdURL,session_token)
elif intent_name == "show-t0-routes":
    getSDDCT0routes(proxy,session_token)
elif intent_name == "show-t0-bgp-neighbors":
    getSDDCT0BGPneighbors(proxy, session_token)
elif intent_name == "new-t0-prefix-list":
    newBGPprefixlist(proxy, session_token)
elif intent_name == "attach-t0-prefix-list":
    neighbor_id = sys.argv[2]
    attachT0BGPprefixlist(proxy, session_token, neighbor_id)
elif intent_name == "detach-t0-prefix-lists":
    neighbor_id = sys.argv[2]
    detachT0BGPprefixlists(proxy, session_token, neighbor_id)
elif intent_name == "remove-t0-prefix-list":
    prefix_list_id = sys.argv[2]
    removeBPGprefixlist(proxy, session_token, prefix_list_id)
elif intent_name == "show-t0-prefix-lists":
    getSDDCT0PrefixLists(proxy, session_token)    
elif intent_name == "show-egress-interface-counters":
    edge_cluster_id = getSDDCEdgeCluster(proxy, session_token)
    edge_path_0 = getSDDCEdgeNodes(proxy, session_token, edge_cluster_id, 0)
    edge_path_1 = getSDDCEdgeNodes(proxy, session_token, edge_cluster_id, 1)
    stat_0 = getSDDCInternetStats(proxy,session_token, edge_path_0)
    stat_1 = getSDDCInternetStats(proxy,session_token, edge_path_1)
    total_stat = stat_0 + stat_1
    print("Current Total Bytes count on Internet interface is " + str(total_stat) + " Bytes.")
elif intent_name == "show-dns-zones":
    print(getSDDCDNS_Zones(proxy,session_token))
elif intent_name == "show-sddc-hosts":
    print(getCDChosts(SDDC_ID, ORG_ID, session_token))
elif intent_name == "show-sddcs":
    print(getSDDCS(ORG_ID, session_token))
elif intent_name == "show-org-users":
    print(showORGusers(ORG_ID, session_token))
elif intent_name == "show-vms":
    print(getVMs(proxy,session_token))
elif intent_name == "show-connected-accounts":
    print(getConnectedAccounts(ORG_ID,session_token))
elif intent_name == "show-compatible-subnets":
    n = (len(sys.argv))
    if ( n < 4):
        print("Usage: show-compatible-subnets linkedAccountId region")
    else:
        print(getCompatibleSubnets(ORG_ID,session_token,sys.argv[2],sys.argv[3]))
elif intent_name == "get-access-token":
    print(session_token)
elif intent_name == "show-vpn":
    if len(sys.argv) == 2:
        SDDCVPN = getSDDCVPN(proxy, session_token)
        print(SDDCVPN)
    elif len(sys.argv) == 3:
        VPN_ID = sys.argv[2]
        SDDC_VPN_STATS = getSDDCVPNSTATS(proxy,session_token,VPN_ID)
        print(SDDC_VPN_STATS)
    else:
        print("Incorrect syntax. Check the help.")
elif intent_name == "show-vpn-detailed":
    if len(sys.argv) == 3:
        VPN_ID = sys.argv[2]
        SDDC_VPN_SERVICES = getSDDCVPNServices(proxy,session_token,VPN_ID)
        print(SDDC_VPN_SERVICES)
    else:
        print("Incorrect syntax. Check the help.")
elif intent_name == "new-vpn":
    vpn_name = input("Enter the VPN Name: ")
    remote_private_ip = input('Enter the remote private IP:')
    remote_public_ip = input('Enter the remote public IP:')
    source_networks = input('Enter your source networks, separated by commas (for example: 192.168.10.0/24,192.168.20.0/24)')
    destination_networks = input('Enter your destination networks, separated by commas (for example: 192.168.10.0/24,192.168.20.0/24)')
    print(vpn_name + remote_private_ip + remote_public_ip)
elif intent_name == "show-vpn-ike-profile":
    vpn_ipsec_profile = getSDDCVPNIpsecProfiles(proxy, session_token)
    print(vpn_ipsec_profile)
elif intent_name == "show-l2vpn-services":
    l2vpn = getSDDCL2VPNServices(proxy, session_token)
    print(l2vpn)
elif intent_name == "show-l2vpn":
    l2vpn = getSDDCL2VPNSession(proxy, session_token)
    print(l2vpn)
elif intent_name == "new-l2vpn":
    display_name = sys.argv[2]
    endpoint = sys.argv[3]
    peer_ip = sys.argv[4]
    print("Creating an IPSec VPN IKE Profile...")
    ike_profile = newSDDCIPSecVpnIkeProfile(proxy,session_token,display_name)
    print(ike_profile)
    print("Creating an IPSec VPN Tunnel Profile...")
    tunnel_profile = newSDDCIPSecVpnTunnelProfile(proxy,session_token,display_name)
    print(tunnel_profile)
    print("Creating an IPSec VPN Session...")
    vpn_session = newSDDCIPSecVpnSession(proxy,session_token,display_name,endpoint,peer_ip)
    print(vpn_session)
    print("Creating an L2 VPN Session...")
    l2vpn = newSDDCL2VPN(proxy, session_token, display_name)
    print(l2vpn)
elif intent_name == "show-vpn-ipsec-tunnel-profile":
    vpn_ipsec_tunnel_profile = getSDDCVPNIpsecTunnelProfiles(proxy, session_token)
    print(vpn_ipsec_tunnel_profile)
elif intent_name == "show-vpn-ipsec-endpoints":
    vpn_ipsec_endpoints = getSDDCVPNIpsecEndpoints(proxy, session_token)
    print(vpn_ipsec_endpoints)
elif intent_name == "remove-vpn-ipsec-tunnel-profile":
    id = sys.argv[2]
    print(removeSDDCIPSecVpnTunnelProfile(proxy, session_token,id))
elif intent_name == "remove-vpn-ike-profile":
    id = sys.argv[2]
    print(removeSDDCIPSecVpnIkeProfile(proxy, session_token,id))
elif intent_name == "remove-vpn":
    id = sys.argv[2]
    print(removeSDDCVPN(proxy, session_token,id))
elif intent_name == "remove-l2vpn":
    id = sys.argv[2]
    print(removeSDDCL2VPN(proxy, session_token,id))
elif intent_name == "show-network":
    getSDDCnetworks(proxy, session_token)
elif intent_name == "new-network":
    if sys.argv[3].lower() == "routed" and len(sys.argv) == 7:
        # DHCP-Enabled Network
        display_name = sys.argv[2]
        routing_type = "ROUTED"
        gateway_address = sys.argv[4]
        dhcp_range = sys.argv[5]
        domain_name = sys.argv[6]
        newSDDC = newSDDCnetworks(proxy, session_token, display_name, gateway_address, dhcp_range, domain_name, routing_type)
        print(newSDDC)
    elif sys.argv[3].lower() == "disconnected" :
        # Disconnected Network
        display_name = sys.argv[2]
        routing_type = "DISCONNECTED"
        gateway_address = sys.argv[4]
        dhcp_range = ""
        domain_name = ""
        newSDDC = newSDDCnetworks(proxy, session_token, display_name, gateway_address, dhcp_range, domain_name, routing_type)
        print(newSDDC)
    elif sys.argv[3].lower() == "routed" and len(sys.argv) == 5:
        # Static Network
        display_name = sys.argv[2]
        gateway_address = sys.argv[4]
        dhcp_range = "none"
        domain_name = ""
        routing_type = "ROUTED"
        newSDDC = newSDDCnetworks(proxy, session_token, display_name, gateway_address, dhcp_range, domain_name, routing_type)
        print(newSDDC)
    elif sys.argv[3].lower() == "extended":
        display_name = sys.argv[2]
        tunnel_id = sys.argv[4]
        l2vpn_path = getSDDCL2VPNSessionPath(proxy,session_token)
        print(newSDDCStretchednetworks(proxy,session_token,display_name,tunnel_id, l2vpn_path))
    else:
        print("Incorrect syntax. Try again or check the help.")
elif intent_name == "remove-network":
    network_id = sys.argv[2]
    print(removeSDDCNetworks(proxy, session_token,network_id))
elif intent_name == "show-nat":
    if len(sys.argv) == 2:
        print(getSDDCNAT(proxy, session_token))
    elif len(sys.argv) == 3:
        NATid = sys.argv[2]
        NATStats = getSDDCNATStatistics(proxy,session_token,NATid)
        print(NATStats)
    else: 
        print("Incorrect syntax. Try again or check the help.")
elif intent_name == "new-nat-rule":
    display_name = sys.argv[2]
    action = sys.argv[3]
    if action == "any" or action == "REFLEXIVE":
        translated_network = sys.argv[4]
        source_network = sys.argv[5]
        service = ""
        translated_port = ""
        if len(sys.argv) >= 7:
            logging = sys.argv[6]
        else:
            logging = "false"
        if len(sys.argv) >= 8:
            status = sys.argv[7]
        else:
            status = "true"
        print(newSDDCNAT(proxy, session_token, display_name, action, translated_network, source_network, service, translated_port, logging, status))
    elif action == "DNAT": 
        translated_network = sys.argv[4]
        source_network = sys.argv[5]
        service = sys.argv[6]
        translated_port = sys.argv[7]
        if len(sys.argv) >= 9:
            logging = sys.argv[8]
        else:
            logging = "false"
        if len(sys.argv) >= 10:
            status = sys.argv[9]
        else:
            status = "true"
        print(newSDDCNAT(proxy, session_token, display_name, action, translated_network, source_network, service, translated_port, logging, status))
    else :
        print("There was an error. Make sure you follow the instructions.")
elif intent_name == "remove-nat-rule":
    if len(sys.argv) == 3:
        id = sys.argv[2]
        result = removeSDDCNAT(proxy, session_token, id)
        print(result)
        print("\n")
        print(getSDDCNAT(proxy, session_token))
    else:
        print("Incorrect syntax. Try again or check the help.")
elif intent_name == "show-cgw-rule":
    print(getSDDCCGWRule(proxy, session_token))
elif intent_name == "show-mgw-rule":
    print(getSDDCMGWRule(proxy, session_token))
elif intent_name == "show-dfw-section-rules":
    if len(sys.argv) == 2:
        print("Incorrect syntax. Specify the section name.")
    if len(sys.argv) == 3:
        section = sys.argv[2]
        print(getSDDCDFWRule(proxy, session_token,section))
elif intent_name == "new-dfw-rule":
    sequence_number = 0
    display_name = sys.argv[2]
    sg_string = sys.argv[3]
    dg_string = sys.argv[4]
    group_index = '/infra/domains/cgw/groups/'
    scope_index = '/infra/labels/cgw-'
    list_index = '/infra/services/'
    if sg_string.lower() == "connected_vpc":
        source_groups = ["/infra/tier-0s/vmc/groups/connected_vpc"]
    elif sg_string.lower() == "directconnect_prefixes":
        source_groups = ["/infra/tier-0s/vmc/groups/directConnect_prefixes"]
    elif sg_string.lower() == "s3_prefixes":
        source_groups = ["/infra/tier-0s/vmc/groups/s3_prefixes"]
    elif sg_string.lower() == "any":
        source_groups = ["ANY"]
    else:
        sg_list = sg_string.split(",")
        source_groups= [group_index + x for x in sg_list]
    if dg_string.lower() == "connected_vpc":
        destination_groups = ["/infra/tier-0s/vmc/groups/connected_vpc"]
    elif dg_string.lower() == "directconnect_prefixes":
        destination_groups = ["/infra/tier-0s/vmc/groups/directConnect_prefixes"]
    elif dg_string.lower() == "s3_prefixes":
        destination_groups = ["/infra/tier-0s/vmc/groups/s3_prefixes"]
    elif dg_string.lower() == "any":
        destination_groups = ["ANY"]
    else:
        dg_list = dg_string.split(",")
        destination_groups = [group_index + x for x in dg_list]
    services_string = sys.argv[5]
    if services_string.lower() == "any":
        services = ["ANY"]
    else:
        services_list = services_string.split(",")
        services = [list_index + x for x in services_list]
    action = sys.argv[6].upper()
    section = sys.argv[7]
    if len(sys.argv) == 9:
        sequence_number = sys.argv[8]
        new_rule = newSDDCDFWRule(proxy, session_token, display_name, source_groups, destination_groups, services, action, section, sequence_number)
    else:
        new_rule = newSDDCDFWRule(proxy, session_token, display_name, source_groups, destination_groups, services, action, section, sequence_number)
    if new_rule == 200:
        print("\n The rule has been created.")
        print(getSDDCDFWRule(proxy,session_token, section))
    else:
        print("Incorrect syntax. Try again.")
elif intent_name == "remove-dfw-rule":
    if len(sys.argv) != 4:
        print("Incorrect syntax. ")
    else:
        section_id = sys.argv[2]
        rule_id = sys.argv[3]
        if removeSDDCDFWRule(proxy, session_token, section_id, rule_id) == 200:
            print("The rule " + rule_id + " has been deleted")
            print(getSDDCDFWRule(proxy,session_token, section_id))
        else :
            print("Issues deleting the security rule. Check the syntax.")
elif intent_name == "show-dfw-section":
    print(getSDDCDFWSection(proxy, session_token))
elif intent_name == "new-dfw-section":
    if len(sys.argv) >= 5:
        print("Wrong syntax, try again.")
    if len(sys.argv) == 3:
        name = sys.argv[2]
        category = "Application"
        status_code = newSDDCDFWSection(proxy, session_token, name, category)
        if status_code == 200:
            print("Success:")
            print("\nThe section " + name + " has been created in the " + category + " category.")
            print(getSDDCDFWSection(proxy, session_token))
        else:
            print("There was an error. Check the syntax.")
    if len(sys.argv) == 4:
        name = sys.argv[2]
        category = sys.argv[3]
        status_code = newSDDCDFWSection(proxy, session_token, name, category)
        if status_code == 200:
            print("Success:")
            print("\nThe section " + name + " has been created in the " + category + " category.")
            print(getSDDCDFWSection(proxy, session_token))
        else:
            print("There was an error. Check the syntax.")
elif intent_name == "remove-dfw-section":
    if len(sys.argv) != 3:
        print("Incorrect syntax. ")
    else:
        section_id = sys.argv[2]
        if removeSDDCDFWSection(proxy, session_token, section_id) == 200:
            print("The section " + section_id + " has been deleted.")
            print(getSDDCDFWSection(proxy,session_token))
        else :
            print("Issues deleting the DFW section. Check the syntax.")
elif intent_name == "show-mtu":
    print("The MTU over the Direct Connect is " + str(getSDDCMTU(proxy,session_token)) + " Bytes.")
elif intent_name == "set-mtu":
    if len(sys.argv) != 3:
        print("Incorrect syntax.")
    mtu = sys.argv[2]
    if int(mtu) < 1500 or int(mtu) > 8900:
        print("Incorrect syntax. The MTU should be between 1500 and 8900 bytes.")
    else:
        setMTU = setSDDCMTU(proxy,session_token,mtu)
        if setMTU == 200:
            print("The MTU has been updated:")
            print("\nThe MTU over the Direct Connect is now set to " + str(getSDDCMTU(proxy,session_token)) + " Bytes.")
        else:
            print("There was an error. Check the syntax.")
elif intent_name == "show-shadow-account":
    print("The SDDC is deployed in the " + str(getSDDCShadowAccount(proxy,session_token)) + " AWS Shadow Account.")
elif intent_name == "show-sddc-bgp-as":
    print("The SDDC BGP Autonomous System is ASN " + getSDDCBGPAS(proxy,session_token) + ".")
elif intent_name == "set-sddc-bgp-as":
    if len(sys.argv) != 3:
        print("Incorrect syntax.")
    else:
        asn = sys.argv[2]
        setasn = setSDDCBGPAS(proxy,session_token,asn)
        print(setasn)
        if setasn == 200:
            print("The BGP AS has been updated:")
            print("The SDDC BGP Autonomous System is ASN " + getSDDCBGPAS(proxy,session_token) + ".")
        else:
            print("There was an error. Check the syntax.")
            print("The SDDC BGP Autonomous System is ASN " + getSDDCBGPAS(proxy,session_token) + ".")
elif intent_name == "show-sddc-bgp-vpn":
    print(getSDDCBGPVPN(proxy,session_token))
elif intent_name == "show-sddc-connected-vpc":
    print(getSDDCConnectedVPC(proxy,session_token))
elif intent_name == "set-sddc-connected-services":
    value = sys.argv[2]
    if setSDDCConnectedServices(proxy,session_token,value) == 200 and value == 'true':
        print("S3 access from the SDDC is over the ENI.")
    elif setSDDCConnectedServices(proxy,session_token,value) == 200 and value == 'false':
        print("S3 access from the SDDC is over the Internet.")
    else:
        print("Make sure you use a 'true' or 'false' parameter")
elif intent_name == "show-sddc-public-ip":
    print(getSDDCPublicIP(proxy,session_token))
elif intent_name == "new-sddc-public-ip":
    if len(sys.argv) != 3:
        print("Incorrect syntax. Please add a description of the public IP address.")
    else :
        notes = sys.argv[2]
        if newSDDCPublicIP(proxy, session_token, notes) == 200:
            print(getSDDCPublicIP(proxy,session_token))
        else :
            print("Issues creating a Public IP.")
elif intent_name == "set-public-ip":
    if len(sys.argv) != 4:
        print("Incorrect syntax. Please add the new description of the public IP address.")
    else:
        public_ip = sys.argv[2]
        notes = sys.argv[3]
        if setSDDCPublicIP(proxy, session_token, notes, public_ip) == 200:
            print(getSDDCPublicIP(proxy,session_token))
        else :
            print("Issues updating a Public IP. Check the syntax.")
elif intent_name == "remove-sddc-public-ip":
    if len(sys.argv) != 3:
        print("Incorrect syntax. ")
    else:
        public_ip = sys.argv[2]
        if removeSDDCPublicIP(proxy, session_token, public_ip) == 200:
            print(getSDDCPublicIP(proxy,session_token))
        else :
            print("Issues deleting the Public IP. Check the syntax.")
elif intent_name == "show-vpn-internet-ip":
    public_ip = getSDDCVPNInternetIP(proxy, session_token)
    print(public_ip)
elif intent_name == "show-sddc-state":
    sddc_state = getSDDCState(ORG_ID, SDDC_ID, session_token)
    print("\nThis is your current environment:")
    print(sddc_state)
elif intent_name == "new-mgw-rule":
    sequence_number = 0
    display_name = sys.argv[2]
    # String and List Manipulation:
    sg_string = sys.argv[3]
    dg_string = sys.argv[4]
    group_index = '/infra/domains/mgw/groups/'
    list_index = '/infra/services/'
    if sg_string.lower() == "any":
        source_groups = ["ANY"]
    else:
        sg_string = sg_string.upper()
        sg_list = sg_string.split(",")
        source_groups= [group_index + x for x in sg_list]
    
    # String and List Manipulation:
    # We take the input argument (NSX-MANAGER or VCENTER or ESXI nodes)

    if dg_string.lower() == "any":
        destination_groups = ["ANY"]
    else:
        dg_string = dg_string.upper()
        dg_list = dg_string.split(",")
        destination_groups= [group_index + x for x in dg_list]


    services_string = sys.argv[5]
    if services_string.lower() == "any":
        services = ["ANY"]
    else:
        services_list = services_string.split(",")
        print(services_list)
        services = [list_index + x for x in services_list]
    action = sys.argv[6].upper()
    if len(sys.argv) == 8:
        sequence_number = sys.argv[7]
        new_rule = newSDDCMGWRule(proxy, session_token, display_name, source_groups, destination_groups, services, action, sequence_number)
        print(new_rule)
    else:
        new_rule = newSDDCMGWRule(proxy, session_token, display_name, source_groups, destination_groups, services, action, sequence_number)
    if new_rule == 200:
        print("\n The rule has been created.")
        print(getSDDCMGWRule(proxy,session_token))
        print(new_rule)
    else:
        print("Incorrect syntax. Try again.")
elif intent_name == "new-cgw-rule":
    sequence_number = 0
    display_name = sys.argv[2]
    sg_string = sys.argv[3]
    dg_string = sys.argv[4]
    group_index = '/infra/domains/cgw/groups/'
    scope_index = '/infra/labels/cgw-'
    list_index = '/infra/services/'
    if sg_string.lower() == "connected_vpc":
        source_groups = ["/infra/tier-0s/vmc/groups/connected_vpc"]
    elif sg_string.lower() == "directconnect_prefixes":
        source_groups = ["/infra/tier-0s/vmc/groups/directConnect_prefixes"]
    elif sg_string.lower() == "s3_prefixes":
        source_groups = ["/infra/tier-0s/vmc/groups/s3_prefixes"]
    elif sg_string.lower() == "any":
        source_groups = ["ANY"]
    else:
        sg_list = sg_string.split(",")
        source_groups = [group_index + x for x in sg_list]
    if dg_string.lower() == "connected_vpc":
        destination_groups = ["/infra/tier-0s/vmc/groups/connected_vpc"]
    elif dg_string.lower() == "directconnect_prefixes":
        destination_groups = ["/infra/tier-0s/vmc/groups/directConnect_prefixes"]
    elif dg_string.lower() == "s3_prefixes":
        destination_groups = ["/infra/tier-0s/vmc/groups/s3_prefixes"]
    elif dg_string.lower() == "any":
        destination_groups = ["ANY"]
    else:
        dg_list = dg_string.split(",")
        destination_groups= [group_index + x for x in dg_list]
    services_string = sys.argv[5]
    if services_string.lower() == "any":
        services = ["ANY"]
    else:
        services_list = services_string.split(",")
        services = [list_index + x for x in services_list]
    action = sys.argv[6].upper()
    scope_string = sys.argv[7].lower()
    scope_list = scope_string.split(",")
    scope = [scope_index + x for x in scope_list]
    if len(sys.argv) == 9:
        sequence_number = sys.argv[8]
        new_rule = newSDDCCGWRule(proxy, session_token, display_name, source_groups, destination_groups, services, action, scope, sequence_number)
    else:
        new_rule = newSDDCCGWRule(proxy, session_token, display_name, source_groups, destination_groups, services, action, scope, sequence_number)
    if new_rule == 200:
        print("\n The rule has been created.")
        print(getSDDCCGWRule(proxy,session_token))
    else:
        print("Incorrect syntax. Try again.")
elif intent_name == "remove-cgw-rule":
    if len(sys.argv) != 3:
        print("Incorrect syntax. ")
    else:
        rule_id = sys.argv[2]
        if removeSDDCCGWRule(proxy, session_token, rule_id) == 200:
            print("The rule " + rule_id + " has been deleted")
            print(getSDDCCGWRule(proxy,session_token))
        else :
            print("Issues deleting the security rule. Check the syntax.")
elif intent_name == "remove-mgw-rule":
    if len(sys.argv) != 3:
        print("Incorrect syntax. ")
    else:
        rule_id = sys.argv[2]
        if removeSDDCMGWRule(proxy, session_token, rule_id) == 200:
            print(getSDDCMGWRule(proxy,session_token))
        else :
            print("Issues deleting the security rule. Check the syntax.")
elif intent_name == "new-group":
    gw = sys.argv[2].lower()
    group_id = sys.argv[3]
    if gw == "mgw" and len(sys.argv) == 4:
        ip_addresses = []
        ip_address = ''
        # Start a loop that will run until the user enters 'done'.
        while ip_address != 'done':
        # Ask the user for a name.
            ip_address = input("Please enter IP address (for example, \"172.16.10.20\") or type 'done' when your list is finished:")
        # Add the new name to our list.
            if ip_address != "done":
                ip_addresses.append(ip_address)
        newSDDCGroup = newSDDCGroupIPaddress(proxy,session_token,gw,group_id,ip_addresses)
        print(newSDDCGroup)
    if gw == "mgw" and len(sys.argv) == 5:
        ip_addresses_string = sys.argv [4]
        ip_addresses = ip_addresses_string.split(",")
        newSDDCGroup = newSDDCGroupIPaddress(proxy,session_token,gw,group_id,ip_addresses)
        print(newSDDCGroup) 
    if gw == "cgw":
        group_criteria = sys.argv[4].lower()
        if group_criteria not in ["ip-based", "member-based", "criteria-based", "group-based"]:
            print("Incorrect syntax. Make sure you use one of the 4 methods to define a CGW group: ip-based, member-based, criteria-based, or group-based.")
        else:
            if group_criteria == "ip-based" and len(sys.argv) == 5:
                ip_addresses = []
            # Set new_name to something other than 'quit'.
                ip_address = ''
            # Start a loop that will run until the user enters 'quit'.
                while ip_address != 'done':
            # Ask the user for a name.
                    ip_address = input("Please enter IP address (\"172.16.10.20\") or type 'done' when your list is finished: ")
            # Add the new name to our list.
                    if ip_address != "done":
                        ip_addresses.append(ip_address)
                newSDDCGroup = newSDDCGroupIPaddress(proxy,session_token,gw,group_id,ip_addresses)
                print(newSDDCGroup)
            elif group_criteria == "ip-based" and len(sys.argv) == 6:
                ip_addresses_string = sys.argv [5]
                ip_addresses = ip_addresses_string.split(",")
                newSDDCGroup = newSDDCGroupIPaddress(proxy,session_token,gw,group_id,ip_addresses)
                print(newSDDCGroup)
            elif group_criteria == "criteria-based" and len(sys.argv) == 5:
            # Only support for Virtual_Machine based criteria for now.
                # member_type = input("Please enter your criteria type:")
                member_type = "VirtualMachine"
                key = input("Please enter the criteria (Name, Tag, OSName or ComputerName): ")
                if key not in ["Name", "Tag", "OSName", "ComputerName"]:
                    print("Incorrect syntax. Check again.")
                else:
                    operator=input("Please enter the operator (EQUALS, NOTEQUALS, CONTAINS, STARTSWITH, ENDSWITH): ")
                    if operator not in ["EQUALS", "NOTEQUALS", "CONTAINS", "STARTSWITH", "ENDSWITH"]:
                        print("Incorrect syntax. Check again.")
                    if key == "Tag" and operator == "NOTEQUALS":
                        print("Incorrect syntax. The tag method does not support the NOTEQUALS Operator. Try again.")
                    else:
                        value=input("Enter the value of your membership criteria: ")
                        newSDDCGroup = newSDDCGroupCriteria(proxy,session_token,gw,group_id,member_type,key,operator,value)
                        print(newSDDCGroup)
            elif group_criteria == "criteria-based" and len(sys.argv) == 8:
            # Only support for Virtual_Machine based criteria for now.
                # member_type = input("Please enter your criteria type:")
                member_type = "VirtualMachine"
                key = sys.argv[5]
                operator = sys.argv[6]
                value = sys.argv[7]
                if key not in ["Name", "Tag", "OSName", "ComputerName"]:
                    print("Incorrect syntax. Check again.")
                elif operator not in ["EQUALS", "NOTEQUALS", "CONTAINS", "STARTSWITH", "ENDSWITH"]:
                    print("Incorrect syntax. Check again.")
                else:
                    newSDDCGroup = newSDDCGroupCriteria(proxy,session_token,gw,group_id,member_type,key,operator,value)
                    print(newSDDCGroup)
            elif group_criteria == "member-based" and len(sys.argv) == 5:
            # v1 will be based on a list of VMs. Will not include segment-based for the time being,
                vm_list = []
            # Set new_name to something other than 'quit'.
                vm_name = ''
            # Start a loop that will run until the user enters 'quit'.
                while vm_name != 'done':
            # Ask the user for a name.
                    vm_name = input("Please enter the name of the VM or type 'done' when your list is finished: ")
            # Add the new name to our list.
                    if vm_name != "done":
                        vm_id = getVMExternalID(proxy,session_token,vm_name)
                        vm_list.append(vm_id)
                newSDDCGroup = newSDDCGroupVM(proxy,session_token,gw,group_id,vm_list)
                print(newSDDCGroup)
            elif group_criteria == "member-based" and len(sys.argv) == 6:
                vm_name_string = sys.argv[5]
                vm_name_list = vm_name_string.split(",")
                ## iterate through list or through previous string to get list of external ids
                vm_external_id_list = [getVMExternalID(proxy,session_token,x) for x in vm_name_list]
                # vm_id = getVMExternalID(proxy,session_token,vm_name)
                newSDDCGroup = newSDDCGroupVM(proxy,session_token,gw,group_id,vm_external_id_list)
                print(newSDDCGroup)
            elif group_criteria == "group-based":
                #Example: new-group cgw new-group-name group-based existing-group-to-add-as-member
                group_name_string = sys.argv[5]
                retval = newSDDCGroupGr(proxy,session_token,gw,group_id,group_name_string)
                if retval == 200:
                    print("Group created")
                else:
                    print("Could not create group")
            else:
                print("Incorrect syntax. Try again.")
elif intent_name == "show-group":
    if len(sys.argv) == 2:
        mgw_groups = getSDDCGroups(proxy, session_token, "mgw")
        print(("\nHere are the Management Groups:"))
        print(mgw_groups)
        cgw_groups = getSDDCGroups(proxy, session_token, "cgw")
        print(("\nHere are the Comnpute Groups:"))
        print(cgw_groups)
    elif len(sys.argv) == 3:
        gw = sys.argv[2].lower()
        sddc_groups = getSDDCGroups(proxy, session_token, gw)
        print(sddc_groups)
    elif len(sys.argv) == 4:
        group_id = sys.argv[3]
        gw = sys.argv[2].lower()
        sddc_groups = getSDDCGroup(proxy,session_token,gw,group_id)
    else:
        print("Incorrect syntax. Try again or check the help.")
elif intent_name == "show-group-association":
    if len(sys.argv) == 4:
        group_id = sys.argv[3]
        gw = sys.argv[2].lower()
        sddc_groups = getSDDCGroupAssociation(proxy,session_token,gw,group_id)
    else:
        print("Incorrect syntax. Try again or check the help.")
elif intent_name == "remove-group":
    if len(sys.argv) != 4:
        print("This command did not work. Follow the instructions")
    else:
        gw = sys.argv[2].lower()
        group_id = sys.argv[3]
        sddc_group_delete = removeSDDCGroup(proxy,session_token,gw,group_id)
elif intent_name == "show-dns-services":
    if len(sys.argv) == 2:
        mgw_dns_services = getSDDCDNS_Services(proxy, session_token, "mgw")
        print("\nHere are the Management DNS Services:")
        print(mgw_dns_services)
        cgw_dns_services = getSDDCDNS_Services(proxy, session_token, "cgw")
        print("\nHere are the Compute DNS Services:")
        print(cgw_dns_services)
    elif len(sys.argv) == 3:
        gw = sys.argv[2].lower()
        sddc_dns_services = getSDDCDNS_Services(proxy, session_token, gw)
        print(sddc_dns_services)
    else:
        print("Incorrect syntax. Try again or check the help.")
elif intent_name == "show-services" or intent_name == "show-service":
    if len(sys.argv) == 2:
        sddc_services = getSDDCServices(proxy,session_token)
        print(sddc_services)
    elif len(sys.argv) == 3:
        service_id = sys.argv[2]
        sddc_service = getSDDCService(proxy,session_token,service_id)
        print(sddc_service)
    else:
        print("This command did not work. Follow the instructions")
elif intent_name == "new-service":
    if len(sys.argv) == 2:
        service_id = input("Please input the name of the service:")
        service_entry_list = []
            # Start a loop that will run until the user enters 'quit'.
            # Ask the user for a name.
        destination_port = ""
        while destination_port != 'done':
            destination_port_list = []
            source_port_list = []
            service_entry_id = input("Please enter the Service Entry ID:")
            l4_protocol = input("Please enter the L4 Protocol:")
            source_port = ""
            destination_port = ""
            while source_port != 'done':
                source_port = input("Plese enter the Source Ports or type 'done' when your list is finished:")
                if source_port != "done":
                    source_port_list.append(source_port)
            while (destination_port != 'next') and (destination_port != "done"):
                source_port = ""
                destination_port = input("Plese enter the Destination Ports, type 'next' when you want to define another service entry or 'done' if you have finished:")
                if (destination_port != 'next') and (destination_port != "done"):
                    destination_port_list.append(destination_port)
            # print(service_id)
            # print(destination_port_list)
            # print(source_port_list)
            # print(l4_protocol)
            service_entry = {
                "l4_protocol": l4_protocol,
                "source_ports": source_port_list,
                "destination_ports" : destination_port_list,
                "resource_type" : "L4PortSetServiceEntry",
                "id" : service_entry_id,
                "display_name" : service_entry_id     }
            service_entry_list.append(service_entry)
            # print(service_entry)
            # print(service_entry_list)
        newSDDCService(proxy,session_token,service_id,service_entry_list)
        sddc_service = getSDDCService(proxy,session_token,service_id)
        print(sddc_service)
    elif len(sys.argv) == 4:
        name = sys.argv[2]
        service_entry_string = sys.argv[3]
        service_entry_list = service_entry_string.split(",")
        newSDDCService(proxy,session_token,name,service_entry_list)
        sddc_service = getSDDCService(proxy,session_token,service_id)
        print(sddc_service)
    else:
        print("Incorrect syntax")
# elif intent_name == "new-service-entry":
#    print("This is WIP")
elif intent_name == "remove-service":
    if len(sys.argv) > 3:
        print("This command did not work. Follow the instructions")
    else:
        service_id = sys.argv[2]
        sddc_service_delete = removeSDDCService(proxy,session_token,service_id)
elif intent_name == "help":
    getHelp()
else:
    getHelp()
    
