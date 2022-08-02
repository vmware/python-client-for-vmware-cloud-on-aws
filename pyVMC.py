#!/usr/bin/env python3
# The shebang above is to tell the shell which interpreter to use. This make the file executable without "python3" in front of it (otherwise I had to use python3 pyvmc.py)
# I also had to change the permissions of the file to make it run. "chmod +x pyVMC.py" did the trick.
# I also added "export PATH="MY/PYVMC/DIRECTORY":$PATH" (otherwise I had to use ./pyvmc.y)
# For git BASH on Windows, you can use something like this #!/C/Users/usr1/AppData/Local/Programs/Python/Python38/python.exe

# Python Client for VMware Cloud on AWS

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################


"""

Welcome to PyVMC ! 

VMware Cloud on AWS API Documentation is available at: https://code.vmware.com/apis/920/vmware-cloud-on-aws
CSP API documentation is available at https://console.cloud.vmware.com/csp/gateway/api-docs
vCenter API documentation is available at https://code.vmware.com/apis/366/vsphere-automation


You can install python 3.9 from https://www.python.org/downloads/windows/ (Windows) or https://www.python.org/downloads/mac-osx/ (MacOs).

You can install the dependent python packages locally (handy for Lambda) with:
pip3 install requests or pip3 install requests -t . --upgrade
pip3 install configparser or pip3 install configparser -t . --upgrade
pip3 install PTable or pip3 install PTable -t . --upgrade

With git BASH on Windows, you might need to use 'python -m pip install' instead of pip3 install

"""
import re

import requests                         # need this for Get/Post/Delete
import configparser                     # parsing config file
import argparse
import operator
import time
import json
import sys
import pandas as pd
from deepdiff import DeepDiff
from os.path import exists
from prettytable import PrettyTable
from requests.sessions import session
from datetime import datetime
from requests.auth import HTTPBasicAuth
from re import search
from pyvmc_csp import *
from pyvmc_nsx import *
from pyvmc_vmc import *
from pyvmc_vcdr import *

if not exists("./config.ini"):
    print('config.ini is missing - rename config.ini.example to config.ini and populate the required values inside the file.')
    sys.exit()

DEBUG_MODE = False

config = configparser.ConfigParser()
config.read("./config.ini")
strProdURL      = config.get("vmcConfig", "strProdURL")
strCSPProdURL   = config.get("vmcConfig", "strCSPProdURL")
Refresh_Token   = config.get("vmcConfig", "refresh_Token")
ORG_ID          = config.get("vmcConfig", "org_id")
SDDC_ID         = config.get("vmcConfig", "sddc_id")
strVCDRProdURL  = config.get("vmcConfig", "strVCDRProdURL")

if config.has_section("vtcConfig"):
    aws_acc         = config.get("vtcConfig", "MyAWS")
    region          = config.get("vtcConfig", "AWS_region")
    dxgw_id         = config.get("vtcConfig", "DXGW_id")
    dxgw_owner      = config.get("vtcConfig", "DXGW_owner")
else:
    print('config.ini is outdated - the vtcConfig section is missing. Please insert the vtcConfig section in config.ini.example into your config.ini file. All transit gateway commands will fail without this configuration change.')

if config.has_section("tkgConfig"):
    egress_CIDR     = config.get("tkgConfig", "egress_CIDR")
    ingress_CIDR    = config.get("tkgConfig", "ingress_CIDR")
    namespace_CIDR  = config.get("tkgConfig", "namespace_CIDR")
    service_CIDR    = config.get("tkgConfig", "service_CIDR")
else:
    print('config.ini is outdated - the tkgConfig section is missing. Please insert the tkgConfig section in config.ini.example into your config.ini file. All TKG commands will fail without this configuration change.')

if len(strProdURL) == 0 or len(strCSPProdURL) == 0 or len(Refresh_Token) == 0 or len(ORG_ID) == 0 or len(SDDC_ID) == 0:
    print('strProdURL, strCSPProdURL, Refresh_Token, ORG_ID, and SDDC_ID must all be populated in config.ini')
    sys.exit()

class data():
    sddc_name       = ""
    sddc_status     = ""
    sddc_region     = ""
    sddc_cluster    = ""
    sddc_hosts      = 0
    sddc_type       = ""

def generate_table(results):
    """Generates a 'prettytable' using a JSON payload; automatically uses the dictionary keys in the payload as column headers."""
    keyslist = list(results[0].keys())
    table = PrettyTable(keyslist)
    for dct in results:
        table.add_row([dct.get(c, "") for c in keyslist])
    return table

# ============================
# CSP - Service Definitions
# ============================


def getServiceDefinitions(strCSPProdURL, orgID, sessiontoken):
    """Gets services and URI for associated access token and Org ID"""
    json_response = get_services_json(strCSPProdURL, orgID, sessiontoken)
    services= json_response['servicesList']
    table = PrettyTable(['Service Name', 'Access type', 'Service URL'])
    for i in services:
        table.add_row([i['displayName'], i['serviceAccessType'], i['serviceUrls']['serviceHome']])
    print(table)

def addUsersToCSPGroup(csp_url, session_token):
    if len(sys.argv) < 4:
        print('Usage: add-users-to-csp-group [groupID] [comma separated email addresses')
        sys.exit()
    groupId = sys.argv[2]
    usernamesToAdd = sys.argv[3].split(',')
    params = {
            'notifyUsers': 'false',
            'usernamesToAdd': usernamesToAdd
    }
    json_response = add_users_csp_group_json(csp_url, ORG_ID, session_token, groupId, params)
    print(f"Added: {json_response['succeeded']}" )
    print(f"Failed: {json_response['failed']}" )


def findCSPUserByServiceRole(csp_url, session_token):
    if len(sys.argv) < 3:
        print('Usage: find-csp-user-by-service-role [role]')
        sys.exit()
    role_name = sys.argv[2]
    json_response = get_csp_users_json(csp_url, ORG_ID, session_token)
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
    json_response_groups = get_csp_group_info_json(csp_url, ORG_ID, session_token, groupId)
    grouproles = json_response_groups['serviceRoles']
    json_response_users = get_csp_users_json(csp_url, ORG_ID, session_token)
    users = json_response_users['results']
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


def getCSPGroupMembers(csp_url, session_token):
    if len(sys.argv) < 3:
        print('Usage: show-csp-group-members [groupID]')
    groupid = sys.argv[2]
    json_response = get_csp_users_group_json(csp_url, ORG_ID, session_token, groupid)
    users = json_response['results']
    table = PrettyTable(['Username','First Name', 'Last Name','Email','userId'])
    for user in users:
        table.add_row([user['username'],user['firstName'],user['lastName'],user['email'],user['userId']])
    print(table)


def getCSPGroups(csp_url, session_token):
    json_response = get_csp_groups_json(csp_url, ORG_ID, session_token)
    groups = json_response['results']
    table = PrettyTable(['ID','Name', 'Group Type','User Count'])
    for grp in groups:
        table.add_row([grp['id'],grp['displayName'], grp['groupType'], grp['usersCount']])
    print(table)


def getCSPOrgUsers(csp_url,session_token):
    if len(sys.argv) < 3:
        print('Usage: show-csp-org-users [searchTerms]')
    else:
        searchTerm = sys.argv[2]
        params = {
            'userSearchTerm': searchTerm
        }
        json_response = search_csp_users_json(csp_url, session_token, params, ORG_ID)
        users = json_response['results']
        if len(users) >= 20:
            print("Search API is limited to 20 results, refine your search term for accurate results.")
        table = PrettyTable(['Username', 'First Name', 'Last Name', 'Email', 'userId'])
        for user in users:
            table.add_row([user['user']['username'], user['user']['firstName'], user['user']['lastName'], user['user']['email'], user['user']['userId']])
        print(table)


def getCSPServiceRoles(csp_url, session_token):
    json_response = get_csp_service_roles_json(csp_url, ORG_ID, session_token)
    for svc_def in json_response['serviceRoles']:
        for svc_role in svc_def['serviceRoleNames']:
            print(svc_role)


def showORGusers(orgID, sessiontoken):
    """Prints out all Org users, sorted by last name"""
    jsonResponse = get_csp_users_json(strCSPProdURL, orgID, sessiontoken)
    users = jsonResponse['results']
    table = PrettyTable(['First Name', 'Last Name', 'User Name'])
    for i in users:
        table.add_row([i['user']['firstName'],i['user']['lastName'],i['user']['username']])
    print (table.get_string(sortby="Last Name"))


# ============================
# SDDC - AWS Account and VPC
# ============================


def setSDDCConnectedServices(proxy_url, sessiontoken, value):
    """Sets SDDC access to S3 to either internet or connected VPC via input value"""
    json_response = get_conencted_vpc_json(proxy_url, sessiontoken)
    sddc_connected_vpc = json_response['results'][0]
    json_data = {
        "name": "s3",
        "enabled": value
    }
    json_response_status_code = set_connected_vpc_services_json(proxy, sessiontoken, sddc_connected_vpc['linked_vpc_id'], json_data)
    return json_response_status_code


def getCompatibleSubnets(orgID, sessiontoken, linkedAccountId,region):
    """Lists all of the compatible subnets by Account ID and AWS Region"""
    jsonResponse = get_compatible_subnets_json(strProdURL, orgID, sessiontoken, linkedAccountId, region)
    vpc_map = jsonResponse['vpc_map']
    table = PrettyTable(['vpc','description'])
    subnet_table = PrettyTable(['vpc_id','subnet_id','subnet_cidr_block','name','compatible'])
    for i in vpc_map:
        myvpc = jsonResponse['vpc_map'][i]
        table.add_row([myvpc['vpc_id'],myvpc['description']])
        for j in myvpc['subnets']:
            subnet_table.add_row([j['vpc_id'],j['subnet_id'],j['subnet_cidr_block'],j['name'],j['compatible']])
    print(table)
    print(subnet_table)


def getConnectedAccounts(orgID, sessiontoken):
    """Prints all connected AWS accounts"""
    accounts = get_connected_accounts_json(strProdURL, orgID, sessiontoken)
    orgtable = PrettyTable(['OrgID'])
    orgtable.add_row([orgID])
    print(str(orgtable))
    table = PrettyTable(['Account Number','id'])
    for i in accounts:
        table.add_row([i['account_number'],i['id']])
    print(table)


def getSDDCConnectedVPC(proxy_url, session_token):
    """Returns table with Connected VPC and Services information - Compatible with M18+ SDDCs only"""
    json_response = get_conencted_vpc_json(proxy_url, session_token)
    sddc_connected_vpc = json_response['results'][0]
    sddc_connected_vpc_services = get_connected_vpc_services_json(proxy_url, session_token, sddc_connected_vpc['linked_vpc_id'])
#   The API changed for connected VPCs from M16 to M18 when the connected VPC prefix lists were added to M18.
#   This if-else block should allow this function to work with both M16 and earlier as well as M18 and newer SDDCs.
    if 'active_eni' in sddc_connected_vpc:
        eni = sddc_connected_vpc['active_eni']
    elif 'traffic_group_eni_mappings' in sddc_connected_vpc:
        eni = sddc_connected_vpc['traffic_group_eni_mappings'][0]['eni']
    else:
        eni = "Unknown"
    table = PrettyTable(['Customer-Owned Account', 'Connected VPC ID', 'Subnet', 'Availability Zone', 'ENI', 'Service Access'])
    table.add_row([sddc_connected_vpc['linked_account'], sddc_connected_vpc['linked_vpc_id'], sddc_connected_vpc['linked_vpc_subnets'][0]['cidr'], sddc_connected_vpc['linked_vpc_subnets'][0]['availability_zone'], eni, sddc_connected_vpc_services['results'][0]['enabled']])
    return table


def getSDDCShadowAccount(proxy_url,sessiontoken):
    """Returns SDDC Shadow Account"""
    json_response = get_sddc_shadow_account_json(proxy_url, sessiontoken)
    sddc_shadow_account = json_response['shadow_account']
    return sddc_shadow_account


def getAccessToken(myKey):
    """ Gets the Access Token using the Refresh Token """
    params = {'api_token': myKey}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post('https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize', params=params, headers=headers)
    jsonResponse = response.json()
    access_token = jsonResponse['access_token']
    return access_token


# ============================
# SDDC - SDDC
# ============================


def getSDDCState(org_id, sddc_id, sessiontoken):
    """Prints out state of selected SDDC"""
    sddc_state = get_sddc_info_json(strProdURL, org_id, sessiontoken, sddc_id)
    table = PrettyTable(['Name', 'Id', 'Status', 'Type', 'Region', 'Deployment Type'])
    table.add_row([sddc_state['name'], sddc_state['id'], sddc_state['sddc_state'], sddc_state['sddc_type'], sddc_state['resource_config']['region'], sddc_state['resource_config']['deployment_type']])
    print("\nThis is your current environment:")
    print (table)


def getSDDCS(orgID, sessiontoken):
    """Prints all SDDCs in an Org with their clusters and number of hosts"""
    sddcInfo = get_sddcs_json(strProdURL, orgID, sessiontoken)
    orgtable = PrettyTable(['OrgID'])
    orgtable.add_row([orgID])
    print(str(orgtable))
    table = PrettyTable(['Name', 'Cloud', 'Status', 'Hosts', 'ID'])
    for i in sddcInfo:
        hostcount = 0
        mySDDCs = get_sddc_info_json(strProdURL, orgID, sessiontoken, i['id'])
        clusters = mySDDCs['resource_config']['clusters']
        if clusters:
            hostcount = 0
            for c in clusters:
                hostcount += len(c['esx_host_list'])
        table.add_row([i['name'], i['provider'],i['sddc_state'], hostcount, i['id']])
    print(table)


def getVMs(proxy_url, session_token):
    """ Gets a list of all compute VMs, with their power state and their external ID. """
    json_response = get_vms_json(proxy_url, session_token)
    extracted_dictionary = json_response['results']
    table = PrettyTable(['Display_Name', 'Status', 'External_ID'])
    for i in extracted_dictionary:
        table.add_row([i['display_name'], i['power_state'], i['external_id']])
    return table


def getSDDChosts(sddcID, orgID, sessiontoken):
    """Prints out all SDDC Hosts"""
    jsonResponse = get_sddc_info_json(strProdURL, orgID, sessiontoken, sddcID)
    cdcID = jsonResponse['resource_config']['vc_ip']
    cdcID = cdcID.split("vcenter")
    cdcID = cdcID[1]
    cdcID = cdcID.split("/")
    cdcID = cdcID[0]
    clusters = jsonResponse['resource_config']['clusters']
    table = PrettyTable(['Cluster', 'Name', 'Status', 'ID'])
    for c in clusters:
        for i in c['esx_host_list']:
            hostName = i['name'] + cdcID
            table.add_row([c['cluster_name'], hostName, i['esx_state'], i['esx_id']])
    print(table)


def getNSXTproxy(orgID, sddcID, sessiontoken):
    """Returns the NSX Reverse Proxy URL"""
    json_response = get_sddc_info_json(strProdURL, orgID, sessiontoken, sddcID)
    proxy_url = json_response['resource_config']['nsx_api_public_endpoint_url']
    return proxy_url


# ============================
# SDDC - TKG
# ============================


def get_cluster_id(org_id, sddc_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/vmc/api/orgs/{}/sddcs/{}".format(strProdURL, org_id, sddc_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    cluster_id = json_response['resource_config']['clusters'][0]['cluster_id']
    return cluster_id

def validate_cluster( org_id, sddc_id, cluster_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/wcp/v1/orgs/{}/deployments/{}/clusters/{}/operations/validate-cluster".format(strProdURL, org_id, sddc_id, cluster_id)
    body = {
        # no need for a body
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    task_id = json_response ['id']
    return task_id

def validate_network( org_id, sddc_id, cluster_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/wcp/v1/orgs/{}/deployments/{}/clusters/{}/operations/validate-network".format(strProdURL, org_id, sddc_id, cluster_id)
    body = {
        "egress_cidr": [egress_CIDR],
        "ingress_cidr": [ingress_CIDR],
        "namespace_cidr": [namespace_CIDR],
        "service_cidr": service_CIDR
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    task_id = json_response ['id']
    return task_id

def enable_wcp( org_id, sddc_id, cluster_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/wcp/v1/orgs/{}/deployments/{}/clusters/{}/operations/enable-wcp".format(strProdURL, org_id, sddc_id, cluster_id)
    body = {
        "egress_cidr": [egress_CIDR],
        "ingress_cidr": [ingress_CIDR],
        "namespace_cidr": [namespace_CIDR],
        "service_cidr": service_CIDR
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    task_id = json_response ['id']
    return task_id

def disable_wcp( org_id, sddc_id, cluster_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/wcp/v1/orgs/{}/deployments/{}/clusters/{}/operations/disable-wcp".format(strProdURL, org_id, sddc_id, cluster_id)
    body = {
        # no need for a body
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    task_id = json_response ['id']
    return task_id


# ============================
# VTC - AWS Operations
# ============================


def connect_aws_account(account, region, resource_id, org_id, session_token):
    response = connect_aws_account_json(strProdURL, account, region, resource_id, org_id, session_token)
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['id']
    return task_id


def disconnect_aws_account(account, resource_id, org_id, session_token):
    response = disconnect_aws_account_json(strProdURL, account, resource_id, org_id, session_token)
    json_response = response.json()
    if not response.ok :
        print("    Error: " + json_response['message'])
        print("    Message: " + json_response['details'][0]['validation_error_message'])
        task_id = 0
    else:
        task_id = json_response ['id']
    return task_id


# ============================
# VTC - DXGW Operations
# ============================


def attach_dxgw(routes, resource_id, org_id, dxgw_owner, dxgw_id, region, session_token):
    json_response = attach_dxgw_json(strProdURL, routes, resource_id, org_id, dxgw_owner, dxgw_id, region, session_token)
    task_id = json_response ['id']
    return task_id

def detach_dxgw(resource_id, org_id, dxgw_id, session_token):
    json_response = detach_dxgw_json(strProdURL, resource_id, org_id, dxgw_id, session_token)
    task_id = json_response ['id']
    return task_id


# ============================
# VTC - SDDC Operations
# ============================


def attach_sddc(deployment_id, resource_id, org_id, session_token):
    response = attach_sddc_json(strProdURL, deployment_id, resource_id, org_id, session_token)
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['config']['operation_id']
    return task_id


def remove_sddc(deployment_id, resource_id, org_id, session_token):
    response = remove_sddc_json(strProdURL,deployment_id, resource_id, org_id, session_token)
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['config']['operation_id']
    return task_id


def get_nsx_info( org_id, deployment_id, session_token):
    json_response = get_nsx_info_json(strProdURL, org_id, deployment_id, session_token)
    print("    NSX private IP:   " + json_response['nsx_private_ip'])
    for i in range (len(json_response['nsx_users'])):
        # Catch 'None' usernames and passwords in SDDCs prior to M15, convert to string so it displays properly
        username = json_response['nsx_users'][i]['user_name']
        if username is None:
            username = "None"
        password = json_response['nsx_users'][i]['password']
        if password is None:
            password = "None"
        print("    NSX User : " + username + " - Password: " + password)
    print("    NSX public FQDN:  " + json_response['nsx_public_fqdn'])
    print("    NSX private FQDN: " + json_response['nsx_private_fqdn'])
    print("    LOGIN URLs:")
    print("       Public CSP:    " + json_response['login_urls'][0]['preferred_url'])
    print("       Private CSP:   " + json_response['login_urls'][1]['preferred_url'])
    for i in range (len(json_response['login_urls'][1]['other_urls'])):
        print("                      " + json_response['login_urls'][1]['other_urls'] [i])
    print("       Private local: " + json_response['login_urls'][2]['preferred_url'])
    return


def get_deployments(org_id, session_token):
    json_response = get_deployments_json(strProdURL,org_id, session_token)
    if (json_response['empty'] == True):
        print("\n=====No SDDC found=========")
    else:
        for i in range(json_response['total_elements']):
            print(str(i+1) + ": " + json_response['content'][i]['name'])
    return


def get_deployment_id(sddc, org_id, session_token):
    json_response = get_deployment_id_json(strProdURL, org_id, session_token)
    deployment_id = json_response['content'][int(sddc)-1]['id']
    return deployment_id


def get_resource_id(group_id, org_id, session_token):
    json_response = get_resource_id_json(strProdURL, org_id, group_id, session_token)
    resource_id = json_response[0]['id']
    return resource_id


# ============================
# VTC - SDDC Group Operations
# ============================


def create_sddc_group(name, deployment_id, org_id, session_token):
    json_response = create_sddc_group_json(strProdURL, name, deployment_id, org_id, session_token)
    task_id = json_response ['operation_id']
    return task_id


def delete_sddc_group(resource_id, org_id, session_token):
    response = delete_sddc_group_json(strProdURL, resource_id, org_id, session_token)
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['id']
    return task_id


def get_group_id(group, org_id, session_token):
    if DEBUG_MODE:
        print(f'DEBUG: In get_group_id(), group={group}')
    json_response = get_group_id_json(strProdURL, group, org_id, session_token)
    group_id = json_response['content'][int(group)-1]['id']
    if DEBUG_MODE:
        print(f'DEBUG: json_response group_id={group_id}')
    return group_id


def get_sddc_groups(org_id, session_token):
    json_response = get_sddc_groups_json(strProdURL, org_id, session_token)
    if (json_response['empty'] == True):
        print("     No SDDC Group found\n")
        return None
    else:
        sddc_groups = []
        for i in range(json_response['total_elements']):
            sddc_groups.append(json_response['content'])
            print(str(i+1) + ": " + json_response['content'][i]['name'] + ": " + json_response['content'][i]['id'])
    return sddc_groups[0]


def get_group_info(group_id, resource_id, org_id, session_token):
    json_response = get_group_info_json(strProdURL, org_id, group_id, session_token)
    print("\nORG ID      : " + json_response['org_id'])
    print("SDDC Group")
    print("==========")
    print("    Name      : " + json_response['name'])
    print("    Group ID  : " + json_response['id'])
    print("    Creator   : " + json_response['creator']['user_name'])
    print("    Date/Time : " + json_response['creator']['timestamp'])

    ext_json_response = ext_get_group_info_json(strProdURL, org_id, resource_id)
    print("SDDCs")
    print("=====")
    if 'AwsRealizedSddcConnectivityTrait' in ext_json_response['traits'] :
        if ext_json_response['traits']['AwsRealizedSddcConnectivityTrait']['sddcs'] != []:
            for i in range(len(ext_json_response['traits']['AwsRealizedSddcConnectivityTrait']['sddcs'])):
                print("    SDDC_ID " + str(i+1) + ": " + ext_json_response['traits']['AwsRealizedSddcConnectivityTrait']['sddcs'][i]['sddc_id'])  #loop here
        else:
            print("    No SDDC attached")

    print("Transit Gateway")
    print("===============")
    if 'AwsNetworkConnectivityTrait' in ext_json_response['traits'] :
        if ext_json_response['traits']['AwsNetworkConnectivityTrait']['l3connectors'] != []:
            print("    TGW_ID    : " + ext_json_response['traits']['AwsNetworkConnectivityTrait']['l3connectors'][0]['id'])
            print("    Region    : " + ext_json_response['traits']['AwsNetworkConnectivityTrait']['l3connectors'][0]['location']['name'])
        else:
            print("    No TGW")

    print("AWS info")
    print("========")
    if 'AwsVpcAttachmentsTrait' in ext_json_response['traits'] :
        if not ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts']:
            print("    No AWS account attached")
        else:
            print("    AWS Account  : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['account_number'])
            print("    RAM Share ID : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['resource_share_name'])
            print("    Status       : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['state'])
            if ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['state'] == "ASSOCIATING":
                print("        Go to AWS console/RAM and accept the share and wait for Status ASSOCIATED (5-10 mins)")
            else:
                print("VPC info")
                print("========")
                if not ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments']:
                    print("    No VPC attached")
                else:
                    for i in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'])):
                        print("    VPC " + str(i+1) + "        :" + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["vpc_id"])
                        print("        State         : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["state"])
                        print("        Attachment    : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["attach_id"])
                        if ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["configured_prefixes"]:
                            print("        Static Routes : " + (', '.join(ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["configured_prefixes"])))
    else:
        print("    No AWS account attached")

    print("DX Gateway")
    print("==========")
    if 'AwsDirectConnectGatewayAssociationsTrait' in ext_json_response['traits'] :
        if not ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations']:
            print("    No DXGW Association")
        else:
            print("    DXGW ID   : " +  ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['direct_connect_gateway_id'])
            print("    DXGW Owner: " +  ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['direct_connect_gateway_owner'])
            print("    Status    : " +  ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['state'])
            print("    Prefixes  : " +  (', '.join(ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['peering_regions'][0]['allowed_prefixes'])))

    else:
        print("    No DXGW Association")
    return


def check_empty_group(group_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/inventory/{}/core/deployment-groups/{}".format(strProdURL, org_id, group_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # print(len(json_response['membership']['included']))
    if (len(json_response['membership']['included']) != 0):
        return False
    return True


# ============================
# VTC - TGW Operations
# ============================


def get_route_tables(resource_id, org_id, session_token):
    json_response = get_route_tables_json(strProdURL, resource_id, org_id, session_token)
    if  not json_response['content']:       #'content' is empty []
        print("    Routing Tables empty")
    else:
        members_id = json_response['content'][0]['id']
        external_id = json_response['content'][1]['id']
        print("     Members route domain: Routes to all SDDCs, VPCs and Direct Connect Gateways")
        mem_json_response = vtgw_route_json(strProdURL, org_id, resource_id, members_id, session_token)
        for i in range(len(mem_json_response['content'])):
            print("\tDestination: " + mem_json_response['content'][i]['destination'] + "\t\tTarget: " + mem_json_response['content'][i]['target']['id'])
        ext_json_response = vtgw_route_json(strProdURL, org_id, resource_id, external_id, session_token)
        print("     External (VPC and Direct Connect Gateway) route domain: Routes only to member SDDCs")
        for i in range(len(ext_json_response['content'])):
            print("\tDestination: " + ext_json_response['content'][i]['destination'] + "\t\tTarget: " + ext_json_response['content'][i]['target']['id'])
    return


def get_task_status(task_id, org_id, session_token):
    json_response = get_task_status_json(strProdURL,task_id, org_id, session_token)
    status = json_response ['state']['name']
    print(status)
    start = time.time()
    new_session_token = ""
    while(status != "COMPLETED"):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(2)
        elapse = time.time() - start
        if elapse >= 1700 : # session_token is only valid for 1800 sec. Over 1700, will need a new token.
            if not new_session_token :
                sys.stdout.write("Generating a new session_token")
                new_session_token = getAccessToken(Refresh_Token)
                session_token = new_session_token
        json_response = get_task_status_json(strProdURL,task_id, org_id, session_token)
        status = json_response ['state']['name']
        if status == "FAILED":
            print("\nTask FAILED ")
            print("error message: " + json_response['state']['error_msg'])
            print("error code: " + json_response['state']['error_code'])
            print("message key: " + json_response['state']['name_message']['message_key'])
            break
    elapse = time.time() - start
    minutes = elapse // 60
    seconds = elapse - (minutes * 60)
    print("\nFINISHED in", '{:02}min {:02}sec'.format(int(minutes), int(seconds)))
    return

# ============================
# VTC - VPC Operations
# ============================

def attach_vpc(att_id, resource_id, org_id, account, session_token):
    json_body = {
        "type": "APPLY_ATTACHMENT_ACTION",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
                "type": "AwsApplyAttachmentActionConfig",
                "account" : {
                    "account_number": account,
                    "attachments": [
                        {
                            "action": "ACCEPT",
                            "attach_id": att_id
                        }
                    ]
                }
            }
        }
    task_id = attach_vpc_json(strProdURL, session_token, json_body, org_id)
    return task_id

def detach_vpc(att_id, resource_id, org_id, account, session_token):
    json_body = {
        "type": "APPLY_ATTACHMENT_ACTION",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
                "type": "AwsApplyAttachmentActionConfig",
                "account" : {
                    "account_number": account,
                    "attachments": [
                        {
                            "action": "DELETE",
                            "attach_id": att_id
                        }
                    ]
                }
            }
        }
    task_id = attach_vpc_json(strProdURL, session_token, json_body, org_id)
    return task_id

def get_pending_att(resource_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/{}?trait=AwsVpcAttachmentsTrait".format(strProdURL, org_id, resource_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    vpcs=[]
    n=1
    if 'AwsVpcAttachmentsTrait' in json_response['traits'] :
        for i in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'])):
            print("Account: " + json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['account_number'])
            if json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'] == None:        #'attachements' doesnt exists
                print("   No VPCs Pending Acceptance")
            else:
                for j in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'])):
                    if json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['state'] == "PENDING_ACCEPTANCE":
                        print(str(n) +": " + "VPC attachment = " + str(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id']))
                        vpcs.append(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id'])
                        n=n+1
    else:
        print("No AWS account attached")
    return vpcs


def get_available_att(resource_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/{}?trait=AwsVpcAttachmentsTrait".format(strProdURL, org_id, resource_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    vpcs=[]
    n=1
    for i in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'])):
        print("Account: " + json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['account_number'])
        for j in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'])):
            if json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['state'] == "AVAILABLE":
                print(str(n) +": " + "VPC attachment = " + str(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id']))
                vpcs.append(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id'])
                n=n+1
    return vpcs


def add_vpc_prefixes(routes, att_id, resource_id, org_id, account, session_token):
    json_body = {
        "type": "APPLY_ATTACHMENT_ACTION",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
            "type": "AwsApplyAttachmentActionConfig",
            "account" : {
                "account_number": account,
                "attachments": [
                        {
                        "action": "UPDATE",
                        "attach_id": att_id,
                        "configured_prefixes": routes
                        }
                    ]
                }
            }
        }
    task_id = add_vpc_prefixes_json(strProdURL, session_token, json_body, org_id)
    return task_id


# ============================
# NSX-T - all
# ============================


def search_nsx(proxy_url, session_token, object_type, object_id):
    """Prints out all Compute Gateways segements in the SDDC"""
    json_response = search_nsx_json(proxy_url, session_token, object_type, object_id)
    # Print total result count - used for debugging purposes.  Comment out when unused.
    # print(f'Total results: {json_response["result_count"]}')
    results = json_response['results']
    # Print total total JSON payload - used for debugging purposes.  Comment out when unused.
    # print(json.dumps(results, indent = 2))
    print("")
    if object_type == "BgpNeighborConfig":
        if len(results) !=0:
            table = generate_table(results)
            print(table.get_string(fields=["resource_type", "display_name",  "id", "neighbor_address", "remote_as_num"]))
        else:
            print("None found.")
    elif object_type == "BgpRoutingConfig":
        for item in results:
            if not 'route_aggregations' in item:
                item['route_aggregations'] = "--"
        if len(results) !=0:
            table = generate_table(results)
            print(table.get_string(fields=["resource_type", "display_name", "id", "enabled", "ecmp",  "route_aggregations"]))
        else:
            print("None found.")
    elif object_type == "Group":
        for item in results:
            if not 'description' in item:
                item['description'] = "--"
            if len(item['expression']) > 0:
                if 'ip_addresses' in item['expression'][0]:
                    item['ip_addresses'] = item['expression'][0]['ip_addresses']
                else:
                    item['ip_addresses'] = "--"
        if len(results) !=0:
            table = generate_table(results)
            table._max_width = {"display_name" : 35, "description" : 50, "ip_addresses" : 20}
            print(table.get_string(fields=["display_name", "description", "ip_addresses"]))
        else:
            print("None found.")
    elif object_type == "IdsSignature":
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["display_name", "cves", "attack_target", "cvss"]))
    elif object_type == "PrefixList":
        for item in results:
            if not item.get("prefixes"):
                item.clear()
        results = list(filter(None, results))
        if len(results) !=0:
            table = generate_table(results)
            table._max_width = {"prefixes" : 50}
            print(table.get_string(fields=["resource_type", "id", "description", "prefixes"]))
        else:
            print("None found.")
    elif object_type == "RouteBasedIPSecVpnSession":
        for item in results:
            item['bgp ip_addresses'] = item['tunnel_interfaces'][0]['ip_subnets'][0]['ip_addresses']
            item['bgp prefix length'] = item['tunnel_interfaces'][0]['ip_subnets'][0]['prefix_length']
        if len(results) !=0:
            table = generate_table(results)
            print(table.get_string(fields=[ "display_name", "resource_type", "peer_id",  "peer_address", "bgp ip_addresses", "bgp prefix length"]))
    elif object_type == "Segment":
        for item in results:
            if 'subnets' in item:
                if 'network' in item['subnets'][0]:
                    item['network'] = item['subnets'][0]['network']
                else:
                    item['network'] = "--"
                if 'gateway_address' in item ['subnets'][0]:
                    item['gateway_address'] = item['subnets'][0]['gateway_address']
                else:
                    item['gateway_address'] = "--"
                if 'dhcp_ranges' in item['subnets'][0]:
                    item['dhcp_ranges'] = item['subnets'][0]['dhcp_ranges']
                else:
                    item['dhcp_ranges'] = "--"
            else:
                item['network'] = "--"
                item['gateway_address'] = "--"
                item['dhcp_ranges'] = "--"
            if 'connectivity_path' not in item:
                item['connectivity_path'] ="--"
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id", "type", "network", "gateway_address", "dhcp_ranges", "connectivity_path"]))
    elif object_type == "Service":
        for item in results:
            if 'source_ports' in item['service_entries'][0]:
                item['source_ports'] = item['service_entries'][0]['source_ports']
            else:
                item['source_ports'] = "--"
            if 'destination_ports' in item['service_entries'][0]:
                item['destination_ports'] = item['service_entries'][0]['destination_ports']
            else:
                item['destination_ports'] = "--"
        if len(results) !=0:
            table = generate_table(results)
        table._max_width = {"resource_type" : 15, "display_name" : 40, "id" : 40 , "source_ports": 20, "destination_ports" : 20}
        print(table.get_string(fields=["resource_type", "display_name", "id", "source_ports", "destination_ports"]))
    elif object_type == "StaticRoutes":
        for item in results:
            item['next_hops'] = item['next_hops'][0]['ip_address']
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id", "network", "next_hops"]))
    elif object_type == "Tier0":
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id"]))
    elif object_type == "Tier1":
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id", "type", "tier0_path", "path"]))
    elif object_type == "VirtualMachine":
        for item in results:
            item['computer_name'] = item['guest_info']['computer_name']
            item['os_name'] = item['guest_info']['os_name']
            item['target_display_name'] = item['source']['target_display_name']
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "computer_name", "os_name", "target_display_name", "display_name"]))
    elif object_type == "VirtualNetworkInterface":
        for item in results:
            if len(item['ip_address_info']) > 0:
                if 'ip_addresses' in item['ip_address_info'][0]:
                    item['ip_addresses'] = item['ip_address_info'][0]['ip_addresses']
            else:
                item['ip_addresses'] = "--"
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "owner_vm_type", "owner_vm_id", "mac_address", "ip_addresses"]))


# ============================
# NSX-T - Advanced Firewall
# ============================


def getNSXAFAddOn(org_id, sddc_id, session_token):
    json_response = get_sddc_info_json(strProdURL, org_id, sddc_id, session_token)
    sddcName = json_response['name']
    nsxAFTable = PrettyTable(['SDDC Name', 'NSX Advanced Firewall Enabled?'])
    nsxAFStatus1 = json_response['resource_config']['nsxt_addons']
    if nsxAFStatus1 is None:
        nsxAFTable.add_row([sddcName, "False"])
    else:
        nsxAFStatus = json_response['resource_config']['nsxt_addons']['enable_nsx_advanced_addon']
        nsxAFTable.add_row([sddcName, nsxAFStatus])
    # pretty_data = json.dumps(json_response, indent=4)
    # print(pretty_data)
    print(nsxAFTable)


def getNsxIdsEnabledClusters(proxy, session_token):
    json_response = get_nsx_ids_cluster_enabled_json(proxy, session_token)
    clustersTable = PrettyTable(['Cluster ID', 'Distributed IDS Enabled'])
    clusterArray = json_response['results']
    for i in clusterArray:
        clusterStatus = i['ids_enabled']
        clusterID = i['cluster']['target_id']
        clustersTable.add_row([clusterID, clusterStatus])
    print(clustersTable)


def enableNsxIdsCluster(proxy, session_token, targetID):
    json_data = {
        "ids_enabled": True,
        "cluster": {
            "target_id": targetID
        }
    }
    response = enable_nsx_ids_cluster_json(proxy, session_token, targetID, json_data)
    if response.statuscode == 200:
        print(f"IDS enabled on cluster {targetID}")


def disableNsxIdsCluster(proxy, session_token, targetID):
    json_data = {
        "ids_enabled": False,
        "cluster": {
            "target_id": targetID
        }
    }
    response = disable_nsx_ids_cluster_json(proxy, session_token, targetID, json_data)
    if response.statuscode == 200:
        print("IDS disabled on cluster {}".format(targetID))


def enableNsxIdsAll(proxy, session_token):
    cluster_json = get_nsx_ids_cluster_enabled_json(proxy, session_token)
    clusterTable = PrettyTable(["Cluster ID", "Distributed IDS Enabled"])
    clusterResults = cluster_json['results']
    for i in clusterResults:
        targetID = i['cluster']['target_id']
        if i['ids_enabled'] == False:
            json_body = {
                "ids_enabled": True,
                "cluster": {
                    "target_id": targetID
                }
            }
            response = enable_nsx_ids_cluster_json(proxy, session_token, targetID, json_body)
            if response.status_code == 200:
                clusterTable.add_row([targetID, "True"])
        else:
            clusterTable.add_row([targetID, "True"])
    print(clusterTable)


def disableNsxIdsAll(proxy, session_token):
    cluster_json = get_nsx_ids_cluster_enabled_json(proxy, session_token)
    clusterTable = PrettyTable(["Cluster ID", "Distributed IDS Enabled"])
    clusterResults = cluster_json['results']
    for i in clusterResults:
        targetID = i['cluster']['target_id']
        if i['ids_enabled'] == True:
            json_body = {
                "ids_enabled": False,
                "cluster": {
                    "target_id": targetID
                }
            }
            response, myURL = disable_nsx_ids_cluster_json(proxy, session_token, targetID, json_body)
            if response.status_code == 200:
                clusterTable.add_row([targetID, "False"])
        else:
            clusterTable.add_row([targetID, "False"])
    print(clusterTable)


def enableNsxIdsAutoUpdate(proxy, session_token):
    json_data = {
        "auto_update": True
    }
    response = enable_nsx_ids_auto_update_json(proxy, session_token, json_data)
    if response.status_code == 202:
        print("IDS Signature auto-update enabled")


def NsxIdsUpdateSignatures(proxy, session_token):
    response, myURL = nsx_ids_update_signatures_json(proxy, session_token)
    if response.status_code == 202:
        print("Signature update started")


def getNsxIdsSigVersions(proxy, session_token):
    response = get_ids_signature_versions_json(proxy, session_token)
    sigTable = PrettyTable(['Signature Version', 'State', 'Status', 'Update Time (UTC)'])
    sigResponse = response['results']
    for i in sigResponse:
        sigVer = i['version_id']
        sigState = i['state']
        sigStatus = i['status']
        sigTimeUnix = i['update_time']
        sigTimeUnix /= 1000
        sigTime = datetime.utcfromtimestamp(sigTimeUnix).strftime('%Y-%m-%d %H:%M:%S')
        sigTable.add_row([sigVer, sigState, sigStatus, sigTime])
    sigTable.sortby = "State"
    print(sigTable)


def getIdsProfiles(proxy, session_token):
    response = get_ids_profiles_json(proxy, session_token)
    profileTable = PrettyTable(['Name', 'Severity', 'Filter Name', 'Filter Value'])
    profileResponse = response['results']
    for i in range(len(profileResponse)):
        profileName = profileResponse[i]['display_name']
        profileSev = profileResponse[i]['profile_severity']
        if 'criteria' in profileResponse[i]:
            profileCriteriaArray = profileResponse[i]['criteria']
            for x in range(len(profileCriteriaArray)):
                if 'resource_type' in profileCriteriaArray[x] and profileCriteriaArray[x][
                    'resource_type'] == "IdsProfileFilterCriteria":
                    filterName = profileCriteriaArray[x]['filter_name']
                    filterValue = profileCriteriaArray[x]['filter_value']
                    profileTable.add_row([profileName, profileSev, filterName, filterValue])
                else:
                    pass

        else:
            profileTable.add_row([profileName, profileSev, "", ""])
    print(profileTable)


def search_ids_signatures_product_affected(proxy_url, session_token):
    """Returns a table consisting of the IDS Signature Product Affected based on the search term for assistance
    in building the IDS Profile"""
    json_response = search_nsx_json(proxy_url, session_token, "IdsSignature", "NULL")
    idsSigs = json_response['results']
    print("Loading Signatures....")
    while 'cursor' in json_response:
        json_response = search_nsx_json_cursor(proxy, session_token, "IdsSignature", "NULL", json_response['cursor'])
        idsSigs2 = json_response['results']
        idsSigs.extend(idsSigs2)
    df = pd.DataFrame(idsSigs)
    sigs = df.drop(columns=['_last_modified_user', '_protection', '_last_modified_time', 'marked_for_delete',
                            '_revision', '_system_owned', '_create_user', '_create_time', 'overridden',
                            'path', 'urls', 'class_type', 'parent_path', 'categories', 'id', 'flow', 'resource_type',
                            'signature_revision', 'relative_path', 'display_name'])
    ids_table = PrettyTable(['Product Affected'])
    ids_prod_affected = sigs['product_affected']
    ids_prod_affected = ids_prod_affected.drop_duplicates()
    user_input = input("Please input your search term: ")
    ids_prod_affected = ids_prod_affected.tolist()
    for i in ids_prod_affected:
        if search(user_input, i, re.IGNORECASE):
            ids_table.add_row([i])
    print(ids_table)


def listIdsPolicies(proxy, session_token):
    json_response = get_ids_policies_json(proxy, session_token)
    policyTable = PrettyTable(['Policy Name', 'Stateful', 'Locked'])
    policyResponse = json_response['results']
    for i in range(len(policyResponse)):
        policyName = policyResponse[i]['display_name']
        policyState = policyResponse[i]['stateful']
        policyLocked = policyResponse[i]['locked']
        policyTable.add_row([policyName, policyState, policyLocked])
    print(policyTable)


def create_ids_profile(**kwargs):
    """Create an IDS Profile"""
    if kwargs['objectname'] is None:
        print("Please use -n to specify the name of the segment to be configured.  Consult the help for additional options.")
        sys.exit()
    display_name = kwargs['objectname']
    cvss = None
    pa = None
    if kwargs['cvss'] is not None:
        cvss = kwargs['cvss']
    if kwargs['product_affected'] is not None:
        pa = kwargs['product_affected']
    if pa is not None and cvss is not None:
        json_data = {
            "profile_severity": [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ],
            "criteria": [
                {
                    "filter_name": "CVSS",
                    "filter_value": cvss,
                    "resource_type": "IdsProfileFilterCriteria"
                },
                {
                    "operator": "AND",
                    "resource_type": "IdsProfileConjunctionOperator"
                },
                {
                    "filter_name": "PRODUCT_AFFECTED",
                    "filter_value": pa,
                    "resource_type": "IdsProfileFilterCriteria"
                }
            ],
            "resource_type": "IdsProfile",
            "display_name": display_name,
            "id": display_name
        }
    elif pa is not None:
        json_data = {
            "profile_severity": [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ],
            "criteria": [
                {
                    "filter_name": "PRODUCT_AFFECTED",
                    "filter_value": pa,
                    "resource_type": "IdsProfileFilterCriteria"
                }
            ],
            "resource_type": "IdsProfile",
            "display_name": display_name,
            "id": display_name
        }
    elif cvss is not None:
        json_data = {
            "profile_severity": [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW"
            ],
            "criteria": [
                {
                    "filter_name": "CVSS",
                    "filter_value": cvss,
                    "resource_type": "IdsProfileFilterCriteria"
                },
            ],
            "resource_type": "IdsProfile",
            "display_name": display_name,
            "id": display_name
        }
    response_code = patch_ips_profile_json(proxy, session_token, json_data, display_name)
    if response_code == 200:
        print(f'The IDS Profile {display_name} has been created successfully')
    else:
        sys.exit(f'There was an error, please check your syntax')


def create_ids_policy(**kwargs):
    if kwargs['objectname'] is None:
        print("Please use -n to specify the name of the segment to be configured.  Consult the help for additional options.")
        sys.exit()
    display_name = kwargs['objectname']
    json_data = {
        "resource_type": "IdsSecurityPolicy",
        "display_name": display_name,
        "id": display_name
    }
    response_code = put_ids_policy_json(proxy, session_token, json_data, display_name)
    if response_code == 200:
        print(f'The IDS policy {display_name} has been created successfully')
    else:
        sys.exit('There was an error, please check your syntax')


def get_ids_rules():
    ids_policies_json = get_ids_policies_json(proxy, session_token)
    ids_policies_json = ids_policies_json['results']
    for i in ids_policies_json:
        ids_policy_name = i['display_name']
        ids_table = PrettyTable()
        ids_table.title = f'IDS Rules for IDS Policy {ids_policy_name}'
        ids_table.field_names = ['Display Name', 'Source Group', 'Destination Group', 'IDS Profile', 'Services', 'Scope', 'Action', 'Logged']
        ids_rule_json = get_ids_rule_json(proxy, session_token, ids_policy_name)
        ids_rule_json = ids_rule_json['results']
        for r in ids_rule_json:
            ids_table.add_row([r['display_name'], r['source_groups'], r['destination_groups'], r['ids_profiles'], r['services'], r['scope'], r['action'], r['logged']])
        print(ids_table)


def create_ids_rule(**kwargs):
    if kwargs['objectname'] is None:
        print("Please use -n to specify the name of the IDS Rule to be configured.  Consult the help for additional options.")
        sys.exit()

#   Load variables from kwargs
    display_name = kwargs['objectname']
    act = kwargs['action']
    srcgrp = kwargs['source_group']
    destgrp = kwargs['dest_group']
    idspol = kwargs['ids_policy'][0]
    scp = kwargs['scope']
    srvc = kwargs['services']
    idspro = kwargs['ids_profile'][0]

#   Build variables and lists to use in JSON payload
    idsprolst = [f'/infra/settings/firewall/security/intrusion-services/profiles/{idspro}']
    idspolstr = f'/infra/domains/cgw/intrusion-service-policies/{idspol}'
    srcgrplst = []
    destgrplst = []
    srvclst = []
    scplst = []
    if srcgrp == 'ANY':
        srcgrplst = ['ANY']
    else:
        for i in srcgrp:
            srcgrpitem = f'/infra/domains/cgw/groups/{i}'
            srcgrplst.append(srcgrpitem)
    if destgrp == 'ANY':
        destgrplst = ['ANY']
    else:
        for i in destgrp:
            dstgrpitem = f'/infra/domains/cgw/groups/{i}'
            destgrplst.append(dstgrpitem)
    if srvc == 'ANY':
        srvclst = ['ANY']
    else:
        for i in srvc:
            srvcitem = f'/infra/services/{i}'
            srvclst.append(srvcitem)
    if scp == 'ANY':
        scplst = ['ANY']
    else:
        for i in scp:
            scpitem = f'/infra/domains/cgw/groups/{i}'
            scplst.append(scpitem)

#   Build the JSON payload
    json_data = {
        "action": act,
        "ids_profiles": idsprolst,
        "resource_type": "IdsRule",
        "id": display_name,
        "display_name": display_name,
        "parent_path": idspolstr,
        "source_groups": srcgrplst,
        "destination_groups": destgrplst,
        "services": srvclst,
        "scope": scplst,
        "direction": "IN_OUT",
        "ip_protocol": "IPV4_IPV6",
        "logged": False
    }

    json_response_code = put_ids_rule_json(proxy, session_token, display_name, idspol, json_data)
    if json_response_code == 200:
        print(f'IDS Rule {display_name} was successfully created under IDS Policy {idspol}')
    else:
        print(f'There was an error, please check your syntax')


# ============================
# NSX-T - BGP and Routing
# ============================


def attachT0BGPprefixlist(proxy, session_token, neighbor_id):
    """Attaches identified prefix list to T0 edge gateway - applicable for route-based VPN"""
    neighbor_json = get_sddc_t0_bgp_single_neighbor_json(proxy, session_token, neighbor_id)
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
            pretty_json = json.dumps(neighbor_json, indent=2)
            print(pretty_json)
            print()
        elif test == "2":
            prefix_list_id = input('Please enter the prefix list ID exactly ')
            neighbor_json['route_filtering'][0]["in_route_filters"] = ['/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id]
            print()
            print(f'Prefix list {prefix_list_id} has been added to in_route_filters in JSON for neighbor id {neighbor_id}. Please review and commit.')
            print()
        elif test =="3":
            prefix_list_id = input('Please enter the prefix list ID exactly ')
            neighbor_json['route_filtering'][0]["out_route_filters"] = ['/infra/tier-0s/vmc/prefix-lists/' + prefix_list_id]
            print()
            print(f'Prefix list {prefix_list_id} has been added to out_route_filters in JSON for neighbor id {neighbor_id}. Please review and commit.')
            print()
        elif test =="4":
            if neighbor_json.get("in_route_filters"):
                del neighbor_json["in_route_filters"]
            if neighbor_json.get("out_route_filters"):
                del neighbor_json["out_route_filters"]
            neighbor_json['route_filtering'] = [{'enabled': True, 'address_family': 'IPV4'}]
        elif test == "5":
            status_code = attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json)
            print(f'Status {status_code}. Complete - route filter entry:')
            print()
            pretty_json = json.dumps(neighbor_json["route_filtering"], indent=2)
            print(pretty_json)
            print()
        elif test == "6":
            break
        else:
            print("Please choose 1, 2, 3 or 4 - Try again or check the help.")


def detachT0BGPprefixlists(proxy, session_token, neighbor_id):
    """Detaches all prefix lists from specified T0 BGP neighbor - applicable for route-based VPN"""
    neighbor_json = get_sddc_t0_bgp_single_neighbor_json(proxy, session_token, neighbor_id)
    print(json.dumps(neighbor_json, indent=2))
    for key in list(neighbor_json.keys()):
        if key.startswith('_'):
            del neighbor_json[key]
    neighbor_json['route_filtering'] = [{'enabled': True, 'address_family': 'IPV4'}]
    status_code = attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json)
    print(f'Status {status_code}. Prefix lists detached from {neighbor_id}')


def newBGPprefixlist(csp_url, session_token):
    """Creates new prefix list for T0 edge gateway - applicable for route based VPN"""
#   capture details for new prefix list
    description= input('Enter a description name for the prefix list:  ').lower()
    display_name= input('Enter a display name for the prefix list:  ').lower()
    prefix_list_id= input('Enter an ID string for the prefix list:  ').lower()
#   create python dictionary to contain the prefix list
    prefix_list = {}
    prefix_list['description'] = description
    prefix_list["display_name"] = display_name
    prefix_list["id"] = prefix_list_id
    prefix_list["prefixes"] = []
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
            action= input('Enter the action (PERMIT or DENY):  ').upper()
            if action == "PERMIT" or action == "DENY":
                scope= input('Optional - Enter either le or ge:  ').lower()
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
            new_bgp_prefix_list_json(csp_url, session_token, prefix_list_id, prefix_list)
            print("prefix list added")
        elif test == "4":
            break
        else:
            print("Please choose 1, 2, 3 or 4 - Try again or check the help.")


def getSDDCBGPAS(proxy_url,sessiontoken):
    json_response = get_sddc_bgp_as_json(proxy_url,sessiontoken)
    sddc_bgp_as = json_response['local_as_num']
    print(f'The SDDC BGP Autonomous System is ASN {sddc_bgp_as}')


def setSDDCBGPAS(proxy_url,sessiontoken,asn):
    json_data = {
    "local_as_num": asn
    }
    set_sddc_bgp_as_json(proxy_url,sessiontoken,json_data)
    print("The BGP AS has been updated:")
    getSDDCBGPAS(proxy_url,session_token)
 
 
def getSDDCMTU(proxy_url,sessiontoken):
    json_response = get_sddc_mtu_json(proxy_url,sessiontoken)
    sddc_MTU = json_response['intranet_mtu']
    print(f'The MTU over the Direct Connect is {sddc_MTU} Bytes.')


def setSDDCMTU(proxy_url,sessiontoken,mtu):
    json_data = {
    "intranet_mtu" : mtu
    }
    set_sddc_mtu_json(proxy_url,sessiontoken,json_data)
    print("The MTU has been updated:")
    getSDDCMTU(proxy_url,sessiontoken)


def getSDDCEdgeCluster(proxy_url, sessiontoken):
    """ Gets the Edge Cluster ID """
    json_response = get_sddc_edge_cluster_json(proxy_url, sessiontoken)
    edge_cluster_id = json_response['results'][0]['id']
    return edge_cluster_id


def getSDDCEdgeNodes(proxy_url, sessiontoken, edge_cluster_id,edge_id):
    """ Gets the Edge Nodes Path """
    json_response= get_sddc_edge_nodes_json(proxy_url, sessiontoken, edge_cluster_id)
    edge_path = json_response['results'][edge_id]['path']
    return edge_path


def getSDDCInternetStats(proxy_url, sessiontoken, edge_path):
    """Displays counters for egress interface"""
    json_response = get_sddc_internet_stats_json(proxy_url, sessiontoken, edge_path)
    total_bytes = json_response['per_node_statistics'][0]['tx']['total_bytes']
    return total_bytes


def getSDDCBGPVPN(proxy_url, sessiontoken):
    """Retreives preferred path - VPN or DX."""
    json_response = get_sddc_bgp_vpn_json(proxy_url, sessiontoken)
    sddc_bgp_vpn = json_response['route_preference']
    if sddc_bgp_vpn == "VPN_PREFERRED_OVER_DIRECT_CONNECT":
        return "The preferred path is over VPN, with Direct Connect as a back-up."
    else:
        return "The preferred path is over Direct Connect, with VPN as a back-up."


def getSDDCT0BGPneighbors(csp_url, session_token):
    """Prints BGP neighbors for T0 edge gateway"""
    bgp_neighbors = get_sddc_t0_bgp_neighbors_json(proxy, session_token)
    neighbors = bgp_neighbors['results']
    bgp_table = PrettyTable(['ID','Remote AS Num','Remote Address','In_route_filter','Out_route_filter'])
    for neighbor in neighbors:
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
            print(json.dumps(neighbors,indent=2))


def getSDDCT0BGPRoutes(proxy, session_token):
    """Prints BGP routes for T0 edge gateway"""
    bgp_neighbors = get_sddc_t0_bgp_neighbors_json(proxy, session_token)
    learnedRoutesTable = PrettyTable(['BGP Neighbor', 'Source Address', 'AS Path', 'Network', 'Next Hop'])
    advertisedRoutesTable = PrettyTable(['BGP Neighbor', 'Source Address', 'Network', 'Next Hop'])
    neighbors = bgp_neighbors['results']
    for i in range(len(neighbors)):
        bgp_neighbor_id = neighbors[i]['id']
        route_learned_json = get_sddc_t0_learned_routes_json(proxy, session_token, bgp_neighbor_id)
        route_advertised_json = get_sddc_t0_advertised_routes_json(proxy, session_token, bgp_neighbor_id)
#       Building the learned routes table
        edgeLearnedRoutes = route_learned_json['results'][0]['egde_node_routes']
        sourceAddrLearned = edgeLearnedRoutes[0]['source_address']
        bgpLearnedRoutes = edgeLearnedRoutes[1]['routes']
        for x in range(len(bgpLearnedRoutes)):
            learnedRoutesTable.add_row([bgp_neighbor_id,sourceAddrLearned,bgpLearnedRoutes[x]['as_path'],bgpLearnedRoutes[x]['network'],bgpLearnedRoutes[x]['next_hop']])
#       Building the advertised routes table
        edgeAdvertisedRoutes = route_advertised_json['results'][0]['egde_node_routes']
        sourceAddrAdvertised = edgeAdvertisedRoutes[0]['source_address']
        bgpAdvertisedRoutes = edgeAdvertisedRoutes[1]['routes']
        for y in range(len(bgpAdvertisedRoutes)):
            advertisedRoutesTable.add_row([bgp_neighbor_id,sourceAddrAdvertised,bgpAdvertisedRoutes[y]['network'],bgpAdvertisedRoutes[y]['next_hop']])
    print ('BGP Advertised Routes')
    print (advertisedRoutesTable.get_string(sortby="BGP Neighbor"))
    print ('BGP Learned Routes')
    print (learnedRoutesTable.get_string(sortby="BGP Neighbor"))


def getSDDCT0PrefixLists(proxy, session_token):
    """Prints prefix lists for T0 edge gateway - applicable for route-based VPN"""
    prefix_lists = get_sddc_t0_prefixlists_json(proxy, session_token)
    prefix_results = prefix_lists['results']
#   clear results for any prefix lists found that contain "System created prefix list"
    str_check = 'System created prefix list'
    for item in range(len(prefix_results)):
        if "description" in prefix_results[item]:
            if str_check in prefix_results[item]['description']:
                prefix_results[item].clear()
#   remove empty dictionaries
    prefix_results = list(filter(None, prefix_results))
#   print a nicely formatted list of only user-uploaded prefix lists; system created lists were eliminated in above code
    if len(prefix_results) != 0:
        for prefixlist in prefix_results:
            if "description" in prefixlist:
                prefixlisttable = PrettyTable(['ID','Display Name','Description'])
                prefixlisttable.add_row([prefixlist["id"],prefixlist["display_name"],prefixlist["description"]])
            else:
                prefixlisttable = PrettyTable(['ID','Display Name'])
                prefixlisttable.add_row([prefixlist["id"],prefixlist["display_name"]])
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
                print(json.dumps(prefix_lists,indent=2))
    else:
        print("No user created prefixes found.")


def getSDDCT0routes(proxy_url, session_token):
    """Prints all routes for T0 edge gateway"""
    t0_routes_json = get_sddc_t0_routes_json(proxy_url, session_token)
    t0_routes = t0_routes_json['results'][1]['route_entries']
    route_table = PrettyTable(['Route Type', 'Network', 'Admin Distance', 'Next Hop'])
    for routes in t0_routes:
        route_table.add_row([routes['route_type'],routes['network'],routes['admin_distance'],routes['next_hop']])
    print ('T0 Routes')
    print ('Route Type Legend:')
    print ('t0c - Tier-0 Connected\nt0s - Tier-0 Static\nb   - BGP\nt0n - Tier-0 NAT\nt1s - Tier-1 Static\nt1c - Tier-1 Connected\nisr: Inter-SR')
    print (route_table.get_string(sort_key = operator.itemgetter(1,0), sortby = "Network", reversesort=True))


def getSDDCT0staticroutes(proxy_url,session_token):
    """Prints static routes configured on T0 edge gateway"""
    t0_static_routes_json = get_sddc_t0_static_routes_json(proxy_url, session_token)
    t0_static_routes = t0_static_routes_json['results']
    route_table = PrettyTable(['Display Name', 'Network', 'Admin Distance', 'Next Hop'])
    for routes in t0_static_routes:
        route_table.add_row([routes['display_name'],routes['network'],routes['next_hops'][0]['admin_distance'],routes['next_hops'][0]['ip_address']])
    print (route_table.get_string(sort_key = operator.itemgetter(1,0), sortby = "Network", reversesort=True))


# ============================
# NSX-T - DNS
# ============================


def getSDDCDNS_Services(proxy_url,sessiontoken,gw):
    """Retreives the DNS zone services."""
    sddc_dns_service = get_sddc_dns_services_json(proxy_url,sessiontoken,gw)
    table = PrettyTable(['ID', 'Name', 'Listener IP'])
    table.add_row([sddc_dns_service['id'], sddc_dns_service['display_name'], sddc_dns_service['listener_ip']])
    return table


def getSDDCDNS_Zones(proxy_url,sessiontoken):
    """ Gets the SDDC Zones """
    json_response = get_sddc_dns_zones_json(proxy_url,sessiontoken)
    sddc_dns = json_response['results']
    table = PrettyTable(['ID', 'Name','DNS Domain Names','upstream_servers'])
    for i in sddc_dns:
        table.add_row([i['id'], i['display_name'], i['dns_domain_names'], i['upstream_servers']])
    return table


# ============================
# NSX-T - Firewall - Gateway
# ============================


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
    if json_response_status_code != 200:
        print(response.text)
    return json_response_status_code


def removeSDDCCGWRule(proxy_url, sessiontoken, rule_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/cgw/gateway-policies/default/rules/" + rule_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code


def removeSDDCMGWRule(proxy_url, sessiontoken, rule_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = (proxy_url + "/policy/api/v1/infra/domains/mgw/gateway-policies/default/rules/" + rule_id)
    response = requests.delete(myURL, headers=myHeader)
    json_response_status_code = response.status_code
    return json_response_status_code


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


# ============================
# NSX-T - Firewall - Distributed
# ============================


def newSDDCDFWRule(proxy_url, sessiontoken, display_name, source_groups, destination_groups, services, action, section, sequence_number):
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
    json_response_status_code = put_sddc_dfw_rule_json(proxy_url, sessiontoken, section, display_name, json_data)
    return json_response_status_code


def newSDDCDFWSection(proxy_url, sessiontoken, display_name, category):
    json_data = {
    "resource_type":"SecurityPolicy",
    "display_name": display_name,
    "id": display_name,
    "category": category,
    }
    json_response_status_code = put_sddc_dfw_section_json(proxy_url, sessiontoken, display_name, json_data)
    return json_response_status_code


def getSDDCDFWRule(proxy_url, sessiontoken, section):
    json_response = get_sddc_dfw_rule_json(proxy_url, sessiontoken, section)
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


def getSDDCDFWSection(proxy_url, sessiontoken):
    json_response = get_sddc_dfw_section_json(proxy_url, sessiontoken)
    sddc_DFWsection = json_response['results']
    table = PrettyTable(['id', 'Name', 'Category', 'Sequence Number'])
    for i in sddc_DFWsection:
        table.add_row([i['id'], i['display_name'], i['category'], i['sequence_number']])
    return table


# ============================
# NSX-T - Firewall Services
# ============================


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


# ============================
# NSX-T - Inventory Groups
# ============================


def newSDDCGroupIPaddress(proxy_url,sessiontoken,gw,group_id,ip_addresses):
    """ Creates a single SDDC Group based on IP addresses. Use 'mgw' or 'cgw' as the parameter """
    json_data = {
    "expression" : [ {
      "ip_addresses" : ip_addresses,
      "resource_type" : "IPAddressExpression"
    } ],
    "id" : group_id,
    "display_name" : group_id,
    "resource_type" : "Group"}
    json_response_status_code = put_sddc_inventory_group_json_response(proxy_url, sessiontoken, json_data, gw, group_id)
    return json_response_status_code


def newSDDCGroupCriteria(proxy_url, sessiontoken, gw, group_id, member_type, key, operator, value):
    """ Creates a single SDDC Group based on a criteria. Use 'cgw' as the parameter """
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
    json_response_status_code = put_sddc_inventory_group_json_response(proxy_url, sessiontoken, json_data, gw, group_id)
    return json_response_status_code


def newSDDCGroupGr(proxy_url, sessiontoken, gw, group_id, member_of_group):
    """ Creates a single SDDC group and adds 'member_of_group' to the group membership"""

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

    json_response_status_code = put_sddc_inventory_group_json_response(proxy_url, sessiontoken, json_data, gw, group_id)
    #print(response.text)
    return json_response_status_code


def newSDDCGroupVM(proxy_url,sessiontoken,gw,group_id,vm_list):
    """ Creates a single SDDC Group based on a list of VM external_id. Use 'cgw' as the parameter """
    json_data = {
    "expression" : [ {
        "member_type" : "VirtualMachine",
        "external_ids" : vm_list,
        "resource_type" : "ExternalIDExpression"
    } ],
    "id" : group_id,
    "display_name" : group_id,
    }
    json_response_status_code = put_sddc_inventory_group_json_response(proxy_url, sessiontoken, json_data, gw, group_id)
    return json_response_status_code


def removeSDDCGroup(proxy_url, sessiontoken, gw, group_id):
    """ Remove an SDDC Group """
    json_response_status_code = delete_sddc_inventory_group_json_response(proxy_url, sessiontoken, gw, group_id)
    if json_response_status_code == 200:
        print("The group " + group_id + " has been deleted")
    else:
        return


def getVMExternalID(proxy_url,sessiontoken,vm_name):
    response_dictionary = get_vms_json(proxy_url, sessiontoken)
    extracted_dictionary = response_dictionary['results']
#   Below, we're extracting the Python dictionary for the specific VM and then we extract the external_ID/ Instance UUID from the dictionary.
    extracted_VM = next(item for item in extracted_dictionary if item["display_name"] == vm_name)
    extracted_VM_external_id = extracted_VM['external_id']
    return extracted_VM_external_id


def getSDDCGroups(proxy_url, session_token, gw):
    """ Gets the SDDC Groups. Use 'mgw' or 'cgw' as the parameter """
    json_response = get_sddc_inventory_groups_json(proxy_url, session_token, gw)
    sddc_group = json_response['results']
    table = PrettyTable(['ID', 'Name'])
    for i in sddc_group:
        table.add_row([i['id'], i['display_name']])
    return table


def getSDDCGroup(proxy_url, session_token, gw, group_id):
    """ Gets a single SDDC Group. Use 'mgw' or 'cgw' as the parameter.  Displays effective membership and criteria for group"""
    json_response = get_sddc_inventory_group_id_json(proxy_url, session_token, gw, group_id)

#   Define tables
    table = PrettyTable(['Member Type', 'Key', 'Operator', 'Value', 'Conjunction Operator'])
    vm_table = PrettyTable(['VM Name'])
    segment_table = PrettyTable(['Segment Name', 'Path'])
    segment_port_table = PrettyTable(['Segment Port Name'])
    ip_address_table = PrettyTable(['IP Address'])
    vif_table = PrettyTable(['VIFs'])
    group_table = PrettyTable(['Group Path'])
    mac_table = PrettyTable(['MAC Addresses'])
    ad_group_table = PrettyTable(['AD Groups'])

    # pretty_data = json.dumps(json_response, indent=4)
    # print(pretty_data)

    # Checking for groups with defined criteria with the following command.
    if json_response['expression'] == []:
        print("This group has no criteria defined.")
    elif 'expression' in json_response:
        group_criteria = json_response['expression']
        for g in group_criteria:
            if g["resource_type"] == "Condition":
                group = json_response['expression']
                print("The group " + group_id + " has these criteria defined:")
                for i in group:
                    if 'member_type' in i.keys():
                        table.add_row([i['member_type'], i['key'], i['operator'], i['value'], "-"])
                    elif 'conjunction_operator' in i.keys():
                        table.add_row(["", "", "", "", i['conjunction_operator']])
                    else:
                        print("There has been an error")
                print(table)
                print("Based on the above criteria, the effective group membership is:")
                for i in group:
                    if i['resource_type'] == 'ConjunctionOperator':
                        continue
                    elif i['member_type'] == 'VirtualMachine':
                        group_vm_membership_json = get_sddc_group_vm_membership_json(proxy_url, session_token, gw, group_id)
                        group_vm_membership = group_vm_membership_json['results']
                        for x in group_vm_membership:
                            vm_table.add_row([x['display_name']])
                        print("Here is the list of VMs included in this group")
                        print(vm_table)
                    elif i['member_type'] == 'Segment':
                        group_segment_membership_json = get_sddc_group_segment_json(proxy_url, session_token, gw, group_id)
                        group_segment_membership = group_segment_membership_json['results']
                        for y in group_segment_membership:
                            segment_table.add_row([y['display_name']])
                        print("Here is the list of Segments included in this group")
                        print(segment_table)
                    elif i['member_type'] == 'SegmentPort':
                        group_segment_port_membership_json = get_sddc_group_segment_port_json(proxy_url, session_token, gw,
                                                                                              group_id)
                        group_segment_port_membership = group_segment_port_membership_json['results']
                        for z in group_segment_port_membership:
                            segment_port_table.add_row([z['display_name']])
                        print("Here is the list of Segment Ports included in this group")
                        print(segment_port_table)
                    elif i['member_type'] == 'IPSet':
                        group_ip_address_membership_json = get_sddc_group_ip_address_json(proxy_url, session_token, gw,
                                                                                          group_id)
                        group_id_address_membership = group_ip_address_membership_json['results']
                        for a in group_id_address_membership:
                            ip_address_table.add_row([a['displan_name']])
                        print("Here is the list of IP Addresses included in this group")
                        print(ip_address_table)
                    else:
                        print("No effective group member")

            elif g["resource_type"] == "IPAddressExpression":
                ip_addr = get_sddc_group_ip_address_json(proxy_url, session_token, gw, group_id)
                ips = ip_addr['results']
                for i in ips:
                    ip_address_table.add_row([i])
                print("The group " + group_id + " is based on the IP addresses criteria:")
                print(ip_address_table)
            elif g["resource_type"] == "ExternalIDExpression" and g['member_type'] == 'VirtualMachine':
                group_vm = get_sddc_group_vm_membership_json(proxy_url, session_token, gw, group_id)
                vms = group_vm['results']
                for v in vms:
                    vm_table.add_row([v['display_name']])
                print(f"The VMs in group {group_id} are:")
                print(vm_table)
            elif g["resource_type"] == "ExternalIDExpression" and g['member_type'] == 'VirtualNetworkInterface':
                group_vif = get_sddc_group_vif_json(proxy_url, session_token, gw, group_id)
                vifs = group_vif['results']
                for v in vifs:
                    vif_table.add_row([v['display_name']])
                print(f'The VIFs included in the group {group_id} are:')
                print(vif_table)
            elif g['resource_type'] == "PathExpression":
                paths = g['paths']
                for p in paths:
                    if '/infra/domains/cgw/groups/' in p:
                        group_table.add_row([p])
                    elif '/infra/tier-1s/' in p:
                        group_segments = get_sddc_group_segment_json(proxy_url, session_token, gw, group_id)
                        segments = group_segments['results']
                        for s in segments:
                            segment_table.add_row([s['display_name'], s['path']])
                print(f"The group {group_id} contain these groups/segments")
                print(group_table)
                print(segment_table)
            elif g['resource_type'] == 'MACAddressExpression':
                mac_addrs = g['mac_addresses']
                for m in mac_addrs:
                    mac_table.add_row([m])
                print(f'The group {group_id} contains these MAC Addresses')
                print(mac_table)
            elif g['resource_type'] == 'ConjunctionOperator':
                continue
            else:
                print("We currently do not support displaying groups of this configuration")
    else:
        print("whoops")
    return


def getSDDCGroupAssociation(proxy_url, session_token, gw, group_id):
    """ Find where a SDDC Group is being used. Use 'mgw' or 'cgw' as the parameter """
    json_response = get_sddc_group_association_json(proxy_url, session_token, gw, group_id)
    sddc_group = json_response['results']
    if len(sddc_group) == 0:
        print("No object is associated with this group.")
    else:
        table = PrettyTable(['ID', 'Name'])
        for i in sddc_group:
            table.add_row([i['target_id'], i['target_display_name']])
        print(table)


# ============================
# NSX-T - NAT
# ============================


def newSDDCNAT(proxy_url, session_token, display_name, action, translated_network, source_network, service, translated_port, logging, status):
    """ Creates a new NAT rule """
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
        json_response_status_code = new_sddc_nat_json(proxy_url, session_token, display_name, json_data)
        if json_response_status_code == 200:
            print(f"NAT {display_name} created successfully")

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
        json_response_status_code = new_sddc_nat_json(proxy_url, session_token, display_name, json_data)
        if json_response_status_code == 200:
            print(f"NAT {display_name} created successfully")


def getSDDCNAT(proxy_url, sessiontoken):
    """Prints out all SDDC NAT rules"""
    json_response = get_sddc_nat_info_json(proxy_url, sessiontoken)
    sddc_NAT = json_response['results']
    table = PrettyTable(['ID', 'Name', 'Public IP', 'Ports', 'Internal IP', 'Enabled?'])
    for i in sddc_NAT:
        if 'destination_network' in i:
            table.add_row([i['id'], i['display_name'], i['destination_network'], i['translated_ports'], i['translated_network'], i['enabled']])
        else:
            table.add_row([i['id'], i['display_name'], i['translated_network'], "any", i['source_network'], i['enabled']])
    return table


def getSDDCNATStatistics(proxy_url, sessiontoken, nat_id):
    """Prints NAT statistics for provided NAT rule ID"""
    json_response = get_nat_stats_json(proxy_url, sessiontoken, nat_id)
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


# ============================
# NSX-T - Public IP Addressing
# ============================


def newSDDCPublicIP(proxy_url, session_token, ip_id):
    """ Gets a new public IP for compute workloads. Requires a description to be added to the public IP."""
    json_data = {
    "display_name" : ip_id
    }
    json_response_status_code = put_sddc_public_ip_json(proxy_url, session_token, ip_id, json_data)
    return json_response_status_code


def setSDDCPublicIP(proxy_url, session_token, notes, ip_id):
    """ Update the description of an existing  public IP for compute workloads."""
    json_data = {
    "display_name" : notes
    }
    json_response_status_code = put_sddc_public_ip_json(proxy_url, session_token, ip_id, json_data)
    return json_response_status_code


def getSDDCPublicIP(proxy_url, sessiontoken):
    json_response = get_sddc_public_ip_json(proxy_url, sessiontoken)
    sddc_public_ips = json_response['results']
    table = PrettyTable(['IP', 'id', 'Notes'])
    for i in sddc_public_ips:
        table.add_row([i['ip'], i['id'], i['display_name']])
    return table


# ============================
# NSX-T - Segments
# ============================

def configure_t1(**kwargs):
    """ Configures a Tier1 router as 'ROUTED', 'ISOLATED', or 'NATTED'... Creates a new T1 if it does not exist already."""
    if kwargs['objectname'] is None or kwargs['t1type'] is None:
        print("Please use -n to specify the name of the T1 router to be configured, and -t1t or --t1type to specify the type (ROUTED/NATTED/ISOLATED).  Consult the help for additional options.")
        sys.exit()
    t1_id = kwargs["objectname"]
    json_data = {"type": kwargs["t1type"]}
    status = configure_t1_json(proxy, session_token, t1_id, json_data)
    if status == 200:
        print(f'Tier1 gateway {t1_id} has been configured as {kwargs["t1type"]}')
    else:
        print("T1 was not created.  Please check your syntax and try again.")

def remove_t1(**kwargs):
    """ Deletes a Tier1 router as"""
    t1_id = kwargs["objectname"]
    if t1_id =="cgw" or t1_id =="mgw":
        print(" ")
        print("Seriously?")
        print(" ")
        print("That's a terrible idea!")
        print("Are you trying to break the environment?")
        print("Do not try to delete the default CGW of MGW.")
        print(" ")
        sys.exit()
    status = delete_t1_json(proxy, session_token, t1_id)
    if status ==200:
        print(f'Tier1 gateway {t1_id} has been deleted.')
    else: 
        print("T1 was not removed.  Please check your syntax and try again.")

def new_segment(**kwargs):
    """
    Creates a new network segment - requires options to configure correctly.
    Supports new, 'moveable' networks under M18 and later as well as 'fixed' networks pre-M18
    """
    if kwargs['objectname'] is None or kwargs['gateway'] is None:
        print("Please specify a name for the segment, and the gateway/network.")
        sys.exit()
    if kwargs['segment_type'] == "moveable" and kwargs['tier1_id'] is None:
        print("Please specify either the segment type as 'fixed' (-st fixed) OR the ID of the Tier1 for connectivity (-t1id TIER1ID).  Use pyVMC -h for additional options.")
        sys.exit()
    segment_name = kwargs["objectname"]
    segment=search_nsx_json(proxy, session_token, "Segment", segment_name)
    if len(segment['results']) > 0:
        print("The segment already appears to exist.")
        sys.exit()
    segment_type = kwargs['segment_type']
    json_data = {
        "display_name":f'{segment_name}',
        "id":f'{segment_name}',
        "advanced_config":{"connectivity":"ON"},
        "type": "ROUTED",
        "subnets":[
            {
                "gateway_address": f'{kwargs["gateway"]}'
            }
        ]
        }
    if kwargs['dhcp_range'] is not None:
        json_data["subnets"][0]["dhcp_ranges"] = [f'{kwargs["dhcp_range"]}']
    if kwargs['domain_name'] is not None:
        json_data["domain_name"] = f'[{kwargs["domain_name"]}]'
    if kwargs['connectivity'] == "ON":
        json_data["advanced_config"]["connectivity"] = "ON"
    if kwargs['routing_type'] is not None:
        json_data["type"] = f'{kwargs["routing_type"]}'
    if kwargs['tier1_id'] is not None:
        if segment_type == "fixed":
            json_data["connectivity_path"] = "/infra/tier-1s/cgw"
        else:
            json_data["connectivity_path"] = f'/infra/tier-1s/{kwargs["tier1_id"]}'
    status = new_segment_json(proxy, session_token, segment_name, segment_type, json_data)
    if status == 200:
        print(f'The following network has been created: {segment_name}')
        search_nsx(proxy, session_token, "Segment", segment_name)
    else:
        print("The segment was not created. Please check your syntax and try again.")
      
def configure_segment(**kwargs):
    """
    Reconfigures an existing network segment - requires options to configure correctly.
    If segment does not exist, prompts user to create using 'new-segment'
    Supports new, 'moveable' networks under M18 and later as well as 'fixed' networks pre-M18
    """
    if kwargs['objectname'] is None:
        print("Please use -n to specify the name of the segment to be configured.  Consult the help for additional options.")
        sys.exit()
    segment_name = kwargs["objectname"]
    # Quick search to see if the segment exists of not.
    segment=search_nsx_json(proxy, session_token, "Segment", segment_name)
    # If the segment exists, capture the path for the API call, and the existing configuration in JSON.
    if len(segment['results']) > 0:
        json_init=segment['results'][0]
        segment_path = segment['results'][0]['path']
    else:
        print("The segment does not exist.  Please create a segment using 'new-segment'.")
        sys.exit()
    # Establish a list of keys to keep - these represent the values we are willing/able to update.
    keep_list = ['display_name', 'connectivity_path','advanced_config','type']
    # Construct a new JSON using just the keys we want to keep
    json_data = dict([(key, val) for key, val in 
           json_init.items() if key in keep_list])
    # Update the json_data with the configuration specified by the user.
    if kwargs['connectivity'] is not None:
        json_data["advanced_config"]["connectivity"] = f'{kwargs["connectivity"]}'
    if kwargs['routing_type'] is not None:
        json_data["type"] = f'{kwargs["routing_type"]}'
    if kwargs['tier1_id'] is not None:
        if segment_path == "/infra/tier-1s/cgw":
            print("This is a fixed segment - you may not alter the connectivity path.  Plese create a 'moveable' segment.")
        else:
            json_data["connectivity_path"] = f'/infra/tier-1s/{kwargs["tier1_id"]}'
    # make the call to the API
    status = configure_segment_json(proxy, session_token, segment_path, json_data)
    # present results.
    if status ==200:
        print(f'The following network has been modified: {segment_name}')
        search_nsx(proxy, session_token, "Segment", segment_name)
    else: 
        print("The segment was not modified.  Please check your syntax and try again.")

def remove_segment(**kwargs):
    """
    Removes a network segment - requires options to configure correctly.
    Supports new, 'moveable' networks under M18 and later as well as 'fixed' networks pre-M18
    """
    if kwargs['objectname'] is None:
        print("Please use -n to specify a name for the segment to be removed.  Consult the help for additional options.")
    segment_name = kwargs["objectname"]
    segment=search_nsx_json(proxy, session_token, "Segment", segment_name)
    if len(segment['results']) > 0:
        segment_path = segment['results'][0]['path']
        status = remove_segment_json(proxy, session_token, segment_path)
        if status == 200:
            print(f'The following network has been removed: {segment_name}')
        else:
            print("The segment was not removed.  Please check your syntax and try again.")
    else:
        print("The segment does not exist.")
    
def connect_segment(proxy_url, sessiontoken, network_id, gateway_address, dhcp_range, domain_name):
    """ Connects an existing SDDC Network to the default CGW. L2 VPN networks are not currently supported. """
    segment = search_nsx_json(proxy, session_token, "Segment", network_id)
    if 'connectivity_path' in segment['results'][0]:
        if segment['results'][0]['connectivity_path'] == "/infra/tier-1s/cgw":
            json_data = {
                "subnets":[{"dhcp_ranges":[dhcp_range],
                "gateway_address":gateway_address}],
                "domain_name":domain_name,
                "id":network_id,
                "advanced_config":{"connectivity":"ON"}
                }
            if dhcp_range == "":
                del (json_data["subnets"][0]['dhcp_ranges'])
            if domain_name =="":
                del (json_data["domain_name"])
            connect_segment_json(proxy_url, sessiontoken, network_id, json_data)
            print(f'The network has been connected:  {network_id}')
            search_nsx(proxy, session_token, "Segment", network_id)    
    else:
        print("")
        print("Please check your segments again.  CONNECT and DISCONNECT comands may only be used for segments on the default CGW.")
        print("To connect or disconnect secondary T1 routers, please use 'configure-t1'.")

def disconnect_segment(proxy_url, sessiontoken, network_id):
    """ Connects an existing SDDC Network. L2 VPN networks are not currently supported. """
    segment = search_nsx_json(proxy, session_token, "Segment", network_id)
    if 'connectivity_path' in segment['results'][0]:
        if segment['results'][0]['connectivity_path'] == "/infra/tier-1s/cgw":
            json_data = {
                    "id":network_id,
                    "advanced_config":{"connectivity":"OFF"}
                    }
            connect_segment_json(proxy_url, sessiontoken, network_id, json_data)
            print("The network has been disconnected:")
            search_nsx (proxy, session_token, "Segment", network_id)  
    else:
        print("")
        print("Please check your segments again.  CONNECT and DISCONNECT comands may only be used for segments on the default CGW.")
        print("To connect or disconnect secondary T1 routers, please use 'configure-t1'.")

def newSDDCnetworks(proxy_url, sessiontoken, display_name, gateway_address, dhcp_range, domain_name, routing_type):
    """ Creates a new SDDC Network. L2 VPN networks are not currently supported. """
    json_data = {
            "subnets":[{"dhcp_ranges":[dhcp_range],
            "gateway_address":gateway_address}],
            "type":routing_type,
            "display_name":display_name,
            "domain_name":domain_name,
            "id":display_name
            }
    if routing_type == "DISCONNECTED" :
        json_data.update({'advanced_config':{"connectivity":"OFF"}})
    else:
        json_data.update({'advanced_config':{"connectivity":"ON"}})
    if dhcp_range == "":
        del (json_data["subnets"][0]['dhcp_ranges'])
    new_sddc_networks_json(proxy_url, sessiontoken, display_name, json_data)
    print("The following network has been created:")
    table = PrettyTable(['Name', 'Gateway', 'DHCP', 'Domain Name', 'Routing Type'])
    table.add_row([display_name, gateway_address, dhcp_range, domain_name, routing_type])
    return table

def newSDDCStretchednetworks(proxy_url, sessiontoken, display_name, tunnel_id, l2vpn_path):
    """ Creates a new stretched/extended Network. """
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
    new_sddc_stretched_networks_json(proxy_url, sessiontoken, display_name, json_data)
    print("The following network has been created:")
    table = PrettyTable(['Name', 'Tunnel ID', 'Routing Type'])
    table.add_row([display_name, tunnel_id, "extended"])
    return table

def removeSDDCNetworks(proxy_url, sessiontoken, network_id):
    """ Remove an SDDC Network """
    remove_sddc_networks_json(proxy_url, sessiontoken, network_id)
    print(f'The network {network_id} has been deleted.')

def getSDDCnetworks(proxy_url, sessiontoken):
    """Prints out all Compute Gateway segemtns in all the SDDCs in the Org"""
    json_response = get_cgw_segments_json(proxy_url, sessiontoken)
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


# ============================
# NSX-T - VPN
# ============================


def newSDDCL2VPN(proxy_url, session_token, display_name):
    """ Creates the configured L2 VPN """
    json_data = {
    "transport_tunnels": [
        "/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions/" + display_name
    ],
    "resource_type": "L2VPNSession",
    "id": display_name,
    "display_name": "L2VPN",
}
    json_response_status_code = new_l2vpn_json(proxy_url, session_token, display_name, json_data)
    return json_response_status_code


def getSDDCL2VPNSession(proxy_url, sessiontoken):
    """Prints out L2VPN sessions"""
    i = get_l2vpn_session_json(proxy_url, sessiontoken)
    sddc_l2vpn_sessions = i['results']
    table = PrettyTable(['Name', 'ID', 'Enabled?'])
    for i in sddc_l2vpn_sessions:
        table.add_row([i['display_name'], i['id'], i['enabled']])
    return table


def getSDDCL2VPNServices(proxy_url, sessiontoken):
    """Prints out L2VPN services"""
    i = get_l2vpn_service_json(proxy_url, sessiontoken)
    table = PrettyTable(['Name', 'ID', 'mode'])
    table.add_row([i['display_name'], i['id'], i['mode']])
    return table


def getSDDCVPN(proxy_url,sessiontoken):
    """Prints out SDDC VPN session information"""
    json_response = get_sddc_vpn_info_json(proxy_url, sessiontoken)
    sddc_VPN = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Local Address', 'Remote Address'])
    for i in sddc_VPN:
        table.add_row([i['display_name'], i['id'], i['local_endpoint_path'].strip("/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/local-endpoints/"), i['peer_address']])
    return table


def getSDDCVPNIpsecProfiles(proxy_url, sessiontoken):
    """Prints out VPN IKE profiles for the SDDC"""
    json_response = get_vpn_ike_profile_json(proxy_url, sessiontoken)
    sddc_VPN_ipsec_profiles = json_response['results']
    table = PrettyTable(['Name', 'ID', 'IKE Version', 'Digest', 'DH Group', 'Encryption'])
    for i in sddc_VPN_ipsec_profiles:
        table.add_row([i['display_name'], i['id'], i['ike_version'], i['digest_algorithms'], i['dh_groups'], i['encryption_algorithms']])
    return table


def getSDDCVPNIpsecTunnelProfiles(proxy_url, sessiontoken):
    """Prints out VPN IPSEC profiles for the SDDC"""
    json_response = get_vpn_ipsec_profile_json(proxy_url, sessiontoken)
    sddc_VPN_ipsec_tunnel_profiles = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Digest', 'DH Group', 'Encryption'])
    for i in sddc_VPN_ipsec_tunnel_profiles:
        table.add_row([i['display_name'], i['id'], i['digest_algorithms'], i['dh_groups'], i['encryption_algorithms']])
    return table


def getSDDCVPNInternetIP(proxy_url, sessiontoken):
    """Prints out Public IP assigned to VPN"""
    json_response = vpn_public_ip_json(proxy_url, sessiontoken)
    vpn_internet_ip = json_response['vpn_internet_ips'][0]
    print(vpn_internet_ip)


def getSDDCVPNIpsecEndpoints(proxy_url, session_token):
    """ Gets the IPSec Local Endpoints """
    json_response = get_ipsec_vpn_endpoints(proxy_url, session_token)
    sddc_vpn_ipsec_endpoints = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Address'])
    for i in sddc_vpn_ipsec_endpoints:
        table.add_row([i['display_name'], i['id'], i['local_address']])
    return table


def getSDDCVPNServices(proxy_url, session_token, vpn_id):
    """Returns Table of available VPN services"""
    i = get_ipsec_vpn_services(proxy_url, session_token, vpn_id)
    table = PrettyTable(['Name', 'Id', 'Peer'])
    table.add_row([i['display_name'], i['id'], i['peer_address']])
    return table


def getSDDCL2VPNSessionPath(proxy_url, sessiontoken):
    """Prints out L2VPN Session Path"""
    i = get_l2vpn_session_json(proxy_url, sessiontoken)
    sddc_l2vpn_path = i['results'][0]['path']
    return sddc_l2vpn_path


def newSDDCIPSecVpnIkeProfile(proxy_url, session_token, display_name):
    """ Creates the configured IPSec VPN Ike Profile """
    json_data = {
    "resource_type":"IPSecVpnIkeProfile",
    "display_name": display_name,
    "id": display_name,
    "encryption_algorithms":["AES_128"],
    "digest_algorithms":["SHA2_256"],
    "dh_groups":["GROUP14"],
    "ike_version":"IKE_V2"
    }
    json_response_status_code = new_ipsec_vpn_ike_profile_json(proxy_url, session_token, display_name, json_data)
    return json_response_status_code


def newSDDCIPSecVpnTunnelProfile(proxy_url, session_token, display_name):
    """ Creates the configured IPSec VPN Tunnel Profile """
    json_data = {
    "resource_type":"IPSecVpnTunnelProfile",
    "display_name": display_name,
    "id": display_name,
    "encryption_algorithms":["AES_GCM_128"],
    "digest_algorithms":[],
    "dh_groups":["GROUP14"],
    "enable_perfect_forward_secrecy":True
    }
    json_response_status_code = new_ipsec_vpn_profile_json(proxy_url, session_token, display_name, json_data)
    return json_response_status_code


def newSDDCIPSecVpnSession(proxy_url, session_token, display_name, endpoint, peer_ip):
    """ Creates the configured IPSec VPN Tunnel Profile """
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
    json_response_status_code = new_ipsec_vpn_session_json(proxy_url, session_token, json_data, display_name)
    return json_response_status_code


def getSDDCVPNSTATS(proxy_url, sessiontoken, tunnelID):
    """Returns table of VPN Statistics"""
    json_response = get_vpn_stats_json(proxy_url, sessiontoken, tunnelID)
    sddc_vpn_statistics = json_response['results'][0]['policy_statistics'][0]['tunnel_statistics']
    table = PrettyTable(['Status', 'Packets In', 'Packets Out'])
    for i in sddc_vpn_statistics:
        table.add_row([i['tunnel_status'], i['packets_in'], i['packets_out']])
    return table


# ============================
# VCDR - Cloud File System
# ============================
def getVCDRCloudFS(strVCDRProdURL, session_token):
    """Get a list of all deployed cloud file systems in your VMware Cloud DR organization."""
    json_response = get_vcdr_cloud_fs_json(strVCDRProdURL, session_token)
    # print(json.dumps(json_response, indent = 2))
    cloud_fs = json_response["cloud_file_systems"]
    table = PrettyTable(['Cloud FS Name', 'Cloud FS ID'])
    for i in cloud_fs:
        table.add_row([i['name'], i['id']])
    print(table)

def getVCDRCloudFSDetails(strVCDRProdURL, cloud_fs_id, session_token):
    """Get details for an individual cloud file system."""
    json_response = get_vcdr_cloud_fs_details_json(strVCDRProdURL, cloud_fs_id, session_token)
    print(" ")
    print(f"Cloud FS Name: {json_response['name']}")
    print(f"Capacity GiB: {json_response['capacity_gib']:,.2f}")
    print(f"Used GiB: {json_response['used_gib']:,.2f}")
    print(f"Recovery SDDC: {json_response['recovery_sddc_id']}")
    print(" ")


# ============================
# VCDR - Protected Sites
# ============================
def getVCDRSites(strVCDRProdURL, cloud_fs_id, session_token):
    """Get a list of all protected sites associated with an individual cloud file system."""
    json_response = get_vcdr_sites_json(strVCDRProdURL, cloud_fs_id, session_token)
    sites = json_response["protected_sites"]
    table = PrettyTable(['Site Name', 'Site ID'])
    for i in sites:
        table.add_row([i['name'], i['id']])
    print(table)

def getVCDRSiteDetails(strVCDRProdURL, cloud_fs_id, site_id, session_token):
    """Get details about an individual protected site."""
    json_response = get_vcdr_site_details_json(strVCDRProdURL, cloud_fs_id, site_id, session_token)
    print(" ")
    print(f"Site Name: {json_response['name']}")
    print(f"Site Type: {json_response['type']}")
    print(" ")


# ============================
# VCDR - Protected VM
# ============================
def getVCDRVM(strVCDRProdURL, cloud_fs_id, session_token):
    """Get a list of all protected VMs currently being replicated to the specified cloud file system."""
    json_response = get_vcdr_vm_json(strVCDRProdURL, cloud_fs_id, session_token)
    vms = json_response["vms"]
    table = PrettyTable(['VM Name', 'VCDR VM ID', 'VM Size'])
    for i in vms:
        table.add_row([i['name'], i['vcdr_vm_id'], i['size']])
    print(table)


# ============================
# VCDR - Protection Groups
# ============================
def getVCDRPG(strVCDRProdURL, cloud_fs_id, session_token):
    """Get a list of all protection groups associated with an individual cloud file system."""
    json_response = get_vcdr_pg_json(strVCDRProdURL, cloud_fs_id, session_token)
    pgs = json_response["protection_groups"]
    table = PrettyTable(['Protection Group Name', 'Protection Group ID'])
    for i in pgs:
        table.add_row([i['name'], i['id']])
    print(table)

def getVCDRPGDetails(strVCDRProdURL, cloud_fs_id, pg_id, session_token):
    """Get details for the requested protection group."""
    json_response = get_vcdr_pg_details_json(strVCDRProdURL, cloud_fs_id, pg_id, session_token)
    print(json.dumps(json_response, indent = 2))
    print(" ")
    print(f"Protection Group Name: {json_response['name']}")
    print(f"Protection Group Health: {json_response['health']}")
    print(f"Protected Site ID: {json_response['protected_site_id']}")
    print(f"Snapshot Schedule Active?: {json_response['snapshot_schedule_active']}")
    print(f"Snapshot Frequency Type?: {json_response['snapshot_frequency_type']}")
    # print(f"Used GiB: {json_response['used_gib']:,.2f}")
    criteria = json_response["members_specs"]
    print(f"Protected vCenter: {criteria[0]['vcenter_id']}")
    if "vcenter_vm_name_patterns" in criteria[0]:
        print(f"VM Naming Patterns: {criteria[0]['vcenter_vm_name_patterns']}")
    if "vcenter_tags" in criteria[0]:
        print(f"VM Tags: {criteria[0]['vcenter_tags']}")
    if "vcenter_folder_paths" in criteria[0]:
        print(f"VM Folders: {criteria[0]['vcenter_folder_paths']}")
    print(f"Snapshot Schedule Specifications:  {json_response['schedule_specs']}")
    print(" ")

# ============================
# VCDR - Protection Group Snapshots
# ============================
def getVCDRPGSnaps(strVCDRProdURL, cloud_fs_id, pg_id, session_token):
    """Get a list of all snapshots in a specific protection group."""
    json_response = get_vcdr_pg_snaps_json(strVCDRProdURL, cloud_fs_id, pg_id, session_token)
    snaps = json_response["snapshots"]
    table = PrettyTable(['Snapshot Name', 'Snaphot ID'])
    for i in snaps:
        table.add_row([i['name'], i['id']])
    print(table)

def getVCDRSnapDetails(strVCDRProdURL, cloud_fs_id, pg_id, snap_id, session_token):
    """Get a list of all snapshots in a specific protection group."""
    json_response = get_vcdr_pg_snap_details_json(strVCDRProdURL, cloud_fs_id, pg_id, snap_id, session_token)
    create_stamp_int = int(json_response['creation_timestamp'])
    create_stamp = datetime.utcfromtimestamp(create_stamp_int/1e9)
    expire_stamp_int = int(json_response['expiration_timestamp'])
    expire_stamp = datetime.utcfromtimestamp(expire_stamp_int/1e9)
    print(" ")
    print(f"Snapshot Name: {json_response['name']}")
    # print(f"Snapshot Creation: {json_response['creation_timestamp']}")
    print(f"Snapshot Creation: {create_stamp}")
    print(f"Snapshot Expiration: {expire_stamp}")
    print(f"Snapshot Trigger: {json_response['trigger_type']}")
    print(f"Number of VM: {json_response['vm_count']}")
    print(" ")

# ============================
# VCDR - Recovery SDDC
# ============================
def getVCDRSDDCs(strVCDRProdURL, session_token):
    """List VMware Cloud (VMC) Recovery Software-Defined Datacenters (SDDCs)."""
    json_response = get_vcdr_sddcs_json(strVCDRProdURL, session_token)
    sddcs = json_response["data"]
    table = PrettyTable(['Recovery SDDC Name', 'Recovery SDDC ID'])
    for i in sddcs:
        table.add_row([i['name'], i['id']])
    print(table)

def getVCDRSDDCDetails(strVCDRProdURL, sddc_id, session_token):
    """Get details of a specific Recovery SDDC."""
    json_response = get_vcdr_sddc_details_json(strVCDRProdURL, sddc_id, session_token)
    print(" ")
    print(f"Recovery SDDC Name: {json_response['name']}")
    print(f"Recovery SDDC Region: {json_response['region']}")
    print(f"Recovery SDDC AZs: {json_response['availability_zones']}")
    print(" ")

# ============================
# Help
# ============================
def getHelp():
    print("\nWelcome to PyVMC !")
    print("\nHere are the currently supported commands: ")
    print("\nCSP")
    print("\tServices")
    print("\t   show-csp-services: Show entitled services")
    print("\tUser and Group management")
    print("\t   add-users-to-csp-group [GROUP_ID] [EMAILS]: CSP user to a group")
    print("\t   show-csp-group-diff [GROUP_ID] [showall|skipmembers|skipowners]: this compares the roles in the specified group with every user in the org and prints out a user-by-user diff")
    print("\t   show-csp-group-members [GROUP_ID]: show CSP group members")
    print("\t   show-csp-groups: To show CSP groups")
    print("\t   show-csp-org-users [email]: show a CSP user")
    print("\t   show-csp-service-roles: show CSP service roles for the currently logged in user")
    print("\t   find-csp-user-by-service-role [service role name]: search for CSP users with a specific service role")
    print("\t   show-org-users: show the list of organization users")
    print("\t   set-sddc-connected-services: change whether to use S3 over the Internet or via the ENI\n")
    print("\nSDDC")
    print("\tAWS Account and VPC")
    print("\t   show-compatible-subnets [LINKEDACCOUNTID] [REGION]: show compatible native AWS subnets connected to the SDDC")
    print("\t   show-connected-accounts: show native AWS accounts connected to the SDDC")
    print("\t   show-sddc-connected-vpc: show the VPC connected to the SDDC")
    print("\t   show-shadow-account: show the Shadow AWS Account VMC is deployed in\n")
    print("\tSDDC")
    print("\t   get-access-token: show your access token")
    print("\t   show-sddc-state: get a view of your selected SDDC")
    print("\t   show-sddcs: display a lit of your SDDCs")
    print("\t   show-vms: get a list of your VMs\n")
    print("\tTKG")
    print("\t   enable-tkg: Enable Tanzu Kubernetes Grid on an SDDC")
    print("\t   disable-tkg: Disable Tanzu Kubernetes Grid on an SDDC\n")
    print("\nVMware Transit Connect")
    print("\tAWS Operations:")
    print("\t    connect-aws: Connect an vTGW to an AWS account")
    print("\t    disconnect-aws: Disconnect a vTGW from an AWS account\n")
    print("\tDXGW Operations:")
    print("\t    attach-dxgw: Attach a Direct Connect Gateway to a vTGW")
    print("\t    detach-dxgw: Detach a Direct Connect Gateway from a vTGW\n")
    print("\tSDDC Operations:")
    print("\t    get-sddc-info: Display a list of all SDDCs")
    print("\t    get-nsx-info: Display NSX credentials and URLs")
    print("\t    attach-sddc: Attach an SDDC to a vTGW")
    print("\t    detach-sddc: Detach an SDDC from a vTGW\n")
    print("\tSDDC-Group Operations:")
    print("\t    create-sddc-group [name]: Create an SDDC group")
    print("\t    delete-sddc-group: Delete an SDDC group")
    print("\t    get-group-info: Display details for an SDDC group\n")
    print("\tTGW Operations:")
    print("\t    show-tgw-routes: Show the vTGW route table\n")
    print("\tVPC Operations:")
    print("\t    attach-vpc: Attach a VPC to a vTGW")
    print("\t    detach-vpc Detach VPC from a vTGW")
    print("\t    vpc-prefixes: Add or remove vTGW static routes\n")
    print("\nNSX-T")
    print("\tSearch")
    print("\t    search-nsx [OBJECT_TYPE]: lists a table of specified objects returned from NSX")
    print("\tNSX-T Advanced Firewall Add-on - Add-on must be activated via GUI in the Cloud Services Portal")
    print("\t   show-nsxaf-status: Display the status of the NSX Advanced Firewall Add-on\n")
    print("\tDistributed IDS Operations")
    print("\t   show-ids-cluster-status: Show IDS status for each cluster in the SDDC")
    print("\t   enable-cluster-ids [CLUSTER_ID]: Enable IDS on cluster")
    print("\t   disable-cluster-ids [CLUSTER_ID]: Disable IDS on cluster")
    print("\t   enable-all-cluster-ids: Enable IDS on all clusters")
    print("\t   disable-all-cluster-ids: Disable IDS on all clusters")
    print("\t   enable-ids-auto-update: Enable IDS signature auto update")
    print("\t   ids-update-signatures: Force update of IDS signatures")
    print("\t   show-ids-signature-versions: Show downloaded signature versions")
    print("\t   show-ids-profiles: Show all IDS profiles")
    print("\t   search-product-affected: Search through the active IDS signature for specific product affected.  Useful when building an IDS Profile")
    print("\t   create-ids-profile: Create an IDS profile with either Product Affected, CVSS or both.")
    print("\t   show-ids-policies: List all IDS policies")
    print("\t   create-ids-policy: Create an IDS policy ")
    print("\t   show-ids-rules: List all IDS rules")
    print("\t   create-ids-rule: Create an IDS rule using previously created IDS profile and inventory groups\n")
    print("\tBGP and Routing")
    print("\t   attach-t0-prefix-list [BGP NEIGHBOR ID]: attach a BGP Prefix List to a T0 BGP neighbor")
    print("\t   detach-t0-prefix-lists [BGP NEIGHBOR ID]: detach all prefix lists from specified neighbor")
    print("\t   new-t0-prefix-list: create a new T0 BGP Prefix List")
    print("\t   remove-t0-prefix-list [PREFIX LIST ID]: you can see current prefix list with 'show-t0-prefix-lists': remove a T0 BGP Prefix List")
    print("\t   set-sddc-bgp-as [ASN]: update the BGP AS number")
    print("\t   set-mtu: set the MTU configured over the Direct Connect")
    print("\t   show-mtu: show the MTU configured over the Direct Connect")
    print("\t   show-egress-interface-counters: show current Internet interface egress counters")
    print("\t   show-sddc-bgp-as: show the BGP AS number")
    print("\t   show-sddc-bgp-vpn: show whether DX is preferred over VPN")
    print("\t   show-t0-bgp-neighbors: show T0 BGP neighbors")
    print("\t   show-t0-bgp-routes: show all learned and advertised routes through BGP")
    print("\t   show-t0-prefix-lists: show T0 prefix lists")
    print("\t   show-t0-routes: show routes at the T0 router")
    print("\t   show-t0-static-routes: show static routes at the T0 router\n")
    print("\tDNS ")
    print("\t   show-dns-services: show DNS services")
    print("\t   show-dns-zones: show DNS zones\n")
    print("\tFirewall - Gateway")
    print("\t   new-cgw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SCOPE] [SEQUENCE-NUMBER]: create a new CGW security rule")
    print("\t   new-mgw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SEQUENCE-NUMBER]: create a new MGW security rule")
    print("\t   remove-cgw-rule [RULE_ID]: delete a CGW security rule")
    print("\t   remove-mgw-rule [RULE_ID]: delete a MGW security rule")
    print("\t   show-cgw-rule: show the CGW security rules")
    print("\t   show-mgw-rule: show the MGW security rules\n")
    print("\tFirewall - Distributed")
    print("\t   new-dfw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SECTION] [SEQUENCE-NUMBER]: create a new DFW security rule")
    print("\t   new-dfw-section [NAME][CATEGORY]: create a new DFW section")
    print("\t   remove-dfw-rule [SECTION_ID][RULE_ID]: delete a DFW rule")
    print("\t   remove-dfw-section [RULE_ID]: delete a DFW section")
    print("\t   show-dfw-section: show the DFW sections")
    print("\t   show-dfw-section-rules [SECTION]: show the DFW security rules within a section\n")
    print("\tFirewall Services")
    print("\t   new-service: create a new service")
    print("\t   remove-service [SERVICE-ID]: remove a service")
    print("\t   show-services [SERVICE-ID]: show a specific service")
    print("\t   show-services: show services\n")
    print("\tInventory Groups")
    print("\t   new-group [CGW/MGW] [Group_ID]: create a new group")
    print("\t   remove-group [CGW/MGW][Group_ID]: remove a group")
    print("\t   show-group [CGW/MGW] [Group_ID]: show existing groups")
    print("\t   show-group-association [CGW/MGW] [Group_ID]: show security rules used by a groups\n")
    print("\tNAT")
    print("\t   new-nat-rule: To create a new NAT rule")
    print("\t   remove-nat-rule: remove a NAT rule")
    print("\t   show-nat: show the configured NAT rules")
    print("\t   show-nat [NAT-RULE-ID] for statistics of a rule: show the statistics for a specific NAT rule\n")
    print("\tPublic IP addressing")
    print("\t   new-sddc-public-ip: request a new public IP")
    print("\t   remove-sddc-public-ip: remove an existing public IP")
    print("\t   set-sddc-public-ip: update the description of an existing public IP")
    print("\t   show-sddc-public-ip: show the public IPs\n")
    print("\tVirtual Machine Networking")
    print("\t   configure-t1 (-n NAME --t1type ROUTED/NATTED/ISOLATED): Create or configure a new or existing tier-1 compute gateways - compatible with VMC on AWS SDDC 1.18 and onwards")
    print("\t   remove-t1 (-n NAME): Deletes a T1 gateway - compatible with VMC on AWS SDDC 1.18 and onwards;") 
    print("\t   new-segment (try pyVMC.py -h for options): Creates a new 'fixed' or 'moveable' segment- compatible with VMC on AWS SDDC 1.18 and onwards; defaults to 'moveable.") 
    print("\t   configure-segment (try pyVMC.py -h for options): Modifies the configuration of an existing 'fixed' or 'moveable' segment- compatible with VMC on AWS SDDC 1.18 and onwards; does not support changing from fixed/moveable.") 
    print("\t   remove-segment (options: -n SEGMENT NAME): Removes a 'fixed' or 'moveable' segment- compatible with VMC on AWS SDDC 1.18 and onwards") 
    print("\t   connect-segment [NETWORK ID] [GATEWAY_ADDRESS] [DHCP_RANGE] [DOMAIN_NAME] for a DHCP network: changes an existing, disconnected segement to connected and 'routed'")
    print("\t   connect-segment [NETWORK ID] [GATEWAY_ADDRESS] for a static network: changes an existing, disconnected segement to connected and routed")
    print("\t   disconnect-segment [NETWORK ID]: Disconnect an existing routed segment and change to disconnected")
    print("\t   new-network [NAME] DISCONNECTED [GATEWAY_ADDRESS] for a disconnected network")
    print("\t   new-network [NAME] EXTENDED [GATEWAY_ADDRESS] [TUNNEL_ID] for an extended network")
    print("\t   new-network [NAME] ROUTED [GATEWAY_ADDRESS] [DHCP_RANGE] [DOMAIN_NAME] for a DHCP network")
    print("\t   new-network [NAME] ROUTED [GATEWAY_ADDRESS] for a static network")
    print("\t   remove-network: remove a network")
    print("\t   show-network: show your current networks\n")
    print("\tVPN")
    print("\t   new-l2vpn [NAME] [LOCAL_ENDPOINT] [REMOTE_PEER]: create a new L2VPN")
    print("\t   remove-l2VPN [ID]: remove a L2VPN")
    print("\t   remove-vpn [VPN-ID]: remove a VPN")
    print("\t   remove-vpn-ike-profile [ID]: remove a VPN IKE profile")
    print("\t   remove-vpn-ipsec-tunnel-profile [ID]: To remove a VPN IPSec Tunnel profile")
    print("\t   show-l2vpn: show l2 vpn")
    print("\t   show-l2vpn-services: show l2 vpn services")
    print("\t   show-vpn: show the configured VPN")
    print("\t   show-vpn [VPN_ID]: show the VPN statistics")
    print("\t   show-vpn-ike-profile: show the VPN IKE profiles")
    print("\t   show-vpn-internet-ip: show the public IP used for VPN services")
    print("\t   show-vpn-ipsec-tunnel-profile: show the VPN tunnel profile")
    print("\t   show-vpn-ipsec-endpoints: show the VPN IPSec endpoints")
    print("\nVMware Cloud Disaster Recovery")
    print("\t   show-vcdr-fs: show VCDR Cloud File Systems")
    print("\t   show-vcdr-fs-details [CLOUD_FS_ID]: Get details for an individual cloud file system.")
    print("\t   show-vcdr-sites [CLOUD_FS_ID]: Get a list of all protected sites associated with an individual cloud file system.")
    print("\t   show-vcdr-site-details [CLOUD_FS_ID] [PROTECTED_SITE_ID]: Get details about an individual protected site.")
    print("\t   show-vcdr-vm [CLOUD_FS_ID]: Get a list of all protected VMs currently being replicated to the specified cloud file system.")
    print("\t   show-vcdr-pgs [CLOUD_FS_ID]: Get a list of all protection groups associated with an individual cloud file system.")
    print("\t   show-vcdr-pg-details [CLOUD_FS_ID] [PROTECTION_GROUP_ID]: Get details for the requested protection group.")
    print("\t   show-vcdr-pg-snaps [CLOUD_FS_ID] [PROTECTION_GROUP_ID]: Get a list of all snapshots in a specific protection group.")
    print("\t   show-vcdr-pg-snap-details [CLOUD_FS_ID] [PROTECTION_GROUP_ID] [PG_SNAPSHOT_ID]: Get detailed information for a protection group snapshot.")
    print("\t   show-vcdr-sddcs: List VMware Cloud (VMC) Recovery Software-Defined Datacenters (SDDCs).")
    print("\t   show-vcdr-sddc-details [RECOVEY_SDDC_ID]: Get Recovery SDDC Details - Get details of a specific Recovery SDDC. ")
    print("\n")


# --------------------------------------------
# ---------------- Main ----------------------
# --------------------------------------------

if len(sys.argv) > 1:
    intent_name = sys.argv[1].lower()
else:
    intent_name = ""

session_token = getAccessToken(Refresh_Token)
proxy = getNSXTproxy(ORG_ID, SDDC_ID, session_token)

# this is the top level parser
ap = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
# ap.add_argument("-c", "--command", required=True)
ap.add_argument("-n","--objectname", required=False, help= "The name of the object.  May not include spaces or hypens.")

vmnetgrp = ap.add_argument_group('Virtual Machine Networking', "Options only used with 'new-segment' and 'configure-segment'")
vmnetgrp.add_argument("-conn","--connectivity", choices=["ON", "OFF"], required=False, help= "Connectivity status for the segment - by default this is 'OFF'")
vmnetgrp.add_argument("-dhcpr","--dhcp-range", required=False, help= "If applicable, the DHCP range of IP addresses to be distributed.")
vmnetgrp.add_argument("-dn","--domain-name", required=False, help= "The domain name for the subnet - e.g. 'vmc.local'")
vmnetgrp.add_argument("-gw","--gateway", required=False, help= "The gateway and subnet of the network - e.g. '192.138.1.1/24'")
vmnetgrp.add_argument("-rt","--routing-type", choices=["ROUTED", "EXTENDED", "ROUTED_AND_EXTENDED", "DISCONNECTED"], required=False, help= "Routing type - by default this is set to 'ROUTED'")
vmnetgrp.add_argument("-st","--segment-type", choices=["fixed","moveable"], default="moveable", required=False, help= "Determines if this this segment will be 'fixed' to the default CGW - by default this is 'MOVEABLE'")
vmnetgrp.add_argument("-t1id","--tier1-id", required=False, help= "If applicable, the ID of the Tier1 gateway the network should be connected to.")
vmnetgrp.add_argument("-t1t", "--t1type", choices=["ROUTED", "ISOLATED", "NATTED"], required=False, help= "Type of Tier1 router to create.")
# vmnetgrp.add_argument("-xtid", "--ext-tunnel-id",required=False, help= "ID of the extended tunnel.")

idsprofilegrp = ap.add_argument_group('IDS Profile Creation', "Options to buiid and IDS Profile.  The more restrictive the profile the better")
idsprofilegrp.add_argument("-pa", "--product_affected", required=False, nargs='+', help="This is the product affected for the IDS Profile.  To determine the product affected syntax, use the 'search-product-affected' function.")
idsprofilegrp.add_argument("-cvss", "--cvss", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], required=False, nargs='+', help="Choose a CVSS category to limit your IDS profile")

idsrulegrp = ap.add_argument_group('IDS Rule Creation', 'Options to build an IDS Rule.  Source and desitination inventory groups as well as IDS Policy are required for this function')
idsrulegrp.add_argument("-act", "--action", required=False, choices=['DETECT', 'DETECT_PREVENT'], default='DETECT', help="Choose whether this rule will just detect the intrusion or prevent the instrusion")
idsrulegrp.add_argument("-sg", "--source-group", required=False, default='ANY', nargs='*', help='Source inventory group')
idsrulegrp.add_argument("-dg", "--dest-group", required=False, default='ANY', nargs='*', help='Destination inventory group')
idsrulegrp.add_argument('-ipol', '--ids-policy', required=False, nargs=1, help='The IDS Policy this rule will be created under')
idsrulegrp.add_argument('-scp', '--scope', required=False, default='ANY', nargs='*', help='Determines where the IDS rule is applied.  Default is to apply across the entire DFW, but can be specific to a Inventory Group')
idsrulegrp.add_argument('-srv', '--services', required=False, default='ANY', nargs='*', help='Services this IDS rules is applied against.  Default is ANY.')
idsrulegrp.add_argument('-ipro', '--ids-profile', required=False, nargs=1, help='The IDS Profile to evaluate against. Required argument.')


args, unknown = ap.parse_known_args()


# ============================
# CSP - Services
# ============================


if intent_name == "show-csp-services":
    getServiceDefinitions(strCSPProdURL, ORG_ID, session_token)

# ============================
# CSP - User and Group Management
# ============================

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
elif intent_name == "show-org-users":
    showORGusers(ORG_ID, session_token)


# ============================
# SDDC - AWS Account and VPC
# ============================


elif intent_name == "set-sddc-connected-services":
    value = sys.argv[2]
    if setSDDCConnectedServices(proxy,session_token,value) == 200 and value == 'true':
        print("S3 access from the SDDC is over the ENI.")
    elif setSDDCConnectedServices(proxy,session_token,value) == 200 and value == 'false':
        print("S3 access from the SDDC is over the Internet.")
    else:
        print("Make sure you use a 'true' or 'false' parameter")
elif intent_name == "show-compatible-subnets":
    n = (len(sys.argv))
    if ( n < 4):
        print("Usage: show-compatible-subnets linkedAccountId region")
    else:
        getCompatibleSubnets(ORG_ID,session_token,sys.argv[2],sys.argv[3])
elif intent_name == "show-connected-accounts":
    getConnectedAccounts(ORG_ID,session_token)
elif intent_name == "show-sddc-connected-vpc":
    print(getSDDCConnectedVPC(proxy,session_token))
elif intent_name == "show-shadow-account":
    print("The SDDC is deployed in the " + str(getSDDCShadowAccount(proxy,session_token)) + " AWS Shadow Account.")
elif intent_name == "get-access-token":
    print(session_token)


# ============================
# SDDC - SDDC
# ============================


elif intent_name == "show-sddc-state":
    getSDDCState(ORG_ID, SDDC_ID, session_token)
elif intent_name == "show-sddcs":
    getSDDCS(ORG_ID, session_token)
elif intent_name == "show-vms":
    print(getVMs(proxy,session_token))
elif intent_name == "show-sddc-hosts":
    getSDDChosts(SDDC_ID, ORG_ID, session_token)


# ============================
# SDDC - TKG
# ============================


elif intent_name == "enable-tkg":
    cluster_id = get_cluster_id(ORG_ID, SDDC_ID, session_token)
    print("    Validating Cluster: " + cluster_id)
    task_id = validate_cluster(ORG_ID, SDDC_ID, cluster_id, session_token)
    get_task_status(task_id, ORG_ID, session_token)
    print("    Validating Network:")
    print("        Egress CIDR:    " + egress_CIDR)
    print("        Ingress CIDR:   " + ingress_CIDR)
    print("        Namespace CIDR: " + namespace_CIDR)
    print("        Service CIDR:   " + service_CIDR)
    task_id = validate_network(ORG_ID, SDDC_ID, cluster_id, session_token)
    get_task_status(task_id, ORG_ID, session_token)
    print("    Enabling TKG:")
    task_id = enable_wcp(ORG_ID, SDDC_ID, cluster_id, session_token)
    get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "disable-tkg":
    cluster_id = get_cluster_id(ORG_ID, SDDC_ID, session_token)
    print("    Disabling TKG:")
    task_id = disable_wcp(ORG_ID, SDDC_ID, cluster_id, session_token)
    get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "get-tkg-info":
    # The API for this command is broken, waiting for a fix to enable it
    print("    TKG info:")
    cluster_id = get_cluster_id(ORG_ID, SDDC_ID, session_token)
    get_tkg_info(ORG_ID, cluster_id, session_token)


# ============================
# VTC - AWS Operations
# ============================


elif intent_name == "connect-aws":
    print("=====Connecting AWS account=========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    task_id = connect_aws_account(aws_acc, region, resource_id, ORG_ID, session_token)
    if task_id:
        get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "disconnect-aws":
    print("===== Disconnecting AWS account =========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    task_id = disconnect_aws_account(aws_acc, resource_id, ORG_ID, session_token)
    if task_id:
        get_task_status(task_id, ORG_ID, session_token)


# ============================
# VTC - DXGW Operations
# ============================


elif intent_name == "attach-dxgw":
    print("===== Add DXGW Association =========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    routes = input ('   Enter route(s) to add (space separated): ')
    user_list = routes.split()
    task_id = attach_dxgw(user_list, resource_id, ORG_ID, dxgw_owner, dxgw_id, region, session_token)
    get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "detach-dxgw":
    print("===== Remove DXGW Association =========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    task_id = detach_dxgw(resource_id, ORG_ID, dxgw_id, session_token)
    get_task_status(task_id, ORG_ID, session_token)


# ============================
# VTC - SDDC Operations
# ============================


elif intent_name == "attach-sddc":
    print("===== Connecting SDDC =========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    get_deployments(ORG_ID, session_token)
    sddc = input('   Select one SDDC to attach: ')
    deployment_id = get_deployment_id(sddc, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    task_id = attach_sddc(deployment_id, resource_id, ORG_ID, session_token)
    get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "detach-sddc":
    print("===== Removing SDDC =========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    get_deployments(ORG_ID, session_token)
    sddc = input('   Select one SDDC to detach: ')
    deployment_id = get_deployment_id(sddc, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    task_id = remove_sddc(deployment_id, resource_id, ORG_ID, session_token)
    get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "get-nsx-info":
    print("===== get deployments =========")
    get_deployments(ORG_ID, session_token)
    sddc = input('   Select SDDC: ')
    deployment_id = get_deployment_id(sddc, ORG_ID, session_token)
    get_nsx_info( ORG_ID, deployment_id, session_token)

elif intent_name == "get-sddc-info":
    print("===== SDDC Info =========")
    get_deployments(ORG_ID, session_token)


# ============================
# VTC - SDDC-Group Operations
# ============================


elif intent_name == "create-sddc-group":
    if len(sys.argv) != 3:
        print("Incorrect syntax. Please provide the name of the new SDDC.")
    else:
        print("\n=====Creating SDDC Group=========")
        group_name = sys.argv[2]
        get_deployments(ORG_ID, session_token)
        sddc = input('   Select one SDDC to attach: ')
        deployment_id = get_deployment_id(sddc, ORG_ID, session_token)
        task_id = create_sddc_group(group_name, deployment_id, ORG_ID, session_token)
        get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "delete-sddc-group":
    print("===== SDDC Group info =========")
    group_exists = get_sddc_groups( ORG_ID, session_token)
    print("=====Deleting SDDC Group=========")
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    if (check_empty_group(group_id, ORG_ID, session_token)):
        resource_id = get_resource_id(group_id, ORG_ID, session_token)
        task_id = delete_sddc_group(resource_id, ORG_ID, session_token)
        get_task_status(task_id, ORG_ID, session_token)
    else:
        print("SDDC Group not empty: detach all members")

elif intent_name == "get-group-info":
    print("===== SDDC Group info =========")
    group_exists = get_sddc_groups( ORG_ID, session_token)
    if group_exists:
        group = input('   Select SDDC Group: ')
        group_id = get_group_id(group, ORG_ID, session_token)
        resource_id = get_resource_id(group_id, ORG_ID, session_token)
        get_group_info(group_id, resource_id, ORG_ID, session_token)


# ============================
# VTC - TGW Operations
# ============================


elif intent_name == "show-tgw-routes":
    print("===== Show TGW route tables =========")
    #get_sddc_groups( ORG_ID, session_token)
    sddc_groups = get_sddc_groups( ORG_ID, session_token)
    group_id = None
    if DEBUG_MODE:
        print(f'DEBUG: sddc_groups = {sddc_groups}')
    if len(sys.argv) > 2:
        search_name = sys.argv[2]
        for grp in sddc_groups:
            if grp['name'] == search_name:
                group_id = grp['id']
                group_name = search_name
                if DEBUG_MODE:
                    print(f'DEBUG: Found {search_name} with group ID {group_id}')
                break
    else:
        group = input('   Select SDDC Group: ')
        group_id = sddc_groups[int(group) -1]['id']
        group_name = sddc_groups[int(group) -1]['name']
        if DEBUG_MODE:
            print(f'DEBUG: User input group = {group}')
            print(f'DEBUG: group_id from sddc_groups = {group_id}')
    #group_id = get_group_id(group, ORG_ID, session_token)
    if group_id is None:
        print('Could not retrieve group ID')
    else:
        resource_id = get_resource_id(group_id, ORG_ID, session_token)
        print(f'Route table for {group_name} ({group_id})')
        get_route_tables(resource_id, ORG_ID, session_token)


# ============================
# VTC - VPC Operations
# ============================


elif intent_name == "attach-vpc":
    print("=====Attaching VPCs=========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    vpc_list = get_pending_att(resource_id, ORG_ID, session_token)
    if vpc_list == []:
        print('   No VPC to attach')
    else:
        n = input('   Select VPC to attach: ')
        task_id = attach_vpc(vpc_list[int(n)-1], resource_id, ORG_ID, aws_acc, session_token)
        if task_id:
            get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "detach-vpc":
    print("=====Detaching VPCs=========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    vpc_list = get_available_att(resource_id, ORG_ID, session_token)
    if vpc_list == []:
        print('   No VPC to detach')
    else:
        n = input('  Select VPC to detach: ')
        task_id = detach_vpc(vpc_list[int(n)-1], resource_id, ORG_ID, aws_acc, session_token)
        if task_id:
            get_task_status(task_id, ORG_ID, session_token)

elif intent_name == "vpc-prefixes":
    print("===== Adding/Removing VPC Static Routes =========")
    get_sddc_groups( ORG_ID, session_token)
    group = input('   Select SDDC Group: ')
    group_id = get_group_id(group, ORG_ID, session_token)
    resource_id = get_resource_id(group_id, ORG_ID, session_token)
    vpc_list = get_available_att(resource_id, ORG_ID, session_token)
    if vpc_list == []:
        print('   No VPC attached')
    else:
        n = input('   Select VPC: ')
        routes = input ('   Enter route(s) to add (space separated), or press Enter to remove all: ')
        user_list = routes.split()
        task_id = add_vpc_prefixes(user_list, vpc_list[int(n)-1], resource_id, ORG_ID, aws_acc, session_token)
        get_task_status(task_id, ORG_ID, session_token)

# ============================
# NSX-T - Search
# ============================


elif intent_name == "search-nsx":
    if len(sys.argv) == 4:
        object_type = sys.argv[2]
        object_id = sys.argv[3]
        search_nsx(proxy, session_token, object_type, object_id)
    elif len(sys.argv) == 3:
        object_type = sys.argv[2]
        object_id = "NULL"
        search_nsx(proxy, session_token, object_type, object_id)
    else:
        print("Invalid syntax.  Please provide object type to search by as an argument; optionally provide the object id / display name.")
        print("Currently supported object types are as follows:")
        print("    BgpNeighborConfig")
        print("    BgpRoutingConfig")
        print("    Group")
        print("    IdsSignature")
        print("    PrefixList")
        print("    RouteBasedIPSecVPNSession")
        print("    Segment")
        print("    Service")
        print("    StaticRoute")
        print("    Tier0")
        print("    Tier1")
        print("    VirtualMachine")
        print("    VirtualNetworkInterface")
        print("")
        print("A full list may be found in the NSX-T API documentation here: https://developer.vmware.com/apis/1248/nsx-t")

# ============================
# NSX-T - Advanced Firewall
# ============================


elif intent_name == "show-nsxaf-status":
    getNSXAFAddOn(ORG_ID, SDDC_ID, session_token)

elif intent_name == "show-ids-cluster-status":
    getNsxIdsEnabledClusters(proxy, session_token)

elif intent_name == "enable-cluster-ids":
    cluster_id = sys.argv[2]
    enableNsxIdsCluster (proxy, session_token, cluster_id)

elif intent_name == "disable-cluster-ids":
    cluster_id = sys.argv[2]
    disableNsxIdsCluster (proxy, session_token, cluster_id)

elif intent_name == "enable-all-cluster-ids":
    enableNsxIdsAll (proxy, session_token)

elif intent_name == "disable-all-cluster-ids":
    disableNsxIdsAll (proxy, session_token)

elif intent_name == "enable-ids-auto-update":
    enableNsxIdsAutoUpdate (proxy, session_token)

elif intent_name == "ids-update-signatures":
    NsxIdsUpdateSignatures (proxy, session_token)

elif intent_name == "show-ids-signature-versions":
    getNsxIdsSigVersions (proxy, session_token)

elif intent_name == "show-ids-profiles":
    getIdsProfiles (proxy, session_token)

elif intent_name == "search-product-affected":
    search_ids_signatures_product_affected(proxy, session_token)

elif intent_name == "show-ids-policies":
    listIdsPolicies (proxy, session_token)

elif intent_name == "create-ids-profile":
    create_ids_profile(**vars(args))

elif intent_name == "create-ids-policy":
    create_ids_policy(**vars(args))

elif intent_name == "show-ids-rules":
    get_ids_rules()

elif intent_name == "create-ids-rule":
    create_ids_rule(**vars(args))


# ============================
# NSX-T - BGP and Routing
# ============================


elif intent_name == "attach-t0-prefix-list":
    neighbor_id = sys.argv[2]
    attachT0BGPprefixlist(proxy, session_token, neighbor_id)
elif intent_name == "detach-t0-prefix-lists":
    neighbor_id = sys.argv[2]
    detachT0BGPprefixlists(proxy, session_token, neighbor_id)
elif intent_name == "new-t0-prefix-list":
    newBGPprefixlist(proxy, session_token)
elif intent_name == "remove-t0-prefix-list":
    prefixlists = getSDDCT0PrefixLists(proxy, session_token)
    prefix_list_id = sys.argv[2]
    remove_bgp_prefix_list_json(proxy, session_token, prefix_list_id)
    print("The BGP prefix list " + prefix_list_id + " has been deleted")
elif intent_name == "set-sddc-bgp-as":
    if len(sys.argv) != 3:
        print("Incorrect syntax.")
    else:
        asn = sys.argv[2]
        setSDDCBGPAS(proxy,session_token,asn)
elif intent_name == "set-mtu":
    if len(sys.argv) != 3:
        print("Incorrect syntax.")
    mtu = sys.argv[2]
    if int(mtu) < 1500 or int(mtu) > 8900:
        print("Incorrect syntax. The MTU should be between 1500 and 8900 bytes.")
    else:
        setSDDCMTU(proxy,session_token,mtu)
elif intent_name == "show-egress-interface-counters":
    edge_cluster_id = getSDDCEdgeCluster(proxy, session_token)
    edge_path_0 = getSDDCEdgeNodes(proxy, session_token, edge_cluster_id, 0)
    edge_path_1 = getSDDCEdgeNodes(proxy, session_token, edge_cluster_id, 1)
    stat_0 = getSDDCInternetStats(proxy,session_token, edge_path_0)
    stat_1 = getSDDCInternetStats(proxy,session_token, edge_path_1)
    total_stat = stat_0 + stat_1
    print("Current Total Bytes count on Internet interface is " + str(total_stat) + " Bytes.")
elif intent_name == "show-mtu":
    getSDDCMTU(proxy,session_token)
elif intent_name == "show-sddc-bgp-as":
    getSDDCBGPAS(proxy,session_token)
elif intent_name == "show-sddc-bgp-vpn":
    print(getSDDCBGPVPN(proxy,session_token))
elif intent_name == "show-t0-bgp-neighbors":
    getSDDCT0BGPneighbors(proxy, session_token)
elif intent_name == "show-t0-bgp-routes":
    getSDDCT0BGPRoutes(proxy, session_token)
elif intent_name == "show-t0-prefix-lists":
    getSDDCT0PrefixLists(proxy, session_token)
elif intent_name == "show-t0-routes":
    getSDDCT0routes(proxy,session_token)
elif intent_name == "show-t0-static-routes":
    getSDDCT0staticroutes(proxy,session_token)


# ============================
# NSX-T - DNS
# ============================


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
elif intent_name == "show-dns-zones":
    print(getSDDCDNS_Zones(proxy,session_token))


# ============================
# NSX-T - Firewall - Gateway
# ============================


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
        # Commented out 2022-01-03 - unclear why the upper() function is used here, but it breaks for any rule with a group that is in lowercase.
        # sg_string = sg_string.upper()
        sg_list = sg_string.split(",")
        source_groups = [group_index + x for x in sg_list]

    # String and List Manipulation:
    # We take the input argument (NSX-MANAGER or VCENTER or ESXI nodes)

    if dg_string.lower() == "any":
        destination_groups = ["ANY"]
    else:
        # Commented out 2022-01-03 - unclear why the upper() function is used here, but it breaks for any rule with a group that is in lowercase.
        # dg_string = dg_string.upper()
        dg_list = dg_string.split(",")
        destination_groups = [group_index + x for x in dg_list]

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
        new_rule = newSDDCMGWRule(proxy, session_token, display_name, source_groups, destination_groups, services,
                                  action, sequence_number)
        print(new_rule)
    else:
        new_rule = newSDDCMGWRule(proxy, session_token, display_name, source_groups, destination_groups, services,
                                  action, sequence_number)
    if new_rule == 200:
        print("\n The rule has been created.")
        print(getSDDCMGWRule(proxy, session_token))
        print(new_rule)
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
elif intent_name == "show-cgw-rule":
    print(getSDDCCGWRule(proxy, session_token))
elif intent_name == "show-mgw-rule":
    print(getSDDCMGWRule(proxy, session_token))


# ============================
# NSX-T - Firewall - Distributed
# ============================


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
elif intent_name == "remove-dfw-rule":
    if len(sys.argv) != 4:
        print("Incorrect syntax. ")
    else:
        section_id = sys.argv[2]
        rule_id = sys.argv[3]
        if delete_sddc_dfw_rule_json(proxy, session_token, section_id, rule_id) == 200:
            print("The rule " + rule_id + " has been deleted")
            print(getSDDCDFWRule(proxy,session_token, section_id))
        else :
            print("Issues deleting the security rule. Check the syntax.")
elif intent_name == "remove-dfw-section":
    if len(sys.argv) != 3:
        print("Incorrect syntax. ")
    else:
        section_id = sys.argv[2]
        if delete_sddc_dfw_section_json(proxy, session_token, section_id) == 200:
            print("The section " + section_id + " has been deleted.")
            print(getSDDCDFWSection(proxy,session_token))
        else :
            print("Issues deleting the DFW section. Check the syntax.")
elif intent_name == "show-dfw-section":
    print(getSDDCDFWSection(proxy, session_token))
elif intent_name == "show-dfw-section-rules":
    if len(sys.argv) == 2:
        print("Incorrect syntax. Specify the section name.")
    if len(sys.argv) == 3:
        section = sys.argv[2]
        print(getSDDCDFWRule(proxy, session_token,section))


# ============================
# NSX-T - Firewall Services
# ============================


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
elif intent_name == "remove-service":
    if len(sys.argv) > 3:
        print("This command did not work. Follow the instructions")
    else:
        service_id = sys.argv[2]
        sddc_service_delete = removeSDDCService(proxy,session_token,service_id)
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


# ============================
# NSX-T - Inventory Groups
# ============================


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
elif intent_name == "remove-group":
    if len(sys.argv) != 4:
        print("This command did not work. Follow the instructions")
    else:
        gw = sys.argv[2].lower()
        group_id = sys.argv[3]
        sddc_group_delete = removeSDDCGroup(proxy,session_token,gw,group_id)
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


# ============================
# NSX-T - NAT
# ============================


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
            logging = False
        if len(sys.argv) >= 8:
            status = sys.argv[7]
        else:
            status = True
        newSDDCNAT(proxy, session_token, display_name, action, translated_network, source_network, service, translated_port, logging, status)
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
        newSDDCNAT(proxy, session_token, display_name, action, translated_network, source_network, service, translated_port, logging, status)
    else:
        print("There was an error. Make sure you follow the instructions.")
elif intent_name == "remove-nat-rule":
    if len(sys.argv) == 3:
        id = sys.argv[2]
        result = remove_sddc_nat_json(proxy, session_token, id)
        print(result)
        print("\n")
        print(getSDDCNAT(proxy, session_token))
    else:
        print("Incorrect syntax. Try again or check the help.")
elif intent_name == "show-nat":
    if len(sys.argv) == 2:
        print(getSDDCNAT(proxy, session_token))
    elif len(sys.argv) == 3:
        NATid = sys.argv[2]
        NATStats = getSDDCNATStatistics(proxy,session_token,NATid)
        print(NATStats)
    else:
        print("Incorrect syntax. Try again or check the help.")


# ============================
# NSX-T - Public IP Addressing
# ============================


elif intent_name == "new-sddc-public-ip":
    if len(sys.argv) != 3:
        print("Incorrect syntax. Please add a description of the public IP address.")
    else :
        notes = sys.argv[2]
        if newSDDCPublicIP(proxy, session_token, notes) == 200:
            print(getSDDCPublicIP(proxy,session_token))
        else :
            print("Issues creating a Public IP.")
elif intent_name == "remove-sddc-public-ip":
    if len(sys.argv) != 3:
        print("Incorrect syntax. ")
    else:
        public_ip = sys.argv[2]
        if delete_sddc_public_ip_json(proxy, session_token, public_ip) == 200:
            print(getSDDCPublicIP(proxy,session_token))
        else :
            print("Issues deleting the Public IP. Check the syntax.")
elif intent_name == "set-sddc-public-ip":
    if len(sys.argv) != 4:
        print("Incorrect syntax. Please add the new description of the public IP address.")
    else:
        public_ip = sys.argv[2]
        notes = sys.argv[3]
        if setSDDCPublicIP(proxy, session_token, notes, public_ip) == 200:
            print(getSDDCPublicIP(proxy,session_token))
        else :
            print("Issues updating a Public IP. Check the syntax.")
elif intent_name == "show-sddc-public-ip":
    print(getSDDCPublicIP(proxy,session_token))


# ============================
# NSX-T - Segments
# ============================

elif intent_name == "configure-t1":
    configure_t1(**vars(args))
elif intent_name == "remove-t1":
    remove_t1(**vars(args))
elif intent_name == "new-segment":
    new_segment(**vars(args))
elif intent_name == "configure-segment":
    configure_segment(**vars(args))
elif intent_name == "remove-segment":
    remove_segment(**vars(args))
elif intent_name == "new-network":
    if sys.argv[3].lower() == "routed" and len(sys.argv) == 7:
        # DHCP-Enabled Network
        display_name = sys.argv[2]
        routing_type = "ROUTED"
        gateway_address = sys.argv[4]
        dhcp_range = sys.argv[5]
        domain_name = sys.argv[6]
    elif sys.argv[3].lower() == "disconnected" :
        # Disconnected Network
        display_name = sys.argv[2]
        routing_type = "DISCONNECTED"
        gateway_address = sys.argv[4]
        dhcp_range = ""
        domain_name = ""
    elif sys.argv[3].lower() == "routed" and len(sys.argv) == 5:
        # Static Network
        display_name = sys.argv[2]
        gateway_address = sys.argv[4]
        dhcp_range = ""
        domain_name = ""
        routing_type = "ROUTED"
    elif sys.argv[3].lower() == "extended":
        display_name = sys.argv[2]
        tunnel_id = sys.argv[4]
        l2vpn_path = getSDDCL2VPNSessionPath(proxy,session_token)
        print(newSDDCStretchednetworks(proxy,session_token,display_name,tunnel_id, l2vpn_path))
    else:
        print("Incorrect syntax. Try again or check the help.")
    newSDDC = newSDDCnetworks(proxy, session_token, display_name, gateway_address, dhcp_range, domain_name, routing_type)
    print(newSDDC)
elif intent_name == "remove-network":
    network_id = sys.argv[2]
    removeSDDCNetworks(proxy, session_token,network_id)
elif intent_name == "show-network":
    getSDDCnetworks(proxy, session_token)
elif intent_name == "connect-segment":
    network_id = sys.argv[2]
    if len(sys.argv) == 6:
        # DHCP-Enabled Network
        gateway_address = sys.argv[3]
        dhcp_range = sys.argv[4]
        domain_name = sys.argv[5]
    elif len(sys.argv) == 4:
        # Static Network
        gateway_address = sys.argv[3]
        dhcp_range = ""
        domain_name = ""
    else:
        print("Incorrect syntax. Try again or check the help.")    
    connect_segment(proxy, session_token, network_id, gateway_address, dhcp_range, domain_name)
elif intent_name == "disconnect-segment":
    network_id = sys.argv[2]
    disconnect_segment(proxy, session_token, network_id)
elif intent_name == "create-lots-networks":
    number = int(sys.argv[2])
    createLotsNetworks(proxy,session_token,number)


# ============================
# NSX-T - VPN
# ============================


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
elif intent_name == "remove-l2vpn":
    id = sys.argv[2]
    status_code = delete_l2vpn_json(proxy, session_token, id)
    if status_code == 200:
        print(f'L2 VPN with ID {id} has been deleted successfully')
elif intent_name == "new-vpn":
    vpn_name = input("Enter the VPN Name: ")
    remote_private_ip = input('Enter the remote private IP:')
    remote_public_ip = input('Enter the remote public IP:')
    source_networks = input('Enter your source networks, separated by commas (for example: 192.168.10.0/24,192.168.20.0/24)')
    destination_networks = input('Enter your destination networks, separated by commas (for example: 192.168.10.0/24,192.168.20.0/24)')
    print(vpn_name + remote_private_ip + remote_public_ip)
elif intent_name == "remove-vpn":
    id = sys.argv[2]
    status_code = delete_ipsec_vpn_json(proxy, session_token, id)
    if status_code == 200:
        print(f'IPSEC VPN with ID {id} has been deleted successfully')
elif intent_name == "remove-vpn-ike-profile":
    id = sys.argv[2]
    status_code = delete_ipsec_vpn_ike_profile_json(proxy, session_token, id)
    if status_code == 200:
        print(f'VPN IKE Profile {id} has been deleted successfully')
elif intent_name == "remove-vpn-ipsec-tunnel-profile":
    id = sys.argv[2]
    status_code = delete_ipsec_vpn_profile_json(proxy, session_token, id)
    if status_code == 200:
        print(f'IPSEC VPN Profile {id} has been removed successufully')
elif intent_name == "show-l2vpn":
    l2vpn = getSDDCL2VPNSession(proxy, session_token)
    print(l2vpn)
elif intent_name == "show-l2vpn-services":
    l2vpn = getSDDCL2VPNServices(proxy, session_token)
    print(l2vpn)
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
elif intent_name == "show-vpn-ike-profile":
    vpn_ipsec_profile = getSDDCVPNIpsecProfiles(proxy, session_token)
    print(vpn_ipsec_profile)
elif intent_name == "show-vpn-internet-ip":
    getSDDCVPNInternetIP(proxy, session_token)
elif intent_name == "show-vpn-ipsec-endpoints":
    vpn_ipsec_endpoints = getSDDCVPNIpsecEndpoints(proxy, session_token)
    print(vpn_ipsec_endpoints)
elif intent_name == "show-vpn-ipsec-tunnel-profile":
    vpn_ipsec_tunnel_profile = getSDDCVPNIpsecTunnelProfiles(proxy, session_token)
    print(vpn_ipsec_tunnel_profile)
elif intent_name == "show-vpn-detailed":
    if len(sys.argv) == 3:
        VPN_ID = sys.argv[2]
        SDDC_VPN_SERVICES = getSDDCVPNServices(proxy,session_token,VPN_ID)
        print(SDDC_VPN_SERVICES)
    else:
        print("Incorrect syntax. Check the help.")

# elif intent_name == "new-service-entry":
#    print("This is WIP")

# ============================
# VCDR - Cloud File System
# ============================
elif intent_name == "show-vcdr-fs":
    """Get a list of all deployed cloud file systems in your VMware Cloud DR organization."""
    getVCDRCloudFS(strVCDRProdURL, session_token)

elif intent_name == "show-vcdr-fs-details":
    """Get details for an individual cloud file system."""
    cloud_fs_id = sys.argv[2]
    getVCDRCloudFSDetails(strVCDRProdURL, cloud_fs_id, session_token)

# ============================
# VCDR - Protected Sites
# ============================
elif intent_name == "show-vcdr-sites":
    """Get a list of all protected sites associated with an individual cloud file system."""
    cloud_fs_id = sys.argv[2]
    getVCDRSites(strVCDRProdURL, cloud_fs_id, session_token)

elif intent_name == "show-vcdr-site-details":
    """Get details about an individual protected site."""
    cloud_fs_id = sys.argv[2]
    site_id = sys.argv[3]
    getVCDRSiteDetails(strVCDRProdURL, cloud_fs_id, site_id, session_token)

# ============================
# VCDR - Protected VM
# ============================
elif intent_name == "show-vcdr-vm":
    """Get a list of all protected VMs currently being replicated to the specified cloud file system."""
    cloud_fs_id = sys.argv[2]
    getVCDRVM(strVCDRProdURL, cloud_fs_id, session_token)

# ============================
# VCDR - Protection Groups
# ============================
elif intent_name == "show-vcdr-pgs":
    """Get a list of all protection groups associated with an individual cloud file system."""
    cloud_fs_id = sys.argv[2]
    getVCDRPG(strVCDRProdURL, cloud_fs_id, session_token)

elif intent_name == "show-vcdr-pg-details":
    """Get details for the requested protection group."""
    cloud_fs_id = sys.argv[2]
    pg_id = sys.argv[3]
    getVCDRPGDetails(strVCDRProdURL, cloud_fs_id, pg_id, session_token)

# ============================
# VCDR - Protection Group Snapshots
# ============================
elif intent_name == "show-vcdr-pg-snaps":
    """Get a list of all snapshots in a specific protection group."""
    cloud_fs_id = sys.argv[2]
    pg_id = sys.argv[3]
    getVCDRPGSnaps(strVCDRProdURL, cloud_fs_id, pg_id, session_token)

elif intent_name == "show-vcdr-pg-snap-details":
    """Get a list of all snapshots in a specific protection group."""
    cloud_fs_id = sys.argv[2]
    pg_id = sys.argv[3]
    snap_id = sys.argv[4]
    getVCDRSnapDetails(strVCDRProdURL, cloud_fs_id, pg_id, snap_id, session_token)

# ============================
# VCDR - Recovery SDDC
# ============================
elif intent_name == "show-vcdr-sddcs":
    """List VMware Cloud (VMC) Recovery Software-Defined Datacenters (SDDCs)."""
    getVCDRSDDCs(strVCDRProdURL, session_token)

elif intent_name == "show-vcdr-sddc-details":
    """Get details of a specific Recovery SDDC."""
    sddc_id = sys.argv[2]
    getVCDRSDDCDetails(strVCDRProdURL, sddc_id, session_token)

# ============================
# Help
# ============================
elif intent_name == "help":
    getHelp()
else:
    getHelp()
    