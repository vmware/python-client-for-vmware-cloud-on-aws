# VMC on AWS Python library for PyVMC

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import json
import requests


# ============================
# AWS Account and VPC
# ============================


def get_compatible_subnets_json(strProdURL, orgID, sessiontoken, linkedAWSID, region):
    """Returns all compatible subnets for linking in selected AWS Account and AWS Region"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/account-link/compatible-subnets" 
    params = {'linkedAccountId': linkedAWSID,'region': region}
    response = requests.get(myURL, headers=myHeader, params=params)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code} : {response.reason} URL: {myURL}.')
        if 'error_message' in json_response.keys():
           print(json_response['error_message'])
        if 'error_messages' in json_response.keys():
            if len(json_response['error_messages']) > 0:
                print(f"Error Message: {json_response['error_messages'][0]}")
        return None


def get_connected_accounts_json(strProdURL, orgID, sessiontoken):
    """ Returns all connected AWS accounts in json format """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/account-link/connected-accounts"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        if "error_message" in json_response.keys():
            print(json_response['error_message'])


# ============================
# SDDC
# ============================


def get_sddcs_json(strProdURL, orgID, sessiontoken):
    """Returns list of all SDDCs in an Org via json"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])
        return None


def get_sddc_info_json (strProdURL, orgID, sessiontoken, sddcID):
    """Returns SDDC info in JSON format"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs/{sddcID}"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])
        return None


# ============================
# TKG
# ============================


# ============================
# VTC - AWS Operations
# ============================
def connect_aws_account_json(strProdURL, account, region, resource_id, org_id, session_token):
    """Connect an vTGW to an AWS account"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    body = {
    "type": "ADD_EXTERNAL_ACCOUNT",
    "resource_id": resource_id,
    "resource_type": "network-connectivity-config",
    "config" : {
            "type": "AwsAddExternalAccountConfig",
            "account" : {
                "account_number": account,
                "regions" : [region],
                "auto_approval": "true"
            }
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    return response

def disconnect_aws_account_json(strProdURL, account, resource_id, org_id, session_token):
    """Disconnect a vTGW from an AWS account"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    body = {
    "type": "REMOVE_EXTERNAL_ACCOUNT",
    "resource_id": resource_id,
    "resource_type": "network-connectivity-config",
    "config" : {
            "type": "AwsRemoveExternalAccountConfig",
            "policy_id": resource_id,
            "account" : {
                # "account_id": "1ec4c61b-3bfe-697c-8756-0b3a226bb42f",
                "account_number": account
            }
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    return response


# ============================
# VTC - DXGW Operations
# ============================
def attach_dxgw_json(strProdURL, routes, resource_id, org_id, dxgw_owner, dxgw_id, region, session_token):
    """Attach a Direct Connect Gateway to a vTGW"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    body = {
        "type": "ASSOCIATE_DIRECT_CONNECT_GATEWAY",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
   	    "config" : {
            "type": "AwsAssociateDirectConnectGatewayConfig",
		    "direct_connect_gateway_association": {
			    "direct_connect_gateway_id": dxgw_id,
			    "direct_connect_gateway_owner": dxgw_owner,
                "peering_region_configs": [
				    {
					"allowed_prefixes": routes,
                    "region": region
				    }
			    ]
		    }
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    json_response = response.json()
    if response.status_code == 201:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def detach_dxgw_json(strProdURL, resource_id, org_id, dxgw_id, session_token):
    """Detach a Direct Connect Gateway from a vTGW"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    body = {
        "type": "DISASSOCIATE_DIRECT_CONNECT_GATEWAY",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
   	    "config" : {
            "type": "AwsDisassociateDirectConnectGatewayConfig",
		    "direct_connect_gateway_association": {
			    "direct_connect_gateway_id": dxgw_id
		    }
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    json_response = response.json()
    if response.status_code == 201:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(response)

# ============================
# VTC - SDDC Operations
# ============================
def attach_sddc_json(strProdURL, deployment_id, resource_id, org_id, session_token):
    """Attach an SDDC to a vTGW"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    body = {
        "type": "UPDATE_MEMBERS",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
            "type": "AwsUpdateDeploymentGroupMembersConfig",
            "add_members": [
                {
                 "id": deployment_id
                }
            ],
            "remove_members": []
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    return response


def remove_sddc_json(strProdURL, deployment_id, resource_id, org_id, session_token):
    """Detach an SDDC from a vTGW"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    body = {
        "type": "UPDATE_MEMBERS",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
            "type": "AwsUpdateDeploymentGroupMembersConfig",
            "add_members": [],
            "remove_members": [
                {
                 "id": deployment_id
                }
            ]
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    return response

def get_nsx_info_json( strProdURL, org_id, deployment_id, session_token):
    """Display NSX credentials and URLs"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/deployments/{}/nsx".format(strProdURL, org_id, deployment_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def get_deployment_id_json(strProdURL, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/inventory/{}/core/deployments".format(strProdURL, org_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def get_deployments_json(strProdURL,org_id, session_token):
    """Display a list of all SDDCs"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/inventory/{}/core/deployments".format(strProdURL, org_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def get_group_id_json(strProdURL, group, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/inventory/{}/core/deployment-groups".format(strProdURL, org_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def get_resource_id_json(strProdURL, org_id, group_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/?group_id={}".format(strProdURL, org_id, group_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def get_sddc_groups_json(strProdURL, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/inventory/{}/core/deployment-groups".format(strProdURL, org_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def get_task_status_json(strProdURL,task_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/operation/{}/core/operations/{}".format(strProdURL, org_id, task_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

# ============================
# VTC - SDDC Group Operations
# ============================
def create_sddc_group_json(strProdURL, name, deployment_id, org_id, session_token):
    """Create an SDDC group"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/create-group-network-connectivity".format(strProdURL, org_id)
    body = {
        "name": name,
        "description": name,
        "members": [
            {
                "id": deployment_id
            }
        ]
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def delete_sddc_group_json(strProdURL, resource_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    body = {
        "type": "DELETE_DEPLOYMENT_GROUP",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
            "type": "AwsDeleteDeploymentGroupConfig"
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    return response

def get_group_info_json(strProdURL, org_id, group_id, session_token):
    """Display details for an SDDC group"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/inventory/{}/core/deployment-groups/{}".format(strProdURL, org_id, group_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # print(json.dumps(json_response, indent = 2))
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')

def ext_get_group_info_json(strProdURL, org_id, resource_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/{}/?trait=AwsVpcAttachmentsTrait,AwsRealizedSddcConnectivityTrait,AwsDirectConnectGatewayAssociationsTrait,AwsNetworkConnectivityTrait".format(strProdURL, org_id, resource_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # print(json.dumps(json_response, indent = 2))
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')


# ============================
# VTC - TGW Operations
# ============================
def get_route_tables_json(strProdURL, resource_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/{}/route-tables".format(strProdURL, org_id, resource_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])

def vtgw_route_json(strProdURL, org_id, resource_id, mem_ext_id,session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/{}/route-tables/{}/routes".format(strProdURL, org_id, resource_id, mem_ext_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


# ============================
# VTC - VPC Operations
# ============================
def attach_vpc_json(strProdURL, session_token, json_body, org_id):
    """Attach a VPC to a vTGW"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    response = requests.post(myURL, json=json_body, headers=myHeader)
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['id']
    return task_id

def detach_vpc_json(strProdURL, session_token, json_body, org_id):
    """Detach a VPC from a vTGW"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    response = requests.post(myURL, json=json_body, headers=myHeader)
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['id']
    return task_id

def add_vpc_prefixes_json(strProdURL, session_token, json_body, org_id):
    """Add or remove vTGW static routes"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    response = requests.post(myURL, json=json_body, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['id']
    return task_id