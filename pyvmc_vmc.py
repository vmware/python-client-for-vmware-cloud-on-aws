# VMC on AWS Python library for PyVMC

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import json
import sys
import requests

#In order to use the following function, all the functions in this file will have to be modified to use.  
def vmc_error_handling(fxn_response):
    code = fxn_response.status_code
    print (f'API call failed with status code {code}.')
    if code == 400:
        print(f'Error {code}: "Bad Request"')
        print("Request was improperly formatted or contained an invalid parameter.")
    elif code == 401:
        print(f'Error {code}: "The user is not authorized to use the API"')
        print("It's likely your refresh token is out of date or otherwise incorrect.")
    elif code == 403:
        print(f'Error {code}: "The user is forbidden to use the API"')
        print("The client does not have sufficient privileges to execute the request.")
        print("The API is likely in read-only mode, or a request was made to modify a read-only property.")
        print("It's likely your refresh token does not provide sufficient access.")
    elif code == 404:
        print(f'Error {code}: "Organization with this identifier is not found."')
        print("Please confirm the ORG ID and SDDC ID entries in your config.ini are correct.")
    elif code == 409:
        print(f'Error {code}: "The request could not be processed due to a conflict"')
        print("The request can not be performed because it conflicts with configuration on a different entity, or because another client modified the same entity.")
        print("If the conflict arose because of a conflict with a different entity, modify the conflicting configuration. If the problem is due to a concurrent update, re-fetch the resource, apply the desired update, and reissue the request.")
    elif code == 429:
        print(f'Error {code}: "The user has sent too many requests"')
    elif code == 500:
        print(f'Error {code}: "An unexpected error has occurred while processing the request"')
    elif code == 503:
        print(f'Error {code}: "Service Unavailable"')
        print("The request can not be performed because the associated resource could not be reached or is temporarily busy. Please confirm the ORG ID and SDDC ID entries in your config.ini are correct.")
    elif code == 504:
        print(f'Error {code}: "Gateway Error"')
        print("The request can not be performed because there is a problem with the network path. Check your VPN, etc.")
    else:
        print(f'Error: {code}: Unknown error')
    try:
        json_response = fxn_response.json()
        if 'message' in json_response:
            print(json_response['message'])
        if 'related_errors' in json_response:
            print("Related Errors")
            for r in json_response['related_errors']:
                print(r['error_message'])
    except:
        print("No additional information in the error response.")
    return None

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
        return None

# ============================
# SDDC
# ============================

def create_sddc_json(strProdURL, sessiontoken,orgID,name,connectedAccount,region,amount,hostType,subnetId,mgt,size,validate_only):    
    myHeader = {'csp-auth-token': sessiontoken}
    #
    # docs on data structure
    # https://developer.vmware.com/apis/vmc/v1.1/data-structures/SddcConfig/
    #
    call_data = {
        'name': name,
        'account_link_sddc_config': [
            {
                'customer_subnet_ids': [
                    subnetId
                ],
                'connected_account_id': connectedAccount
            }
        ],
        'provider': 'AWS',   # make sure provider is in upper case
        'num_hosts': amount,           # 1 host in this case
        'deployment_type' : 'SingleAZ',  # Multi-AZ for future work
        'host_instance_type' : hostType, #host type from Enumerated options.
        'sddc_type': '1NODE' if amount == 1 else "",  
        'size' : size,
        'region': region,                # region where we have permissions to deploy.
        'vpc_cidr': mgt
    }
    #
    # API Docs: https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/sddcs/post/
    #
    my_url = f'{strProdURL}/vmc/api/orgs/{orgID}/sddcs'
    if validate_only:
        my_url = my_url + "?validateOnly=true"

    resp = requests.post(my_url, json=call_data, headers=myHeader)
    
    if resp.status_code != 200:
        json_response = resp.json()

    if resp.status_code == 202:
        print(f"Create SDDC Started. Creation Task is: ")    # pull the task and print it.
        newTask = json_response['id']
        print(f'{newTask}')
        return json_response
    elif resp.status_code == 200:
        print("Create Task Complete: Input Validated")
        validated = "{'input_validated' : True}"
        return eval(validated)
    elif resp.status_code == 400:
        print(f"Error Code {resp.status_code}: Bad Request, Bad URL or Quota Violation")
        if 'error_messages' in json_response:
            print(json_response['error_messages'][0])
        return None
    elif resp.status_code == 401:
        print(f"Error Code {resp.status_code}: You are unauthorized for this operation. See your administrator")
        if 'error_messages' in json_response:
            print(json_response['error_messages'])
        return None
    elif resp.status_code == 403:
        print(f"Error Code {resp.status_code}: You are forbidden to use this operation. See your administrator")
        if 'error_messages' in json_response:
            print(json_response['error_messages'])
        return None
    else:
        print(f'Status code: {resp.status_code}: Unknown error')
        if 'error_messages' in json_response:
            print(json_response['error_messages'])
        return None
#
# https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/sddcs/sddc/delete/
#
def delete_sddc_json(strProdURL, sessiontoken, orgID, sddcID,force):
    """Returns task for the delete process, or None if error"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs/{sddcID}/"
    if force:
        myURL = myURL + "?force=true"

    response = requests.delete(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 202:
        print('Delete task created. Task ID:')
        newTask = json_response["id"]
        print(f'{newTask}')
        return json_response
    elif response.status_code == 400:
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        else:
            print('The SDDC is not in a state that is valid for deletion')
        return None
    elif response.status_code == 401:
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        else:
            print('Current user is unauthorized for this operation.')
        return None
    elif response.status_code == 403:
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
            print('Access not allowed to the operation for the current user')
        return None    
    elif response.status_code == 404:
        print("Cannot find the SDDC with given identifier")
        return None
    else:   
        print(f'Unexpected response: {response.status_code}')
        return None
#
# https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/tasks/task/get/
#
def watch_sddc_task_json(strProdURL, sessiontoken, orgID, taskid):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/tasks/{taskid}"
    response = requests.get(myURL, headers=myHeader) 
    json_response = response.json()
    if response.status_code == 200:
        # do the right thing
        return json_response
    elif response.status_code == 401:
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        else:
            print("User is unauthorized for current operation")
        return None
    elif response.status_code == 403:
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        else:
            print("User is forbidden from current action")
        return None
    elif response.status_code == 404:
        print("Cannot find the task with given identifier")
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        return None
    else:
        print('Unexpected error')
        return None
    return None
#
# https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/tasks/task/post/
#
def cancel_sddc_task_json(strProdURL, sessiontoken, orgID, taskid):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/tasks/{taskid}?action=cancel"
    response = requests.post(myURL, headers=myHeader) 
    json_response = response.json()
    if response.status_code == 200:
        print(f'Task {taskid} has been successfully cancelled.')
        return json_response
    elif response.status_code == 400:
        print("Invalid Action")
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        return None
    elif response.status_code == 401:
        print("Unauthorized for current action")
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        return None
    elif response.status_code == 403:
        print("Forbidden Action")
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        return None
    elif response.status_code == 404:
        print("Cannot find the task with given identifier")
        if 'error_messages' in json_response: 
            print(json_response["error_messages"][0])
        return None
    else:
        print(f'unexpected response {response.status_code}')
        return None

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



def get_sddcs_json(strProdURL, orgID, sessiontoken):
    """Returns list of all SDDCs in an Org via json"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        vmc_error_handling(response)

# Docs: https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/sddcs/sddc/get/
def get_sddc_info_json (strProdURL, orgID, sessiontoken, sddcID):
    """Returns SDDC info in JSON format. Returns None if error"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs/{sddcID}"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        if 'error_messages' in json_response:
            print(json_response['error_messages'])
        return None


def get_sddc_cluster1_id(vmc_url, session_token, org_id, sddc_id):
    """Returns cluster ID for given SDDC"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{vmc_url}/vmc/api/orgs/{org_id}/sddcs/{sddc_id}'
    response = requests.get(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code ==  200:
        cluster_id = json_response['resource_config']['clusters'][0]['cluster_id']
        return cluster_id
    else:
        vmc_error_handling(response)
        sys.exit(1)


# ============================
# TKG
# ============================


def tkg_validate_cluster_json(vmc_url, org_id, sddc_id, cluster_id, session_token):
    """Validates whether supplied cluster in provided SDDC can support a TKG deployment. Returns task-id"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{vmc_url}/api/wcp/v1/orgs/{org_id}/deployments/{sddc_id}/clusters/{cluster_id}/operations/validate-cluster'
    response = requests.post(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        task_id = json_response ['id']
        return task_id
    else:
        vmc_error_handling(response)
        sys.exit(1)


def get_tkg_supported_clusters_json(vmc_url, session_token, org_id, sddc_id):
    """Gets all clusters in the SDDC with valid support for TKG.  Returns Task-ID"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{vmc_url}/api/wcp/v1/orgs/{org_id}/deployments/{sddc_id}/operations/compute-supported-clusters'
    response = requests.post(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        task_id = json_response['id']
        return task_id
    else:
        vmc_error_handling(response)
        sys.exit(1)


def tkg_validate_network_json(vmc_url, session_token, org_id, sddc_id, cluster_id, json_body):
    """Validates provided network CIDRs are eligible for TKG deployment in provided cluster"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{vmc_url}/api/wcp/v1/orgs/{org_id}/deployments/{sddc_id}/clusters/{cluster_id}/operations/validate-network'
    response = requests.post(my_url, json=json_body, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        task_id = json_response ['id']
        return task_id
    else:
        vmc_error_handling(response)
        sys.exit(1)


def enable_tkg_json(vmc_url, session_token, org_id, sddc_id, cluster_id, json_body):
    """Enables TKG on selected cluster. Returns Task-ID"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{vmc_url}/api/wcp/v1/orgs/{org_id}/deployments/{sddc_id}/clusters/{cluster_id}/operations/enable-wcp'
    response = requests.post(my_url, json=json_body, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        task_id = json_response ['id']
        return task_id
    else:
        vmc_error_handling(response)
        sys.exit(1)


def disable_tkg_json(vmc_url, session_token, org_id, sddc_id, cluster_id):
    """Disables TKG on selected cluster and returns task-id"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{vmc_url}/api/wcp/v1/orgs/{org_id}/deployments/{sddc_id}/clusters/{cluster_id}/operations/disable-wcp'
    response = requests.post(my_url, headers=my_header)
    json_response = response.json()
    if response.status_code == 200:
        task_id = json_response ['id']
        return task_id
    else:
        vmc_error_handling(response)
        sys.exit(1)


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
        return None

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
        return None

# ============================
# VTC - SDDC Operations
# ============================


def config_sddc_group_json(prod_url, session_token, org_id, json_body):
    """Function to configure SDDC Group"""
    my_header = {'csp-auth-token': session_token}
    my_url = f'{prod_url}/api/network/{org_id}/aws/operations'
    response = requests.post(my_url, headers=my_header, json=json_body)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        vmc_error_handling(response)
        sys.exit(1)


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
        return None


# def get_deployment_id_json(strProdURL, org_id, session_token):
#     myHeader = {'csp-auth-token': session_token}
#     myURL = "{}/api/inventory/{}/core/deployments".format(strProdURL, org_id)
#     response = requests.get(myURL, headers=myHeader)
#     json_response = response.json()
#     if response.status_code == 200:
#         return json_response
#     else:
#         print("There was an error. Check the syntax.")
#         print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
#         print(json_response['error_message'])

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
        return None

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
        return None

def get_resource_id_json(strProdURL, org_id, sddc_group_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/?group_id={}".format(strProdURL, org_id, sddc_group_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        vmc_error_handling(response)
        sys.exit(1)

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
        return None

def get_task_status_json(strProdURL,task_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f"{strProdURL}/api/operation/{org_id}/core/operations/{task_id}"
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None


# ============================
# VTC - SDDC Group Operations
# ============================

def buildDeploymentIdList(deploymentList: list) -> list:
    '''Quick function to build up list'''
    retlist = []
    for i in deploymentList:
        d = {"id" : i}
        retlist.append(d)
    return retlist

#
#  No documentation. Use the API explorer.
#
def create_sddc_group_json(strProdURL, name, description, deployment_groups, org_id, session_token):
    """Create an SDDC group"""
    myHeader = {'csp-auth-token': session_token}
 
    myURL = f"{strProdURL}/api/network/{org_id}/core/network-connectivity-configs/create-group-network-connectivity"
    body = {
        "name": name,
        "description": description,
        "members": buildDeploymentIdList(deployment_groups)
    }
    # 
    response = requests.post(myURL, json=body, headers=myHeader)
    if response.status_code == 504:
        print("API returned with 504 error code. Check your permissions and network routes")
        return None

    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        if 'error_message' in json_response:
            print(json_response['error_message'])
        return None

def delete_sddc_group_json(strProdURL, resource_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
                
    myURL = f'{strProdURL}/api/network/{org_id}/aws/operations' 
    body = {
        "type": "DELETE_DEPLOYMENT_GROUP",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
            "type": "AwsDeleteDeploymentGroupConfig"
        }
    }
    response = requests.post(myURL, json=body, headers=myHeader)
    if response.status_code not in (200,201,202):
        print(f"Error on delete call for resource_id: {resource_id}. Code: {response.status_code}, Message: {response.reason}")
        return None
    else:
        json_response = response.json()
        return json_response

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

def ext_get_group_info_json(strProdURL, org_id, resource_id, session_token):
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
        sys.exit(1)
    else:
        return json_response

def detach_vpc_json(strProdURL, session_token, json_body, org_id):
    """Detach a VPC from a vTGW"""
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/aws/operations".format(strProdURL, org_id)
    response = requests.post(myURL, json=json_body, headers=myHeader)
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        sys.exit(1)
    else:
        return json_response

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
        sys.exit(1)
    else:
        return json_response
