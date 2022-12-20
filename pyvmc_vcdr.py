# VCDR Python library for PyVMC

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import json
import requests

def vcdr_error_handling(fxn_response):
    code = fxn_response.status_code
    print (f'API call failed with status code {code}.')
    if code == 400:
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
    elif code == 404:
        print(f'Error {code}: "Bad Request"')
        print("Request was improperly formatted or contained an invalid parameter.")
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
        print("The request can not be performed because the associated resource could not be reached or is temporarily busy. Please confirm the VCDR Orchestrator URL in your config.ini are correct.")
    else:
        print(f'Error: {code}: Unknown error')
    try:
        json_response = fxn_response.json()
        if 'error_message' in json_response:
            print(json_response['error_message'])
    except:
        print("No additional information in the error response.")
    return None


# ============================
# Cloud File System
# ============================

def get_vcdr_cloud_fs_json(strVCDRProdURL, session_token):
    """Get Cloud File Systems - Get a list of all deployed cloud file systems in your VMware Cloud DR organization."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None
        

def get_vcdr_cloud_fs_details_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Cloud File System Details - Get details for an individual cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None

# ============================
# Protected Site
# ============================

def get_vcdr_sites_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Protected Sites - Get a list of all protected sites associated with an individual cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protected-sites'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None

def get_vcdr_site_details_json(strVCDRProdURL, cloud_fs_id, site_id, session_token):
    """Get Protected Site Details - Get details about an individual protected site."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protected-sites/{site_id}'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None

# ============================
# Protected VM
# ============================

def get_vcdr_vm_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Protected Virtual Machines - Get a list of all protected VMs currently being replicated to the specified cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protected-vms'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None

# ============================
# Protection Group
# ============================

def get_vcdr_pg_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Protection Groups - Get a list of all protection groups associated with an individual cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None

def get_vcdr_pg_details_json(strVCDRProdURL, cloud_fs_id, pg_id, session_token):
    """Get Protection Group Details - Get details for the requested protection group."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups/{pg_id}'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None

# ============================
# Protection Group Snapshot
# ============================

def get_vcdr_pg_snaps_json(strVCDRProdURL, cloud_fs_id, pg_id, session_token):
    """Get Protection Group Snapshots - Get a list of all snapshots in a specific protection group."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups/{pg_id}/snapshots'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None
 
def get_vcdr_pg_snap_details_json(strVCDRProdURL, cloud_fs_id, pg_id, snap_id, session_token):
    """Get Protection Group Snapshot Details - Get detailed information for a protection group snapshot."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups/{pg_id}/snapshots/{snap_id}'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None
 
# ============================
# Recovery SDDC
# ============================

def get_vcdr_sddcs_json(strVCDRProdURL, session_token):
    """Get Recovery SDDC - List VMware Cloud (VMC) Recovery Software-Defined Datacenters (SDDCs)."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/recovery-sddcs'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None
 
def get_vcdr_sddc_details_json(strVCDRProdURL, sddc_id, session_token):
    """Get Recovery SDDC Details - Get details of a specific Recovery SDDC. """
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/recovery-sddcs/{sddc_id}'
    response = requests.get(myURL, headers=myHeader)
    if response.status_code == 200:
        json_response = response.json()
        return json_response
    else:
        vcdr_error_handling(response)
        return None
 