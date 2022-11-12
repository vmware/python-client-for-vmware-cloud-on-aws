# VCDR Python library for PyVMC

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import json
import requests

# ============================
# Cloud File System
# ============================

def get_vcdr_cloud_fs_json(strVCDRProdURL, session_token):
    """Get Cloud File Systems - Get a list of all deployed cloud file systems in your VMware Cloud DR organization."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
        

def get_vcdr_cloud_fs_details_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Cloud File System Details - Get details for an individual cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False

# ============================
# Protected Site
# ============================

def get_vcdr_sites_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Protected Sites - Get a list of all protected sites associated with an individual cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protected-sites'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False

def get_vcdr_site_details_json(strVCDRProdURL, cloud_fs_id, site_id, session_token):
    """Get Protected Site Details - Get details about an individual protected site."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protected-sites/{site_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False

# ============================
# Protected VM
# ============================

def get_vcdr_vm_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Protected Virtual Machines - Get a list of all protected VMs currently being replicated to the specified cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protected-vms'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False

# ============================
# Protection Group
# ============================

def get_vcdr_pg_json(strVCDRProdURL, cloud_fs_id, session_token):
    """Get Protection Groups - Get a list of all protection groups associated with an individual cloud file system."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False

def get_vcdr_pg_details_json(strVCDRProdURL, cloud_fs_id, pg_id, session_token):
    """Get Protection Group Details - Get details for the requested protection group."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups/{pg_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False

# ============================
# Protection Group Snapshot
# ============================

def get_vcdr_pg_snaps_json(strVCDRProdURL, cloud_fs_id, pg_id, session_token):
    """Get Protection Group Snapshots - Get a list of all snapshots in a specific protection group."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups/{pg_id}/snapshots'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
 
def get_vcdr_pg_snap_details_json(strVCDRProdURL, cloud_fs_id, pg_id, snap_id, session_token):
    """Get Protection Group Snapshot Details - Get detailed information for a protection group snapshot."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/cloud-file-systems/{cloud_fs_id}/protection-groups/{pg_id}/snapshots/{snap_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
 
# ============================
# Recovery SDDC
# ============================

def get_vcdr_sddcs_json(strVCDRProdURL, session_token):
    """Get Recovery SDDC - List VMware Cloud (VMC) Recovery Software-Defined Datacenters (SDDCs)."""
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/recovery-sddcs'
    response = requests.get(myURL, headers=myHeader)
    print(response)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
 
def get_vcdr_sddc_details_json(strVCDRProdURL, sddc_id, session_token):
    """Get Recovery SDDC Details - Get details of a specific Recovery SDDC. """
    myHeader = {'x-da-access-token': session_token}
    myURL = f'{strVCDRProdURL}/api/vcdr/v1alpha/recovery-sddcs/{sddc_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print (f'API call failed with status code {response.status_code}. URL: {myURL}.')
        return False
 