# Flex Compute Python library for PyVMC

################################################################################
### Copyright (C) 2019-2023 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import sys
import json
from weakref import proxy
import requests
from requests.sessions import session
from requests.auth import HTTPBasicAuth

# ============================
# Flex Compute Namespace
# ============================


def get_flexcomp_namesapces(strProdURL, session_token, org_id):
    pyvmc_header = {"csp-auth-token": session_token}
    url = strProdURL+"/api/c3s/"+org_id+"/core/elastic-namespaces"
    response = requests.get(url, headers=pyvmc_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f"API call failed with status code {response.status_code}. URL: {url}.")
        print(json_response['error_message'])
        return None


def flexcomp_validate_network(strProdURL, session_token, org_id, cidr, seg_name, seg_cidr):
    data = {}
    temp_data = {}
    pyvmc_header = {"csp-auth-token": session_token,
                    "Content-Type": "application/json"}
    url = strProdURL+"/api/c3s/"+org_id+"/core/elastic-namespaces:validate-network"
    data['ens_cidr'] = cidr
    data['segment_configs'] = []
    temp_data['segment_cidr'] = seg_cidr
    temp_data['segment_name'] = seg_name
    temp_data['segment_type'] = "ROUTED"
    data['segment_configs'].append(temp_data)
    payload = json.dumps(data)

    response = requests.post(url, headers=pyvmc_header, data=payload)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {url}.')
        print(json_response['error_message'])
        return None


def create_flexcomp_namespace(strProdURL, session_token, org_id, name, desc, ens_size_id, region, cidr, seg_name, seg_cidr):
    data = {}
    pyvmc_header = {"csp-auth-token": session_token,
                    "Content-Type": "application/json"}
    url = strProdURL+"/api/c3s/"+org_id+"/core/elastic-namespaces:create"
    data['name'] = name
    data['region'] = region
    data['provider'] = "AWS"
    data['description'] = desc
    data['type'] = "BASIC"
    data['tenancy_type'] = "HARD"
    data['capacity_profiles'] = [
        {
            "fault_domains": 1,
            "size_id": ens_size_id,
            "infra_type": "GENERAL_PURPOSE"
        }
    ]
    data['network_config'] = {
        "segment_configs": [
            {
                "segment_cidr": seg_cidr,
                "segment_name": seg_name,
                "segment_type": "ROUTED"
            }
        ],
        "ens_cidr": cidr,
        "internet_connectivity": True
    }
    payload = json.dumps(data)

    response = requests.post(url, headers=pyvmc_header, data=payload)
    json_response = response.json()
    if response.status_code == 201:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {url}.')
        print(json_response['error_message'])
        return None


def delete_flexcomp_namespace(strProdURL, session_token, org_id, nsId):
    pyvmc_header = {"csp-auth-token": session_token,
                    "Content-Type": "application/json"}
    url = strProdURL+"/api/c3s/"+org_id+"/core/elastic-namespaces/"+nsId+":delete"
    response = requests.post(url, headers=pyvmc_header)
    json_response = response.json()
    if response.status_code == 201:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {url}.')
        print(json_response['error_message'])
        return None

# ============================
# Flex Compute Profiles
# ============================


def get_namespace_region(strProdURL, session_token, org_id):
    pyvmc_header = {"csp-auth-token": session_token}
    url = strProdURL+"/api/c3s/"+org_id+"/core/elastic-namespaces/regions"
    response = requests.get(url, headers=pyvmc_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f"API call failed with status code {response.status_code}. URL: {url}.")
        print(json_response['error_message'])
        return None


def get_namespace_profiles(strProdURL, session_token, org_id):
    pyvmc_header = {"csp-auth-token": session_token}
    url = strProdURL + "/api/c3s/" + org_id + "/core/elastic-namespaces/profiles"
    response = requests.get(url, headers=pyvmc_header)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f"API call failed with status code {response.status_code}. URL: {url}.")
        print(json_response['error_message'])
        return None
