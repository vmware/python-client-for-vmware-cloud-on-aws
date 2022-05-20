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
    params = {'org': orgID, 'linkedAccountId': linkedAWSID,'region': region}
    response = requests.get(myURL, headers=myHeader, params=params)
    jsonResponse = response.json()
    return jsonResponse


def get_connected_accounts_json(strProdURL, orgID, sessiontoken):
    """ Returns all connected AWS accounts in json format """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/account-link/connected-accounts"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse


# ============================
# SDDC
# ============================


def get_sddcs_json(strProdURL, orgID, sessiontoken):
    """Returns list of all SDDCs in an Org via json"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse


def get_sddc_info_json (strProdURL, orgID, sessiontoken, sddcID):
    """Returns SDDC info in JSON format"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs/{sddcID}"
    response = requests.get(myURL, headers=myHeader)
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    jsonresponse = response.json()
    return jsonresponse


# ============================
# TKG
# ============================


# ============================
# VTC - AWS Operations
# ============================


# ============================
# VTC - DXGW Operations
# ============================


# ============================
# VTC - SDDC Operations
# ============================


# ============================
# VTC - SDDC Group Operations
# ============================


# ============================
# VTC - TGW Operations
# ============================


# ============================
# VTC - VPC Operations
# ============================