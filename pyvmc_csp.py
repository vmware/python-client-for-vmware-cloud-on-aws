import json
import requests

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
    jsonresponse = response.json()
    return jsonresponse

def get_connected_accounts_json(strProdURL, orgID, sessiontoken):
    """ Returns all connected AWS accounts in json format """
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/account-link/connected-accounts"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse

def get_compatible_subnets_json(strProdURL, orgID, sessiontoken, linkedAWSID, region):
    """Returns all compatible subnets for linking in selected AWS Account and AWS Region"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/account-link/compatible-subnets"
    params = {'org': orgID, 'linkedAccountId': linkedAWSID,'region': region}
    response = requests.get(myURL, headers=myHeader, params=params)
    jsonResponse = response.json()
    return jsonResponse

def get_csp_users_json(strCSPProdURL, orgID, sessiontoken):
    """Returns all CSP Users in the select ORG in JSON format"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{strCSPProdURL}/csp/gateway/am/api/v2/orgs/{orgID}/users'
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse
