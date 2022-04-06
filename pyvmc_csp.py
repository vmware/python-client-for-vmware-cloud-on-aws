import json
import requests


# ============================
# User and Group Management
# ============================


def get_csp_users_json(strCSPProdURL, orgID, sessiontoken):
    """Returns all CSP Users in the select ORG in JSON format"""
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{strCSPProdURL}/csp/gateway/am/api/v2/orgs/{orgID}/users'
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse
