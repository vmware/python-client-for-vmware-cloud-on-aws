import json
import requests


# ============================
# Services
# ============================
def get_csp_groups_json(strCSProdURL, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

def get_services_json(strCSPProdURL, ORG_ID, session_token):
    """Gets services and URI for associated access token and Org ID"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSPProdURL}/csp/gateway/slc/api/v2/ui/definitions/?orgId={ORG_ID}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

# ============================
# User and Group Management
# ============================


def get_csp_users_json(strCSPProdURL, orgID, session_token):
    """Returns all CSP Users in the select ORG in JSON format"""
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSPProdURL}/csp/gateway/am/api/v2/orgs/{orgID}/users'
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse


def get_csp_groups_json(strCSProdURL, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_csp_group_info_json(strCSProdURL, org_id, session_token, group_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups/{group_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_csp_users_group_json(strCSProdURL, org_id, session_token, group_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups/{group_id}/users'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def get_csp_service_roles_json(strCSProdURL, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/loggedin/user/orgs/{org_id}/service-roles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response


def search_csp_users_json(strCSProdURL, session_token, json_data, org_id):
    my_header = {'csp-auth-token': session_token, 'Content-Type': 'application/json'}
    my_url = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/users/search'
    response = requests.get(my_url, headers=my_header, params=json_data)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, my_url


def add_users_csp_group_json(strCSProdURL, org_id, session_token, group_id, json_data):
    myHeader = {'csp-auth-token': session_token, 'Content-Type': 'application/json'}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups/{group_id}/users'
    response = requests.post(myURL, data=json.dumps(json_data), headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code, myURL
