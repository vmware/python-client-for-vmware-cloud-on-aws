# CSP Python library for PyVMC

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import json
import requests

#In order to use the following function, all the functions in this file will have to be modified to use.  
def csp_error_handling(fxn_response):
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
    else:
        print(f'Error: {code}: Unknown error')
    try:
        json_response = fxn_response.json()
        if 'message' in json_response:
            print(json_response['message'])
    except:
        print("No additional information in the error response.")
    return None


# ============================
# Services
# ============================


def get_csp_groups_json(strCSProdURL, ORG_ID, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{ORG_ID}/groups'
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
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        try:
            print(json_response['error_message'])
        except:
            pass


def get_csp_groups_searchterm_json(strCSProdURL, org_id, session_token,search_term):
    """make the call to the API looking for groups that CONTAIN the search term - br"""
    myHeader = {'csp-auth-token': session_token}

    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups-search?groupSearchTerm={search_term}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    #
    # For error handling, print out some text, but use the reason/message that comes from the API.
    #
    if response.status_code == 200:
        return json_response
    elif response.status_code in (400,401,403):
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        if "message" in json_response.keys():
            print(f'Error Message: {json_response["message"]}')
        return None
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        if "error_message" in json_response.keys():
            print(json_response['error_message'])
        return None


def get_csp_group_info_json(strCSProdURL, org_id, session_token, group_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups/{group_id}'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_csp_users_group_json(strCSProdURL, org_id, session_token, group_id):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups/{group_id}/users'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def get_csp_service_roles_json(strCSProdURL, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/loggedin/user/orgs/{org_id}/service-roles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])


def search_csp_users_json(strCSProdURL, session_token, json_data, org_id):
    my_header = {'csp-auth-token': session_token, 'Content-Type': 'application/json'}
    my_url = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/users/search'
    response = requests.get(my_url, headers=my_header, params=json_data)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {my_url}.')
        print(json_response['error_message'])


def add_users_csp_group_json(strCSProdURL, org_id, session_token, group_id, json_data):
    myHeader = {'csp-auth-token': session_token, 'Content-Type': 'application/json'}
    myURL = f'{strCSProdURL}/csp/gateway/am/api/orgs/{org_id}/groups/{group_id}/users'
    response = requests.post(myURL, data=json.dumps(json_data), headers=myHeader)
    json_response = response.json()
    if response.status_code == 200:
        return json_response
    else:
        print("There was an error. Check the syntax.")
        print(f'API call failed with status code {response.status_code}. URL: {myURL}.')
        print(json_response['error_message'])
