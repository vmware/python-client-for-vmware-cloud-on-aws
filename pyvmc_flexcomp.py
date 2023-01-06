# NSX Python library for PyVMC

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

import sys
import json
from weakref import proxy
import requests
from requests.sessions import session
from requests.auth import HTTPBasicAuth

# ============================
# Global error handling
# ============================

def nsx_error_handling(fxn_response):
    code = fxn_response.status_code
    print (f'API call failed with status code {code}.')
    if code == 301:
        print(f'Error {code}: "Moved Permanently"')
        print("Request must be reissued to a different controller node.")
        print("The controller node has been replaced by a new node that should be used for this and all future requests.")
    elif code ==307:
        print(f'Error {code}: "Temporary Redirect"')
        print("Request should be reissued to a different controller node.")
        print("The controller node is requesting the client make further requests against the controller node specified in the Location header. Clients should continue to use the new server until directed otherwise by the new controller node.")
    elif code ==400:
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
        print("The request can not be performed because the associated resource could not be reached or is temporarily busy. Please confirm the ORG ID and SDDC ID entries in your config.ini are correct.")
    else:
        print(f'Error: {code}: Unknown error')
    try:
        json_response = fxn_response.json()
        if 'error_message' in json_response:
            print(json_response['error_message'])
    except:
        print("No additional information in the error response.")
    return None
