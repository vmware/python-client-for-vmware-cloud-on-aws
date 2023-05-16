#!/usr/bin/env python3
# The shebang above is to tell the shell which interpreter to use. This make the file executable without "python3" in front of it (otherwise I had to use python3 pyvmc.py)
# I also had to change the permissions of the file to make it run. "chmod +x pyVMC.py" did the trick.
# I also added "export PATH="MY/PYVMC/DIRECTORY":$PATH" (otherwise I had to use ./pyvmc.y)
# For git BASH on Windows, you can use something like this #!/C/Users/usr1/AppData/Local/Programs/Python/Python38/python.exe

# Python Client for VMware Cloud on AWS

################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################

from random import choices
import re

import requests                         # need this for Get/Post/Delete
import configparser                     # parsing config file
import operator
import os
import time
import json
import sys
import ipaddress
import pandas as pd
from deepdiff import DeepDiff
from os.path import exists
from os import makedirs
from pathlib import Path
from prettytable import PrettyTable
from requests.sessions import session
from datetime import datetime, timezone
from requests.auth import HTTPBasicAuth
from re import search
from pyvmc_csp import *
from pyvmc_nsx import *
from pyvmc_vmc import *
from pyvmc_vcdr import *
from pyvmc_flexcomp import *

# ============================
# Read CONFIG.INI file
# ============================

def read_config():
    if not exists("./config.ini"):
        print()
        print('config.ini is missing')
        response = input("Would you like to build a default config.ini now? (please type 'yes' or 'no')")
        if response.lower() == 'no' or response.lower() == 'n':
            print()
            print('You may rename config.ini.example to config.ini and manually populate the required values inside the file.')
            sys.exit(0)
        elif response.lower() == 'yes' or response.lower() == 'y':
            build_initial_config()
            sys.exit(0)
    else:
        config_params = {}
        try:
            config = configparser.ConfigParser()
            config.read("./config.ini")
            auth_info = False
            Refresh_Token = ""
            clientId = ""
            clientSecret = ""

            strProdURL      = config.get("vmcConfig", "strProdURL")
            strCSPProdURL   = config.get("vmcConfig", "strCSPProdURL")
            ORG_ID          = config.get("vmcConfig", "org_id")
            SDDC_ID         = config.get("vmcConfig", "sddc_id")
            strVCDRProdURL  = config.get("vmcConfig", "strVCDRProdURL")

            config_params.update({"strProdURL": strProdURL})
            config_params.update({"strCSPProdURL": strCSPProdURL})
            config_params.update({"ORG_ID": ORG_ID})
            config_params.update({"SDDC_ID": SDDC_ID})
            config_params.update({"strVCDRProdURL": strVCDRProdURL})

            if config.has_option("vmcConfig", "refresh_Token"):
                Refresh_Token = config.get("vmcConfig", "refresh_Token")
                config_params.update({"Refresh_Token": Refresh_Token})
                auth_info = True

            if config.has_option("vmcConfig", "oauth_clientSecret") and config.has_option("vmcConfig", "oauth_clientId"):
                clientId = config.get("vmcConfig", "oauth_clientId")
                clientSecret = config.get("vmcConfig", "oauth_clientSecret")
                config_params.update({"clientId": clientId})
                config_params.update({"clientSecret": clientSecret})
                auth_info = True

            if len(strProdURL) == 0 or len(strCSPProdURL) == 0 or not auth_info or len(ORG_ID) == 0 or len(SDDC_ID) == 0 or len(strVCDRProdURL) == 0:
                print()
                print('strProdURL, strCSPProdURL, Refresh_Token, ORG_ID, and SDDC_ID must all be populated in config.ini')
                print()
                sys.exit(1)
            if "x-x-x-x" in strVCDRProdURL or " " in strVCDRProdURL:
                print()
                print("Please correct the entry for strVCDRProdURL in config.ini before proceeding.")
                print()
                sys.exit(1)

        except:
            print(
                '''There are problems with your config.ini file.  
                Please be sure you have the latest version and ensure at least the following values are populated:
                - strProdURL     - this should read: "https://vmc.vmware.com"
                - strCSPProdURL  - this should read: "https://console.cloud.vmware.com"
                - Refresh_Token  - this should be a properly scoped refresh refresh token from the VMware Cloud Services Console.
                - oauth_clientId - this should be OAuth Client ID properly scoped from VMware Cloud Services Console.
                - oauth_clientSecret - this should be OAuth Client Secret.
                - ORG_ID         - this should be the ID of your VMware Cloud Organization, found in the VMware Cloud Services Portal.
                - SDDC_ID        - if applicable, this should be the ID of the VMware Cloud SDDC (Software Defined Datacenter) you wish to work with.
                - strVCDRProdURL - if applicable, this should be the URL of your VMware Cloud DR Orchestrator.
                ''')
            sys.exit(1)
        return config_params


def build_initial_config(**kwargs):
    config = configparser.ConfigParser()
    config['vmcConfig'] = {
        'strProdURL':'https://vmc.vmware.com',
        'strCSPProdURL':'https://console.cloud.vmware.com',
        'strVCDRProdURL':'https://vcdr-xxx-xxx-xxx-xxx.app.vcdr.vmware.com/',
        'refresh_Token':'',
        'oauth_clientId':'',
        'oauth_clientSecret':'',
        'org_id':'',
        'sddc_id': ''
        }

    rt = input('Please enter your refresh token:')
    oid = input('Please enter your organization ID:')
    sid = input('Please enter your SDDC ID:')
    config['vmcConfig']['refresh_token'] = rt
    config['vmcConfig']['org_id'] = oid
    config['vmcConfig']['sddc_id'] = sid

    with open('config.ini', 'w') as configfile:
        config.write(configfile)
    show_config()
    print()
    print("Your config.ini has been populated with the default URLs necessary for basic functionality,")
    print(" as well as your Org and SDDC IDs, and your refresh token (if you chose to do so).")
    print()
    print("Please confirm your config.ini file using ./pyVMC.py config show or review your file manually, then try your command again.")
    return


def show_config(**kwargs):
    if not exists("./config.ini"):
        print('config.ini is missing - rename config.ini.example to config.ini and populate the required values inside the file.')
        sys.exit(1)

    try:
        config_file=open("./config.ini","r")
        content=config_file.read()
        print("content of the config file is:")
        print(content)
    except:
        print('There are problems with your config.ini file.')
        sys.exit(1)

#  https://developer.vmware.com/ap  is/csp/csp-iam/latest/csp/gateway/am/api/auth/api-tokens/authorize/post/

def getAccessToken(**kwargs):
    auth_method = kwargs['auth_method']
    strCSPProdURL = kwargs['strCSPProdURL']
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = None

    match auth_method:
        case 'oauth':
            oauth_clientSecret = kwargs['oauth_clientSecret']
            oauth_clientId = kwargs['oauth_clientId']
            auth_string = "/csp/gateway/am/api/auth/authorize"
            payload = {'grant_type': 'client_credentials'}
            response = requests.post(f'{strCSPProdURL}{auth_string}', headers=headers, data=payload, auth=(oauth_clientId, oauth_clientSecret))
 
        case 'refresh_token':
            myKey = kwargs['myKey']
            auth_string = "/csp/gateway/am/api/auth/api-tokens/authorize"
            params = {'api_token': myKey}
            response = requests.post(f'{strCSPProdURL}{auth_string}', params=params, headers=headers)

    if response.status_code != 200:
        print(f'Error received on api token: {response.status_code}.')
        if response.status_code == 400:
            print("Invalid request body | In case of expired refresh_token or bad token in config.ini")
        elif response.status_code == 404:
            print("The requested resource could not be found")
        elif response.status_code == 409:
            print("The request could not be processed due to a conflict")
        elif response.status_code == 429:
            print("The user has sent too many requests")
        elif response.status_code == 500:
            print("An unexpected error has occurred while processing the request")
        else:
            print(f"Unexpected error code {response.status_code}")
        return None

    jsonResponse = response.json()
    access_token = jsonResponse['access_token']
    return access_token


DEBUG_MODE = False

def generate_table(results):
    """Generates a 'prettytable' using a JSON payload; automatically uses the dictionary keys in the payload as column headers."""
    keyslist = list(results[0].keys())
    table = PrettyTable(keyslist)
    for dct in results:
        table.add_row([dct.get(c, "") for c in keyslist])
    return table

def create_directory(dir_name):
    # checking if the directory demo_folder exist or not.
    if not exists(dir_name):  
        # if the demo_folder directory is not present then create it.
        makedirs(dir_name)
        print(f'Created directory:{dir_name}')
    else:
        print(f'Directory already exists: {dir_name}')


def validate_ip_address(ip_addr):
    """Validates if a provided IP address is a valide format"""
    try:
        ip_object = ipaddress.ip_address(ip_addr)
        return True
    except ValueError:
        return False

# ============================
# CSP - Service Definitions
# ============================


def getServiceDefinitions(**kwargs):
    """Gets services and URI for associated access token and Org ID"""
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']
    json_response = get_services_json(strCSPProdURL, ORG_ID, sessiontoken)
    if json_response == None:
        print("API Error")
        sys.exit(1)

    services= json_response['servicesList']
    table = PrettyTable(['Service Name', 'Access type', 'Service URL'])
    for i in services:
        table.add_row([i['displayName'], i['serviceAccessType'], i['serviceUrls']['serviceHome']])
    print(table)

def addUsersToCSPGroup(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']
    group_id = kwargs['group_id']
    email = kwargs['email']
    params = {
            'notifyUsers': 'false',
            'usernamesToAdd': email
    }
    json_response = add_users_csp_group_json(strCSPProdURL, ORG_ID, sessiontoken, group_id, params)
    if json_response == None:
        print("API Error")
        sys.exit(1)

    print(f"Added: {json_response['succeeded']}" )
    print(f"Failed: {json_response['failed']}" )


def findCSPUserByServiceRole(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']
    if kwargs['service_role'] is None:
        print("Please use -r or --service_role to specify the role name to search by.  Use show-csp-service-roles to see entitled roles.")
        sys.exit(1)
    else:
        service_role = kwargs['service_role']
    json_response = get_csp_users_json(strCSPProdURL, ORG_ID, sessiontoken)
    if json_response == None:
        print("API Error")
        sys.exit(1)

    users = json_response['results']
    table = PrettyTable(['Email','Service Role', 'Org Role'])
    for user in users:
        for servicedef in user['serviceRoles']:
            for role in servicedef['serviceRoles']:
                if role['name'] == service_role:
                    display_role = ''
                    for orgrole in user['organizationRoles']:
                        display_role = display_role + orgrole['name'] + ' '
                    table.add_row([user['user']['email'],service_role,display_role])
    print(table)


def getCSPGroupDiff(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']
    SKIP_MEMBERS = False
    SKIP_OWNERS = False
    if kwargs['group_id'] is None:
        print('Usage: show-csp-group-diff --group-id <GROUP ID> --filter [showall|skipmembers|skipowners]')
        sys.exit(1)
    else:
        group_id = kwargs['group_id']
    if kwargs['filter'] == "skipmembers":
        SKIP_MEMBERS = True
        print('Skipping members...')
    elif kwargs['filter'] == "skipowners":
        SKIP_OWNERS = True
        print('Skipping owners...')
    else:
        pass
    json_response_groups = get_csp_group_info_json(strCSPProdURL, ORG_ID, sessiontoken, group_id)
    if json_response_groups == None:
        print("API Error")
        sys.exit(1)

    grouproles = json_response_groups['serviceRoles']
    json_response_users = get_csp_users_json(strCSPProdURL, ORG_ID, sessiontoken)
    if json_response_users == None:
        print("API Error")
        sys.exit(1)

    users = json_response_users['results']
    grouprolelist = []
    for role in grouproles:
        for rname in role['serviceRoleNames']:
            grouprolelist.append(rname)
    print('Group role list:')
    print(grouprolelist)
    i = 0
    for user in users:
        IS_OWNER = False
        for orgrole in user['organizationRoles']:
            if orgrole['name'] == 'org_owner':
                IS_OWNER = True
                break
        IS_MEMBER = False
        for orgrole in user['organizationRoles']:
            if orgrole['name'] == 'org_member':
                IS_MEMBER = True
                break
        if IS_OWNER and SKIP_OWNERS:
            continue
        if IS_MEMBER and SKIP_MEMBERS:
            continue
        i += 1
        if i % 25 == 0:
            wait = input("Press Enter to show more users, q to quit: ")
            if wait == 'q':
                sys.exit(0)  # quiting is not an error
            print('Group role list:')
            print(grouprolelist)
        print(user['user']['email'],f'({i} of {len(users)})')
        print(f'Member: {IS_MEMBER}, Owner: {IS_OWNER}')
        userrolelist = []
        for servicedef in user['serviceRoles']:
            for role in servicedef['serviceRoles']:
                userrolelist.append(role['name'])
        print('User role list:')
        print(userrolelist)
        diff = DeepDiff(grouprolelist,userrolelist,ignore_order=True)
        print('Role Differences:')
        print(diff)
        print("------------- ")


def getCSPGroupMembers(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']
    if kwargs['group_id'] is None:
        print("Please use -gid or --group-id to specify the ID of the group you would like membership of.")
        sys.exit()
    else:
        group_id = kwargs['group_id']
    json_response = get_csp_users_group_json(strCSPProdURL, ORG_ID, sessiontoken, group_id)
    if json_response == None:
        print("API Error")
        sys.exit(1)

    users = json_response['results']
    table = PrettyTable(['Username','First Name', 'Last Name','Email','userId'])
    for user in users:
        table.add_row([user['username'],user['firstName'],user['lastName'],user['email'],user['userId']])
    print(table)


def getCSPGroups(**kwargs):
    """Get List of CSP groups from your Organization -- br"""
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']

    if kwargs['search_term'] is None:
        json_response = get_csp_groups_json(strCSPProdURL, ORG_ID, sessiontoken)
        print("Got the groups")
        if json_response is not None:
            groups = json_response['results']
            num_groups = len(groups)
            if num_groups == 0:
                print("No results returned.")
            else:
                print(str(num_groups) + " result" + ("s" if num_groups > 1 else "") + " returned:")
                table = PrettyTable(['ID', 'Name', 'Group Type', 'User Count'])
                for grp in groups:
                    table.add_row([grp['id'], grp['displayName'], grp['groupType'], grp['usersCount']])
                print(table)
    else:
        search_term = kwargs['search_term']
        json_response = get_csp_groups_searchterm_json(strCSPProdURL, ORG_ID, sessiontoken, search_term)
        if json_response is not None:
            groups = json_response['results']
            num_groups = len(groups)
            if num_groups == 0:
                print("No results returned.")
            else:
                print(str(num_groups) + " result" + ("s" if num_groups > 1 else "") + " returned:")
                table = PrettyTable(['ID', 'Name', 'Group Type', 'User Count'])
                for grp in groups:
                    table.add_row([grp['id'], grp['displayName'], grp['groupType'], grp['usersCount']])
                print(table)
        else:
            print("API Error")
            sys.exit(1)


def searchCSPOrgUsers(**kwargs):
    # for i, j in kwargs.items():
    #     print(i, j)
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']  
    if kwargs['search_term'] is None:
        print("Plese enter a search term (--search-term).  To simply show all ORG users, please use show-org-users")
        sys.exit()
    else:
        searchTerm = kwargs['search_term']
    params = {
            'userSearchTerm': searchTerm
        }
    json_response = search_csp_users_json(strCSPProdURL, sessiontoken, params, ORG_ID)
    if json_response == None:
        print("API Error")
        sys.exit(1)

    users = json_response['results']
    if len(users) >= 20:
        print("Search API is limited to 20 results, refine your search term for accurate results.")
    table = PrettyTable(['Username', 'First Name', 'Last Name', 'Email', 'userId'])
    for user in users:
        table.add_row([user['user']['username'], user['user']['firstName'], user['user']['lastName'], user['user']['email'], user['user']['userId']])
    print(table)


def getCSPServiceRoles(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']
    json_response = get_csp_service_roles_json(strCSPProdURL, ORG_ID, sessiontoken)
    if json_response == None:
        print("API Error")
        sys.exit(1)

    for svc_def in json_response['serviceRoles']:
        for svc_role in svc_def['serviceRoleNames']:
            print(svc_role)


def showORGusers(**kwargs):
    """Prints out all Org users, sorted by last name"""
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strCSPProdURL = kwargs['strCSPProdURL']
    jsonResponse = get_csp_users_json(strCSPProdURL, ORG_ID, sessiontoken)
    if jsonResponse == None:
        print("API Error")
        sys.exit(1)

    users = jsonResponse['results']
    table = PrettyTable(['First Name', 'Last Name', 'User Name'])
    for i in users:
        table.add_row([i['user']['firstName'],i['user']['lastName'],i['user']['username']])
    print (table.get_string(sortby="Last Name"))

# ============================
# Cloud Flex Compute
# ============================


def showFlexcompActivityStatus(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    activity_id = kwargs['activityId']
    jsonResponse = get_activity_status(strProdURL, session_token=sessiontoken, org_id=ORG_ID, activity_id=activity_id)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    table = PrettyTable(['Activity_ID', 'State', 'Activity'])
    table.add_row([jsonResponse['id'], jsonResponse['state'], jsonResponse['activity_type_name']])
    print(table)


def showFlexcompNamespaces(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    jsonResponse = get_flexcomp_namesapces(strProdURL, session_token=sessiontoken, org_id=ORG_ID)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    result = (jsonResponse['content'])
    table = PrettyTable(['ID', 'Name', 'Provider', 'Region', 'State'])
    for i in result:
        table.add_row([i['id'], i['name'],i['provider'],i['region'],i['state']['display_name']])
    print(table.get_string(sortby="Name"))


def showFlexcompRegions(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    jsonResponse = get_namespace_region(strProdURL, session_token=sessiontoken, org_id=ORG_ID)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    result = jsonResponse['region_profile_map']
    table = PrettyTable(['Region Name', 'Region Description'])
    for k,v in result.items():
        table.add_row([k, v['region_description']])
    print(table)


def showFlexcompTemplates(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    jsonResponse = get_namespace_profiles(strProdURL, session_token=sessiontoken, org_id=ORG_ID)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    result = jsonResponse['GENERAL_PURPOSE']['sizes']
    # print(result)
    table = PrettyTable(['id', 'Name', 'Capacity'])
    for i in result:
        cpu_cap = str(i['capacity']['cpu']['value']).split(".")[0]+i['capacity']['cpu']['unit']
        mem_cap = str(i['capacity']['memory']['value']).split(".")[0]+i['capacity']['memory']['unit']
        storage_cap = str(i['capacity']['storage']['value']).split(".")[0]+i['capacity']['storage']['unit']
        capacity = cpu_cap + " " + mem_cap + " " + storage_cap
        table.add_row([i['id'],i['name'],capacity])
    print(table)


def validateNetworkFlexComp(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    cidr = kwargs["flexCompCIDR"]
    seg_name = kwargs['segName']
    seg_cidr = kwargs['segCIDR']
    jsonResponse = flexcomp_validate_network(strProdURL, session_token=sessiontoken, org_id=ORG_ID, cidr=cidr, seg_name=seg_name, seg_cidr=seg_cidr)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    ens_result = jsonResponse["ens_cidr_config"]["result"]
    seg_result = jsonResponse["segments_gateway_cidrs_configs"][0]["result"]
    table = PrettyTable(['Field', 'Message', 'Status'])
    table.add_row([ens_result["field_name"],ens_result["message"],ens_result["status"]])
    table.add_row([seg_result[0]["field_name"],seg_result[0]["message"],seg_result[0]["status"]])
    table.add_row([seg_result[1]["field_name"],seg_result[1]["message"],seg_result[1]["status"]])
    print(table)


def createFlexcompNamespace(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    cidr = kwargs["flexCompCIDR"]
    seg_name = kwargs['segName']
    seg_cidr = kwargs['segCIDR']
    namespace_name = kwargs['nsName']
    namespace_desc = kwargs['nsDesc']
    template_id = kwargs['templateId']
    region = kwargs['region']
    jsonResponse = create_flexcomp_namespace(strProdURL, session_token=sessiontoken, org_id=ORG_ID, name=namespace_name,
                                             desc=namespace_desc, ens_size_id=template_id, region=region, cidr=cidr,
                                             seg_name=seg_name,seg_cidr=seg_cidr)

    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    table = PrettyTable(['Activity_ID', 'State', 'Activity'])
    table.add_row([jsonResponse['id'], jsonResponse['state'], jsonResponse['activity_type_name']])
    print(table)


def deleteFlexcompNamespace(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    nsId = kwargs["nsId"]
    jsonResponse = delete_flexcomp_namespace(strProdURL, session_token=sessiontoken, org_id=ORG_ID, nsId=nsId)

    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    table = PrettyTable(['Activity_ID', 'State', 'Activity'])
    table.add_row([jsonResponse['id'], jsonResponse['state'], jsonResponse['activity_type_name']])
    print(table)


# ===================================
# Cloud Flex Compute - VM operations
# ===================================

def showAllImagesFlexcomp(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    jsonResponse = get_all_images(strProdURL, session_token=sessiontoken, org_id=ORG_ID)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    result = jsonResponse['content']
    # print(result)
    table = PrettyTable(['id', 'Name', 'Type', 'State', 'OS'])
    for i in result:
        table.add_row([i['id'],i['name'],i['type'],i['state']['name'],i['os']])
    print(table)


def showAllVMsFlexcomp(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    jsonResponse = get_all_vms(strProdURL, session_token=sessiontoken, org_id=ORG_ID)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    result = jsonResponse['content']
    table = PrettyTable(['id', 'Name', 'Namespace', 'State', 'Power State'])
    for i in result:
        table.add_row([i['id'],i['name'],i['namespaceName'],i['state']['name'],i['vmMetadata']['powerState']])
    print(table)


def vmPowerOperationsFlexcomp(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    vmId = kwargs['vmId']
    powerOperation = kwargs['powerOperation']
    jsonResponse = vm_power_operation(strProdURL, session_token=sessiontoken, org_id=ORG_ID, vmId=vmId, powerOperation=powerOperation)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    table = PrettyTable(['Activity_ID', 'State', 'Activity'])
    table.add_row([jsonResponse['id'], jsonResponse['state'], jsonResponse['activity_type_name']])
    print(table)


def createVMFlexcomp(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    vmName = kwargs['vmName']
    vmNamespaceId = kwargs['vmNamespaceId']
    vmCPU = kwargs['vmCPU']
    vmMem = kwargs['vmMem']
    vmStorage = kwargs['vmStorage']
    networkSegName = kwargs['networkSegName']
    # networkCIDR = kwargs['networkSegCIDR']
    guestOS = kwargs['guestOS']
    imageId = kwargs['imageId']
    jsonResponse = create_vm_from_iso(strProdURL, session_token=sessiontoken, org_id=ORG_ID, name=vmName, namespace_name=vmNamespaceId, cpu=vmCPU, mem=vmMem, storage=vmStorage, network_seg_id=networkSegName, guestOS=guestOS, imageId=imageId)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    # print(jsonResponse)
    table = PrettyTable(['Activity_ID', 'State', 'Activity'])
    table.add_row([jsonResponse['id'], jsonResponse['state'], jsonResponse['activity_type_name']])
    print(table)


def vmDeleteFlexcomp(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs["strProdURL"]
    vmId = kwargs['vmId']
    jsonResponse = delete_vm(strProdURL, session_token=sessiontoken, org_id=ORG_ID, vmId=vmId)
    if jsonResponse is None:
        print("API Error")
        sys.exit(1)

    table = PrettyTable(['Activity_ID', 'State', 'Activity'])
    table.add_row([jsonResponse['id'], jsonResponse['state'], jsonResponse['activity_type_name']])
    print(table)


# ============================
# SDDC - Create/Delete/Task
# ============================

def printTask(event_name: str, task) -> None:
    taskid = task['id']
    print(f'{event_name} Task Started: {taskid}')
    print(f'Created: {task["created"]}')
    print(f'Updated: {task["updated"]}')
    print(f'Updated by User ID: {task["updated_by_user_id"]}')
    print(f'User ID: {task["user_id"]}')
    print(f'User Name: {task["user_name"]}')
    print(f'Version: {task["version"]}')
    print(f'Updated by User Name: {task["updated_by_user_name"]}')
    #
    # Now the inline parts: 
    #
    
    print(f"Status: {task['status']}")
    print(f"Sub-Status: {task['sub_status']}") 
    print(f"Resource: {task['resource_type']}")
    print(f"Resource ID: {task['resource_id']}")
    print(f"Task Type: {task['task_type']}")
    print(f"Error Message: {task['error_message']}")

    return


def createSDDC(**kwargs) -> None:
    """Creates an SDDC based on the parameters. The caller should have permissions to do this."""
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    sessiontoken = kwargs['sessiontoken']
    name = kwargs['name']
    linked_account_id = kwargs['aws_account_guid']
    linked_account_num = kwargs['aws_account_num']
    region = kwargs['region']
    amount = kwargs['number']
    host_type = kwargs['host_type']
    subnetId = kwargs['aws_subnet_id']
    mgt = kwargs['mgt_subnet']
    size = kwargs['sddc_size']
    validate_only = kwargs['validate_only']

    if linked_account_id is None and linked_account_num is None:
        print("You must supply either the GUID for the linked AWS account or the AWS account number. Please try again.")
        sys.exit(1)
    elif linked_account_id is None:
        accounts = get_connected_accounts_json(strProdURL, org_id, sessiontoken)
        for i in accounts:
            if i['account_number'] == linked_account_num:
                linked_account_id = i['id']
                break

    json_data = {
        'name': name,
        'account_link_sddc_config': [
            {
                'connected_account_id': linked_account_id,
                'customer_subnet_ids': [
                    subnetId
                ]
            }
        ],
        'provider': 'AWS',
        'num_hosts': amount,
        'deployment_type': 'SingleAZ',
        'host_instance_type': host_type,
        'sddc_type': "DEFAULT",
        'size': size,
        'region': region,
        'vpc_cidr': mgt
    }

    json_response = create_sddc_json(strProdURL, sessiontoken, org_id, validate_only, json_data)
    if json_response == None:
        sys.exit(1) # an error

    if 'input_validated' in json_response:
        return
        
    if not validate_only:
        print("SDDC Creation:") 
        print(json.dumps(json_response, indent = 4))
    
    return


def deleteSDDC(**kwargs) -> None:
    """deletes an SDDC based on the parameters. The caller should have permissions to do this."""
    orgID = kwargs["ORG_ID"]
    sessiontoken = kwargs["sessiontoken"]
    strProdURL = kwargs["strProdURL"]
    sddcID = kwargs["SDDCtoDelete"]  #command line argument takes precedence over file, and -- arg.
    force=kwargs['force']

    json_response = delete_sddc_json(strProdURL, sessiontoken, orgID, sddcID,force)
    if (json_response == None):
        sys.exit(1)
    
    print("SDDC Deletion info:") 
    print(json.dumps(json_response, indent=4))

    return None


def watchSDDCTask(**kwargs):
    """watch task and print out status"""
    strProdURL = kwargs['strProdURL']
    orgID = kwargs["ORG_ID"]
    sessiontoken = kwargs["sessiontoken"]
    taskID = kwargs["taskID"]

    json_response = watch_sddc_task_json(strProdURL, sessiontoken, orgID, taskID)
    if json_response == None:
        sys.exit(1)
    # else, print out the task
    task = json_response['id']
    now_utc = datetime.now(timezone.utc)
    print(f'Information on Task {task} @ {now_utc.isoformat().replace("+00:00", "Z")}')
    printTask("Watch Task", json_response)
    
    return None


def cancelSDDCTask(**kwargs):
    """cancel a task"""
    strProdURL = kwargs['strProdURL']
    orgID = kwargs["ORG_ID"]
    sessiontoken = kwargs["sessiontoken"]
    taskID = kwargs["taskID"]

    json_response = cancel_sddc_task_json(strProdURL, sessiontoken, orgID, taskID)
    if json_response == None:
        sys.exit(1)
    
    printTask("Cancel Task",json_response)
    return None


# ============================
# SDDC - AWS Account and VPC
# ============================

def setSDDCConnectedServices(**kwargs):
    """Sets SDDC access to S3 to either internet or connected VPC via input value. tue = ENI, false = internet"""
    proxy_url = kwargs["proxy"]
    sessiontoken = kwargs["sessiontoken"]
    value = kwargs["ENIorInternet"]

    # pull the first connected VPC
    json_response = get_conencted_vpc_json(proxy_url, sessiontoken)
    if json_response == None:
        sys.exit(1)

    sddc_connected_vpc = json_response['results'][0]
    # create the JSON
    json_data = {
        "name": "s3",
        "enabled": value
    }
    json_response_status_code = set_connected_vpc_services_json(proxy_url, sessiontoken, sddc_connected_vpc['linked_vpc_id'], json_data)

    if json_response_status_code == None:
        sys.exit(1)

    print(f'S3 connected via ENI is {value}')


def getCompatibleSubnets(**kwargs):
    """Lists all of the compatible subnets by Account ID and AWS Region"""
    orgID = kwargs["ORG_ID"]
    sessiontoken = kwargs["sessiontoken"]
    SddcID = kwargs["SDDC_ID"]
    linkedAccountId = kwargs["LinkedAccount"]
    region = kwargs["Region"]
    strProdURL = kwargs["strProdURL"]

    jsonResponse = get_compatible_subnets_json(strProdURL, orgID, sessiontoken, linkedAccountId, region)
    if jsonResponse == None:
        print("API Error")
        sys.exit(1)
    
    vpc_map = jsonResponse['vpc_map']
    table = PrettyTable(['vpc','description'])
    subnet_table = PrettyTable(['vpc_id','subnet_id','subnet_cidr_block','name','compatible','connected_account_id'])
    for i in vpc_map:
        myvpc = jsonResponse['vpc_map'][i]
        table.add_row([myvpc['vpc_id'],myvpc['description']])
        for j in myvpc['subnets']:
            subnet_table.add_row([j['vpc_id'],j['subnet_id'],j['subnet_cidr_block'],j['name'],j['compatible'],j['connected_account_id']])
    print(f"VPC for {orgID} in region {region}")
    print(table)
    print(f"Compatible Subnets for Org {orgID}")
    print(subnet_table)


def getConnectedAccounts(**kwargs):
    """Prints all connected AWS accounts"""
    strProdURL = kwargs["strProdURL"]
    orgID = kwargs["ORG_ID"]
    sessiontoken = kwargs["sessiontoken"]

    accounts = get_connected_accounts_json(strProdURL, orgID, sessiontoken)
    orgtable = PrettyTable(['OrgID'])
    orgtable.add_row([orgID])
    print(str(orgtable))
    table = PrettyTable(['Account Number','id'])
    for i in accounts:
        table.add_row([i['account_number'],i['id']])
    
    print("Connected Accounts")
    print(table)


def getSDDCConnectedVPC(**kwargs):
    """Prints table with Connected VPC and Services information - Compatible with M18+ SDDCs only"""
    proxy_url = kwargs['proxy']
    session_token = kwargs["sessiontoken"]
    # NSX 
    json_response = get_conencted_vpc_json(proxy_url, session_token)
    if json_response == None:
        sys.exit(1)
    sddc_connected_vpc = json_response['results'][0]
    sddc_connected_vpc_services = get_connected_vpc_services_json(proxy_url, session_token, sddc_connected_vpc['linked_vpc_id'])
#   The API changed for connected VPCs from M16 to M18 when the connected VPC prefix lists were added to M18.
#   This if-else block should allow this function to work with both M16 and earlier as well as M18 and newer SDDCs.
    if 'active_eni' in sddc_connected_vpc:
        eni = sddc_connected_vpc['active_eni']
    elif 'traffic_group_eni_mappings' in sddc_connected_vpc:
        eni = sddc_connected_vpc['traffic_group_eni_mappings'][0]['eni']
    else:
        eni = "Unknown"
    table = PrettyTable(['Customer-Owned Account', 'Connected VPC ID', 'Subnet', 'Availability Zone', 'ENI', 'Service Name', 'Service Access'])
    table.add_row([sddc_connected_vpc['linked_account'], sddc_connected_vpc['linked_vpc_id'], sddc_connected_vpc['linked_vpc_subnets'][0]['cidr'], sddc_connected_vpc['linked_vpc_subnets'][0]['availability_zone'], eni, sddc_connected_vpc_services['results'][0]['name'],sddc_connected_vpc_services['results'][0]['enabled']])
    print("Connected Services")
    print(table)


def getSDDCShadowAccount(**kwargs):
    """Returns SDDC Shadow Account"""
    proxy_url = kwargs["proxy"]
    sessiontoken = kwargs["sessiontoken"]
    #
    json_response = get_sddc_shadow_account_json(proxy_url, sessiontoken)
    if json_response == None:
        sys.exit(1)
    sddc_shadow_account = json_response['shadow_account']
    print("Shadow Account is:")
    print(sddc_shadow_account)


# ============================
# SDDC - SDDC
# ============================

def getSDDCState(**kwargs):
    """Prints out state of selected SDDC"""
    org_id = kwargs["ORG_ID"]
    sddc_id = kwargs["SDDC_ID"]
    sessiontoken = kwargs["sessiontoken"]
    strProdURL = kwargs["strProdURL"]

    sddc_state = get_sddc_info_json(strProdURL, org_id, sessiontoken, sddc_id)
    if sddc_state == None:
        sys.exit(1)
    table = PrettyTable(['Name', 'Id', 'Status', 'Type', 'Region', 'Deployment Type'])
    table.add_row([sddc_state['name'], sddc_state['id'], sddc_state['sddc_state'], sddc_state['sddc_type'], sddc_state['resource_config']['region'], sddc_state['resource_config']['deployment_type']])
    print("\nThis is your current environment:")
    print (table)


def getSDDCS(**kwargs):
    """Prints all SDDCs in an Org with their clusters and number of hosts"""
    strProdURL = kwargs["strProdURL"]
    orgID = kwargs["ORG_ID"]
    sessiontoken = kwargs["sessiontoken"]

    sddcInfo = get_sddcs_json(strProdURL, orgID, sessiontoken)
    if sddcInfo == None:
        sys.exit(1)

    orgtable = PrettyTable(['OrgID'])
    orgtable.add_row([orgID])
    print(str(orgtable))
    table = PrettyTable(['Name', 'Cloud', 'Status', 'Hosts', 'ID'])
    for i in sddcInfo:
        hostcount = 0
        mySDDCs = get_sddc_info_json(strProdURL, orgID, sessiontoken, i['id'])
        clusters = mySDDCs['resource_config']['clusters']
        if clusters:
            hostcount = 0
            for c in clusters:
                hostcount += len(c['esx_host_list'])
        table.add_row([i['name'], i['provider'],i['sddc_state'], hostcount, i['id']])
    print(table)


def getVMs(**kwargs):   
    """ Gets a list of all compute VMs, with their power state and their external ID. """
    proxy_url = kwargs["proxy"]
    session_token = kwargs["sessiontoken"]

    json_response = get_vms_json(proxy_url, session_token)

    if json_response == None:
        sys.exit(1)

    extracted_dictionary = json_response['results']
    table = PrettyTable(['Display_Name', 'Status', 'External_ID'])
    for i in extracted_dictionary:
        table.add_row([i['display_name'], i['power_state'], i['external_id']])
    print("Virtual Machine List:")
    print(table)


def getSDDChosts(**kwargs):
    """Prints out all SDDC Hosts"""
    strProdURL = kwargs["strProdURL"]
    orgID = kwargs["ORG_ID"]
    sessiontoken = kwargs["sessiontoken"]
    sddcID = kwargs["SDDC_ID"]

    jsonResponse = get_sddc_info_json(strProdURL, orgID, sessiontoken, sddcID)
    if jsonResponse == None:
        print("API Error")
        sys.exit(1)

    cdcID = jsonResponse['resource_config']['vc_ip']
    cdcID = cdcID.split("vcenter")
    cdcID = cdcID[1]
    cdcID = cdcID.split("/")
    cdcID = cdcID[0]
    clusters = jsonResponse['resource_config']['clusters']
    table = PrettyTable(['Cluster', 'Name', 'Status', 'ID'])
    for c in clusters:
        for i in c['esx_host_list']:
            hostName = i['name'] + cdcID
            table.add_row([c['cluster_name'], hostName, i['esx_state'], i['esx_id']])
    print("SDDC Hosts:")
    print(table)


# ============================
# SDDC - TKG
# ============================


def enable_tkg(**kwargs):
    """Enable TKG on SDDC"""
    vmc_url = kwargs['strProdURL']
    auth_flag = kwargs['oauth']
    org_id = kwargs['ORG_ID']
    sddc_id = kwargs['SDDC_ID']
    session_token = kwargs['sessiontoken']
    egress_cidr = kwargs['egress_cidr']
    ingress_cidr = kwargs['ingress_cidr']
    namespace_cidr = kwargs['namespace_cidr']
    service_cidr = kwargs['service_cidr']

    cluster_id = get_sddc_cluster1_id(vmc_url, session_token, org_id, sddc_id)
    json_body = {
        "egress_cidr": [egress_cidr],
        "ingress_cidr": [ingress_cidr],
        "namespace_cidr": [namespace_cidr],
        "service_cidr": service_cidr
    }
    #Validate Cluster-1 in the SDDC will supported TKG
    print("Validating cluster for TKG...")
    cluster_val_id = tkg_validate_cluster_json(vmc_url, org_id, sddc_id, cluster_id, session_token)
    ctask_params={'task_id':cluster_val_id,'ORG_ID':org_id,'strProdURL':vmc_url, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**ctask_params)

    #Validate the supplied CIDRs are valid for TKG
    print("Validatin CIDR ranges for TKG...")
    network_val_id = tkg_validate_network_json(vmc_url, session_token, org_id, sddc_id, cluster_id, json_body)
    ntask_params={'task_id':network_val_id,'ORG_ID':org_id,'strProdURL':vmc_url, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**ntask_params)

    #Enable TKG on the SDDC
    print("Enabling TKG on cluster-1")
    tkg_val_id = enable_tkg_json(vmc_url, session_token, org_id, sddc_id, cluster_id, json_body)
    ttask_params={'task_id':tkg_val_id,'ORG_ID':org_id,'strProdURL':vmc_url, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**ttask_params)
    sys.exit("TKG has been enabled")


def disable_tkg(**kwargs):
    """Disable TKG on the SDDC"""
    vmc_url = kwargs['strProdURL']
    auth_flag = kwargs['oauth']
    org_id = kwargs['ORG_ID']
    sddc_id = kwargs['SDDC_ID']
    session_token = kwargs['sessiontoken']

    cluster_id = get_sddc_cluster1_id(vmc_url, session_token, org_id, sddc_id)

    tkg_val_id = disable_tkg_json(vmc_url, session_token, org_id, sddc_id, cluster_id)
    ttask_params = {'task_id': tkg_val_id, 'ORG_ID': org_id, 'strProdURL': vmc_url, 'sessiontoken': session_token, 'oauth': auth_flag, 'verbose': False}
    get_task_status(**ttask_params)
    sys.exit("TKG has been disabled")


# ============================
# VTC - AWS Operations
# ============================


def connect_aws_account(**kwargs):
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']
    auth_flag = kwargs['oauth']
    sddc_group_id = kwargs['sddc_group_id']
    aws_acc = kwargs['aws_account_id']
    region = kwargs['region_id']

    resource_params = {'sddc_group_id':sddc_group_id,'strProdURL':strProdURL,'org_id':org_id, 'sessiontoken':session_token}
    resource_id = get_resource_id(**resource_params)

    response = connect_aws_account_json(strProdURL, aws_acc, region, resource_id, org_id, session_token)
    json_response = response.json()
    if not response.ok :
        print("    Error: " + json_response['message'])
        sys.exit(1)
    task_id = json_response ['id']

    task_params={'task_id':task_id,'ORG_ID':org_id,'strProdURL':strProdURL, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**task_params)


def disconnect_aws_account(**kwargs):
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']
    auth_flag = kwargs['oauth']
    sddc_group_id = kwargs['sddc_group_id']
    aws_acc = kwargs['aws_account_id']

    resource_params = {'sddc_group_id':sddc_group_id,'strProdURL':strProdURL,'org_id':org_id, 'sessiontoken':session_token}
    resource_id = get_resource_id(**resource_params)

    response = disconnect_aws_account_json(strProdURL, aws_acc, resource_id, org_id, session_token)
    json_response = response.json()
    if not response.ok :
        print("    Error: " + json_response['message'])
        print("    Message: " + json_response['details'][0]['validation_error_message'])
        sys.exit(1)
    task_id = json_response ['id']

    task_params={'task_id':task_id,'ORG_ID':org_id, 'strProdURL':strProdURL,'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**task_params)


# ============================
# VTC - DXGW Operations
# ============================


def attach_dxgw(**kwargs):
    print("===== Add DXGW Association =========")

    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']
    auth_flag = kwargs['oauth']
    sddc_group_id = kwargs['sddc_group_id']
    dxgw_owner = kwargs['aws_account_id']
    dxgw_id = kwargs['dxgw_id']
    region = kwargs['region_id']
    routes = kwargs['prefix_list']
    res_params = {'sessiontoken':session_token, 'strProdURL':strProdURL, 'org_id':org_id, 'sddc_group_id':sddc_group_id}
    resource_id = get_resource_id(**res_params)

    json_response = attach_dxgw_json(strProdURL, routes, resource_id, org_id, dxgw_owner, dxgw_id, region, session_token)
    if json_response is None:
        print("Something went wrong.  Please check your config.ini file and parameters and try again.")
        sys.exit(1)
    else:
        pass
    task_id = json_response ['id']

    task_params={'task_id':task_id,'ORG_ID':org_id,'strProdURL':strProdURL, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**task_params)


def detach_dxgw(**kwargs):
    print("===== Remove DXGW Association =========")
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']
    auth_flag = kwargs['oauth']
    dxgw_id = kwargs['dxgw_id']
    sddc_group_id = kwargs['sddc_group_id']

    res_params = {'sessiontoken':session_token, 'strProdURL':strProdURL, 'org_id':org_id, 'sddc_group_id':sddc_group_id}
    resource_id = get_resource_id(**res_params)

    json_response = detach_dxgw_json(strProdURL, resource_id, org_id, dxgw_id, session_token)
    if json_response is None:
        print("Something went wrong.  Please check your config.ini file and parameters and try again.")
        sys.exit(1)
    else:
        pass
    task_id = json_response ['id']

    task_params={'task_id':task_id,'ORG_ID':org_id,'strProdURL':strProdURL, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**task_params)


# ============================
# VTC - SDDC Operations
# ============================


def attach_sddc(**kwargs):
    org_id = kwargs['ORG_ID']
    session_token =  kwargs['sessiontoken']
    strProdURL = kwargs['strProdURL']
    sddc_id = kwargs['sddc_id']
    sddc_group_id = kwargs['sddc_group_id']

    res_params = {'sessiontoken':session_token, 'strProdURL':strProdURL, 'org_id':org_id, 'sddc_group_id':sddc_group_id}
    resource_id = get_resource_id(**res_params)
    response = attach_sddc_json(strProdURL, sddc_id, resource_id, org_id, session_token)
    if response is None:
        print("Something went wrong.  Please check your config.ini file and parameters and try again.")
        sys.exit(1)
    else:
        pass
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['config']['operation_id']
    print(f'Task ID is {task_id}. Use get-task-status for a progress update.')


def detach_sddc(**kwargs):
    org_id = kwargs['ORG_ID']
    session_token =  kwargs['sessiontoken']
    strProdURL = kwargs['strProdURL']
    sddc_id = kwargs['sddc_id']
    sddc_group_id = kwargs['sddc_group_id']

    res_params = {'sessiontoken':session_token, 'strProdURL':strProdURL, 'org_id':org_id, 'sddc_group_id':sddc_group_id}
    resource_id = get_resource_id(**res_params)

    print("===== Removing SDDC =========")
    response = remove_sddc_json(strProdURL,sddc_id, resource_id, org_id, session_token)
    if response is None:
        print("Something went wrong.  Please check your config.ini file and parameters and try again.")
        sys.exit(1)
    else:
        pass
    json_response = response.json()
    if not response.ok :
        print ("    Error: " + json_response['message'])
        task_id = 0
    else:
        task_id = json_response ['config']['operation_id']
    print(f'Task ID is {task_id}. Use get-task-status for a progress update.')


def get_nsx_info(**kwargs):
    strProdURL = kwargs["strProdURL"]
    org_id = kwargs["ORG_ID"]
    session_token = kwargs["sessiontoken"]
    deployment_id = kwargs["deployment_id"]
    json_response = get_nsx_info_json(strProdURL, org_id, deployment_id, session_token)
    print("    NSX private IP:   " + json_response['nsx_private_ip'])
    for i in range (len(json_response['nsx_users'])):
        # Catch 'None' usernames and passwords in SDDCs prior to M15, convert to string so it displays properly
        username = json_response['nsx_users'][i]['user_name']
        if username is None:
            username = "None"
        password = json_response['nsx_users'][i]['password']
        if password is None:
            password = "None"
        print("    NSX User : " + username + " - Password: " + password)
    print("    NSX public FQDN:  " + json_response['nsx_public_fqdn'])
    print("    NSX private FQDN: " + json_response['nsx_private_fqdn'])
    print("    LOGIN URLs:")
    print("       Public CSP:    " + json_response['login_urls'][0]['preferred_url'])
    print("       Private CSP:   " + json_response['login_urls'][1]['preferred_url'])
    for i in range (len(json_response['login_urls'][1]['other_urls'])):
        print("                      " + json_response['login_urls'][1]['other_urls'] [i])
    print("       Private local: " + json_response['login_urls'][2]['preferred_url'])
    return


def get_deployments(**kwargs):
    strProdURL = kwargs["strProdURL"]
    org_id = kwargs["ORG_ID"]
    session_token = kwargs["sessiontoken"]
    json_response = get_deployments_json(strProdURL,org_id, session_token)
    table = PrettyTable(['ID', 'Name', 'Type', 'SAZ or MAZ', 'AZ'])
    if (json_response['empty'] == True):
        print("\n=====No SDDC found=========")
        sys.exit(1)
    else:
        for i in range(json_response['total_elements']):
            row = json_response['content'][i] 
            table.add_row([row['id'], row['name'], row['type']['code'], row['type']['deployment_type'], row['location']['code']])
    print(table)
    return


def get_resource_id(**kwargs):
    session_token = kwargs['sessiontoken']
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['org_id']
    sddc_group_id = kwargs['sddc_group_id']
    json_response = get_resource_id_json(strProdURL, org_id, sddc_group_id, session_token)
    if json_response is not None:
        resource_id = json_response[0]['id']
        return resource_id
    else:
        print("No results returned.")
        sys.exit(1)


# ============================
# VTC - SDDC Group Operations
# ============================


def create_sddc_group(**kwargs):
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']

    name = kwargs['name']
    description = kwargs['description']
    members = []
    if kwargs['deployment_groups'] is not None:
        for i in kwargs['deployment_groups']:
            d = {"id" : i}
            members.append(d)
    else:
        pass
    json_response = create_sddc_group_json(strProdURL, name, description, members, org_id, session_token)
    if json_response == None:
        sys.exit(1)
    task_id = json_response ['operation_id']
    print(f"The task id for the SSDC group {name} creation is: {task_id}. Use get-task-status for updates.")


def delete_sddc_group(**kwargs):
    ''' delete an existing SDDC resource group'''
    strProdURL = kwargs["strProdURL"]
    sddc_group_id = kwargs['sddc_group_id']  # the id of the group.
    org_id = kwargs["ORG_ID"]
    session_token = kwargs['sessiontoken']

    if (check_empty_group(strProdURL,sddc_group_id, org_id, session_token)):
        res_params = {'sessiontoken':session_token, 'strProdURL':strProdURL, 'org_id':org_id, 'sddc_group_id':sddc_group_id}
        resource_id = get_resource_id(**res_params)
        response = delete_sddc_group_json(strProdURL, resource_id, org_id, session_token)
        if response == None:
            sys.exit(1)
        print(f"The Task ID for the deletion of {resource_id} is {response ['id']}")
    else:
        print("SDDC Group not empty: detach all members")


def get_group_id(strProdURL, group, org_id, session_token):
    if DEBUG_MODE:
        print(f'DEBUG: In get_group_id(), group={group}')
    json_response = get_group_id_json(strProdURL, group, org_id, session_token)
    group_id = json_response['content'][int(group)-1]['id']
    if DEBUG_MODE:
        print(f'DEBUG: json_response group_id={group_id}')
    return group_id


def get_sddc_groups(**kwargs):
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']

    json_response = get_sddc_groups_json(strProdURL, org_id, session_token)
    # 
    if json_response == None:
        sys.exit(1)

    if (json_response['empty'] == True):
        print("     No SDDC Group found\n")
        return None
    else:
        print(f"SDDC Groups in Org: {org_id}:")
        group_table = PrettyTable(['id', 'Group Name', 'description', 'Deployment Type', 'State','Creator'])
        for i in range(json_response['total_elements']):
            row = json_response['content'][i]
            if 'description' not in row:
                row['description'] = "No description"
            group_table.add_row([row['id'],row['name'],row['description'],
               row['deployment_type']['deployment_type'] if ('deployment_type' in row) else 'NA' ,
               row['state']['display_name'],row['creator']['user_name']])
        print(group_table)
    return


def get_group_info(group_id, resource_id, org_id, session_token):
    json_response = get_group_info_json(strProdURL, org_id, group_id, session_token)
    print("\nORG ID      : " + json_response['org_id'])
    print("SDDC Group")
    print("==========")
    print("    Name      : " + json_response['name'])
    print("    Group ID  : " + json_response['id'])
    print("    Creator   : " + json_response['creator']['user_name'])
    print("    Date/Time : " + json_response['creator']['timestamp'])

    ext_json_response = ext_get_group_info_json(strProdURL, org_id, resource_id)
    print("SDDCs")
    print("=====")
    if 'AwsRealizedSddcConnectivityTrait' in ext_json_response['traits'] :
        if ext_json_response['traits']['AwsRealizedSddcConnectivityTrait']['sddcs'] != []:
            for i in range(len(ext_json_response['traits']['AwsRealizedSddcConnectivityTrait']['sddcs'])):
                print("    SDDC_ID " + str(i+1) + ": " + ext_json_response['traits']['AwsRealizedSddcConnectivityTrait']['sddcs'][i]['sddc_id'])  #loop here
        else:
            print("    No SDDC attached")

    print("Transit Gateway")
    print("===============")
    if 'AwsNetworkConnectivityTrait' in ext_json_response['traits'] :
        if ext_json_response['traits']['AwsNetworkConnectivityTrait']['l3connectors'] != []:
            print("    TGW_ID    : " + ext_json_response['traits']['AwsNetworkConnectivityTrait']['l3connectors'][0]['id'])
            print("    Region    : " + ext_json_response['traits']['AwsNetworkConnectivityTrait']['l3connectors'][0]['location']['name'])
        else:
            print("    No TGW")

    print("AWS info")
    print("========")
    if 'AwsVpcAttachmentsTrait' in ext_json_response['traits'] :
        if not ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts']:
            print("    No AWS account attached")
        else:
            print("    AWS Account  : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['account_number'])
            print("    RAM Share ID : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['resource_share_name'])
            print("    Status       : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['state'])
            if ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['state'] == "ASSOCIATING":
                print("        Go to AWS console/RAM and accept the share and wait for Status ASSOCIATED (5-10 mins)")
            else:
                print("VPC info")
                print("========")
                if not ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments']:
                    print("    No VPC attached")
                else:
                    for i in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'])):
                        print("    VPC " + str(i+1) + "        :" + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["vpc_id"])
                        print("        State         : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["state"])
                        print("        Attachment    : " + ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["attach_id"])
                        if ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["configured_prefixes"]:
                            print("        Static Routes : " + (', '.join(ext_json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][0]['attachments'][i]["configured_prefixes"])))
    else:
        print("    No AWS account attached")

    print("DX Gateway")
    print("==========")
    if 'AwsDirectConnectGatewayAssociationsTrait' in ext_json_response['traits'] :
        if not ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations']:
            print("    No DXGW Association")
        else:
            print("    DXGW ID   : " +  ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['direct_connect_gateway_id'])
            print("    DXGW Owner: " +  ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['direct_connect_gateway_owner'])
            print("    Status    : " +  ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['state'])
            print("    Prefixes  : " +  (', '.join(ext_json_response['traits']['AwsDirectConnectGatewayAssociationsTrait']['direct_connect_gateway_associations'][0]['peering_regions'][0]['allowed_prefixes'])))

    else:
        print("    No DXGW Association")
    return


def check_empty_group(strProdURL, group_id, org_id, session_token):
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/inventory/{}/core/deployment-groups/{}".format(strProdURL, org_id, group_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # print(len(json_response['membership']['included']))
    if (len(json_response['membership']['included']) != 0):
        return False
    return True


# ============================
# VTC - TGW Operations
# ============================


def get_route_tables(strProdURL, resource_id, org_id, session_token):
    json_response = get_route_tables_json(strProdURL, resource_id, org_id, session_token)
    if  not json_response['content']:       #'content' is empty []
        print("    Routing Tables empty")
    else:
        members_id = json_response['content'][0]['id']
        external_id = json_response['content'][1]['id']
        print("     Members route domain: Routes to all SDDCs, VPCs and Direct Connect Gateways")
        mem_json_response = vtgw_route_json(strProdURL, org_id, resource_id, members_id, session_token)
        for i in range(len(mem_json_response['content'])):
            print("\tDestination: " + mem_json_response['content'][i]['destination'] + "\t\tTarget: " + mem_json_response['content'][i]['target']['id'])
        ext_json_response = vtgw_route_json(strProdURL, org_id, resource_id, external_id, session_token)
        print("     External (VPC and Direct Connect Gateway) route domain: Routes only to member SDDCs")
        for i in range(len(ext_json_response['content'])):
            print("\tDestination: " + ext_json_response['content'][i]['destination'] + "\t\tTarget: " + ext_json_response['content'][i]['target']['id'])
    return


def get_task_status(**kwargs):
    strProdURL = kwargs['strProdURL']
    task_id = kwargs['task_id']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']
    verbose = kwargs['verbose']
    auth_flag = kwargs['oauth']

    """Take the inputs on a task and then LOOP Until done """ 
    json_response = get_task_status_json(strProdURL,task_id, org_id, session_token)
    if json_response == None:
        sys.exit(1) 
    status = json_response ['state']['name']
    print(status)
    start = time.time()
    new_session_token = ""
    while(status != "COMPLETED"):
        current_time = time.strftime("%H:%M:%S", time.localtime())
        if verbose: 
            print(f'\nPrinting Info on task {task_id} at {current_time}')
            print(json.dumps(json_response, indent = 4))
        else:
            sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(2)
        elapse = time.time() - start
        if elapse >= 1700 : # session_token is only valid for 1800 sec. Over 1700, will need a new token.
            if not new_session_token :
                sys.stdout.write("Generating a new session_token")
                config_params = read_config()
                # Depending on params in config.ini use OAuth or Refresh Token for auth
                auth_params = {}
                try:
                    match auth_flag:
                        case "oauth":
                            auth_params = {'auth_method':auth_flag, 'strCSPProdURL':config_params['strCSPProdURL'], 'oauth_clientSecret':config_params['clientSecret'], 'oauth_clientId':config_params['clientId']}
                            new_session_token = getAccessToken(**auth_params)
                        case "refresh_token":
                            auth_params = {'auth_method':auth_flag, 'strCSPProdURL':config_params['strCSPProdURL'], 'myKey':config_params['Refresh_Token']}
                            new_session_token = getAccessToken(**auth_params)
                except:
                    auth_params = {'auth_method':"refresh_token", 'strCSPProdURL':config_params['strCSPProdURL'], 'myKey':config_params['Refresh_Token']}
                    new_session_token = getAccessToken(**auth_params)
                session_token = new_session_token
        json_response = get_task_status_json(strProdURL,task_id, org_id, session_token)
        if json_response == None:
            sys.exit(1)
        status = json_response ['state']['name']
        if status == "FAILED":
            print("\nTask FAILED ")
            print("error message: " + json_response['state']['error_msg'])
            print("error code: " + json_response['state']['error_code'])
            sys.exit(1)
    elapse = time.time() - start
    minutes = elapse // 60
    seconds = elapse - (minutes * 60)
    print("\nFINISHED in", '{:02}min {:02}sec'.format(int(minutes), int(seconds)))
    return

# ============================
# VTC - VPC Operations
# ============================

def attach_vpc(**kwargs):
    print("=====Attaching VPCs=========")
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']
    auth_flag = kwargs['oauth']
    sddc_group_id = kwargs['sddc_group_id']
    aws_acc = kwargs['aws_account_id']

    resource_params = {'sddc_group_id':sddc_group_id,'strProdURL':strProdURL,'org_id':org_id, 'sessiontoken':session_token}
    resource_id = get_resource_id(**resource_params)

    pend_att_params = {'strProdURL':strProdURL,'resource_id':resource_id, 'org_id':org_id, 'sessiontoken':session_token}
    vpc_list = get_pending_att(**pend_att_params)

    if vpc_list == []:
        print('   No VPC to attach')
        sys.exit(1)
    else:
        n = input('   Select VPC to attach: ')

    json_body = {
        "type": "APPLY_ATTACHMENT_ACTION",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
                "type": "AwsApplyAttachmentActionConfig",
                "account" : {
                    "account_number": aws_acc,
                    "attachments": [
                        {
                            "action": "ACCEPT",
                            "attach_id": vpc_list[int(n)-1]
                        }
                    ]
                }
            }
        }
    json_response = attach_vpc_json(strProdURL, session_token, json_body, org_id)
    task_id = json_response ['id']

    task_params={'task_id':task_id,'ORG_ID':org_id,'strProdURL':strProdURL, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**task_params)


def detach_vpc(**kwargs):
    print("=====Detaching VPCs=========")
    strProdURL = kwargs['strProdURL']
    org_id = kwargs['ORG_ID']
    session_token = kwargs['sessiontoken']
    auth_flag = kwargs['oauth']
    sddc_group_id = kwargs['sddc_group_id']
    aws_acc = kwargs['aws_account_id']

    resource_params = {'strProdURL':strProdURL,'sddc_group_id':sddc_group_id,'strProdURL':strProdURL,'org_id':org_id, 'sessiontoken':session_token}
    resource_id = get_resource_id(**resource_params)

    avail_att_params = {'strProdURL':strProdURL,'resource_id':resource_id, 'org_id':org_id, 'sessiontoken':session_token}
    vpc_list = get_available_att(**avail_att_params)
    if vpc_list == []:
        print('   No VPC to detach')
        sys.exit(1)
    else:
        n = input('  Select VPC to detach: ')

    json_body = {
        "type": "APPLY_ATTACHMENT_ACTION",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
                "type": "AwsApplyAttachmentActionConfig",
                "account" : {
                    "account_number": aws_acc,
                    "attachments": [
                        {
                            "action": "DELETE",
                            "attach_id": vpc_list[int(n)-1]
                        }
                    ]
                }
            }
        }
    json_response = detach_vpc_json(strProdURL, session_token, json_body, org_id)
    task_id = json_response ['id']

    task_params={'task_id':task_id,'ORG_ID':org_id,'strProdURL':strProdURL, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**task_params)


def get_pending_att(**kwargs):
    strProdURL = kwargs['strProdURL']
    resource_id=kwargs['resource_id']
    org_id=kwargs['org_id']
    session_token=kwargs['sessiontoken']
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/{}?trait=AwsVpcAttachmentsTrait".format(strProdURL, org_id, resource_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    vpcs=[]
    n=1
    if 'AwsVpcAttachmentsTrait' in json_response['traits'] :
        for i in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'])):
            print("Account: " + json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['account_number'])
            if json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'] == None:        #'attachements' doesnt exists
                print("   No VPCs Pending Acceptance")
            else:
                for j in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'])):
                    if json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['state'] == "PENDING_ACCEPTANCE":
                        print(str(n) +": " + "VPC attachment = " + str(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id']))
                        vpcs.append(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id'])
                        n=n+1
    else:
        print("No AWS account attached")
    return vpcs


def get_available_att(**kwargs):
    strProdURL = kwargs['strProdURL']
    resource_id=kwargs['resource_id']
    org_id=kwargs['org_id']
    session_token=kwargs['sessiontoken']
    myHeader = {'csp-auth-token': session_token}
    myURL = "{}/api/network/{}/core/network-connectivity-configs/{}?trait=AwsVpcAttachmentsTrait".format(strProdURL, org_id, resource_id)
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    # pretty_data = json.dumps(response.json(), indent=4)
    # print(pretty_data)
    vpcs=[]
    n=1
    for i in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'])):
        print("Account: " + json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['account_number'])
        for j in range(len(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'])):
            if json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['state'] == "AVAILABLE":
                print(str(n) +": " + "VPC attachment = " + str(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id']))
                vpcs.append(json_response['traits']['AwsVpcAttachmentsTrait']['accounts'][int(i)]['attachments'][int(j)]['attach_id'])
                n=n+1
    return vpcs


def add_vpc_prefixes(**kwargs):
    print("===== Adding/Removing VPC Static Routes =========")
    org_id = kwargs['ORG_ID']
    session_token =  kwargs['sessiontoken']
    strProdURL = kwargs['strProdURL']
    aws_acc = kwargs['aws_account_id']
    auth_flag = kwargs['oauth']
    sddc_group_id = kwargs['sddc_group_id']

    res_params = {'sessiontoken':session_token, 'strProdURL':strProdURL, 'org_id':org_id, 'sddc_group_id':sddc_group_id}
    resource_id = get_resource_id(**res_params)

    attachment_params = {'strProdURL':strProdURL, 'resource_id':resource_id, 'org_id':org_id, 'sessiontoken':session_token}
    vpc_list = get_available_att(**attachment_params)
    if vpc_list == []:
        print('   No VPC attached')
        sys.exit(0)
    else:
        n = input('   Select VPC: ')
        att_id = vpc_list[int(n)-1]

        routes = input ('   Enter route(s) to add (space separated), or press Enter to remove all: ')
        user_list = routes.split()

    json_body = {
        "type": "APPLY_ATTACHMENT_ACTION",
        "resource_id": resource_id,
        "resource_type": "network-connectivity-config",
        "config" : {
            "type": "AwsApplyAttachmentActionConfig",
            "account" : {
                "account_number": aws_acc,
                "attachments": [
                        {
                        "action": "UPDATE",
                        "attach_id": att_id,
                        "configured_prefixes": user_list
                        }
                    ]
                }
            }
        }

    json_response = add_vpc_prefixes_json(strProdURL, session_token, json_body, org_id)
    task_id = json_response ['id']
    task_params={'task_id':task_id,'ORG_ID':org_id,'strProdURL':strProdURL, 'sessiontoken':session_token, 'oauth':auth_flag, 'verbose':False}
    get_task_status(**task_params)


# ============================
# VTC - TGW Operations
# ============================


def attach_tgw(**kwargs):
    """Function to attach a customer TGW to a vTGW"""


# ============================
# NSX-T - all
# ============================


def search_nsx(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    object_type = kwargs['object_type']
    if kwargs['object_id'] is None:
        object_id = "NULL"
    else:
        object_id = kwargs['object_id']
    json_response = search_nsx_json(proxy, sessiontoken, object_type, object_id)
    # Print total result count - used for debugging purposes.  Comment out when unused.
    # print(f'Total results: {json_response["result_count"]}')
    results = json_response['results']
    # Print total total JSON payload - used for debugging purposes.  Comment out when unused.
    # print(json.dumps(results, indent = 2))
    print("")
    if object_type == "BgpNeighborConfig":
        if len(results) !=0:
            table = generate_table(results)
            print(table.get_string(fields=["resource_type", "display_name",  "id", "neighbor_address", "remote_as_num"]))
        else:
            print("None found.")
    elif object_type == "BgpRoutingConfig":
        for item in results:
            if not 'route_aggregations' in item:
                item['route_aggregations'] = "--"
        if len(results) !=0:
            table = generate_table(results)
            print(table.get_string(fields=["resource_type", "display_name", "id", "enabled", "ecmp",  "route_aggregations"]))
        else:
            print("None found.")
    elif object_type == "Group":
        for item in results:
            if not 'description' in item:
                item['description'] = "--"
            if len(item['expression']) > 0:
                if 'ip_addresses' in item['expression'][0]:
                    item['ip_addresses'] = item['expression'][0]['ip_addresses']
                else:
                    item['ip_addresses'] = "--"
        if len(results) !=0:
            table = generate_table(results)
            table._max_width = {"display_name" : 35, "description" : 50, "ip_addresses" : 20}
            print(table.get_string(fields=["display_name", "description", "ip_addresses"]))
        else:
            print("None found.")
    elif object_type == "IdsSignature":
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["display_name", "cves", "attack_target", "cvss"]))
    elif object_type == "PrefixList":
        for item in results:
            if not 'description' in item:
                item['description'] = "--"
            if not item.get("prefixes"):
                item.clear()
        results = list(filter(None, results))
        if len(results) !=0:
            table = generate_table(results)
            table._max_width = {"prefixes" : 50}
            print(table.get_string(fields=["resource_type", "id", "description","prefixes"]))
        else:
            print("None found.")
    elif object_type == "RouteBasedIPSecVpnSession":
        for item in results:
            item['bgp ip_addresses'] = item['tunnel_interfaces'][0]['ip_subnets'][0]['ip_addresses']
            item['bgp prefix length'] = item['tunnel_interfaces'][0]['ip_subnets'][0]['prefix_length']
        if len(results) !=0:
            table = generate_table(results)
            print(table.get_string(fields=[ "display_name", "resource_type", "peer_id",  "peer_address", "bgp ip_addresses", "bgp prefix length"]))
    elif object_type == "Segment":
        for item in results:
            if 'subnets' in item:
                if 'network' in item['subnets'][0]:
                    item['network'] = item['subnets'][0]['network']
                else:
                    item['network'] = "--"
                if 'gateway_address' in item ['subnets'][0]:
                    item['gateway_address'] = item['subnets'][0]['gateway_address']
                else:
                    item['gateway_address'] = "--"
                if 'dhcp_ranges' in item['subnets'][0]:
                    item['dhcp_ranges'] = item['subnets'][0]['dhcp_ranges']
                else:
                    item['dhcp_ranges'] = "--"
            else:
                item['network'] = "--"
                item['gateway_address'] = "--"
                item['dhcp_ranges'] = "--"
            if 'connectivity_path' not in item:
                item['connectivity_path'] ="--"
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id", "type", "network", "gateway_address", "dhcp_ranges", "connectivity_path"]))
    elif object_type == "Service":
        for item in results:
            if 'source_ports' in item['service_entries'][0]:
                item['source_ports'] = item['service_entries'][0]['source_ports']
            else:
                item['source_ports'] = "--"
            if 'destination_ports' in item['service_entries'][0]:
                item['destination_ports'] = item['service_entries'][0]['destination_ports']
            else:
                item['destination_ports'] = "--"
        if len(results) !=0:
            table = generate_table(results)
        table._max_width = {"resource_type" : 15, "display_name" : 40, "id" : 40 , "source_ports": 20, "destination_ports" : 20}
        print(table.get_string(fields=["resource_type", "display_name", "id", "source_ports", "destination_ports"]))
    elif object_type == "StaticRoutes":
        for item in results:
            item['next_hops'] = item['next_hops'][0]['ip_address']
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id", "network", "next_hops"]))
    elif object_type == "Tier0":
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id"]))
    elif object_type == "Tier1":
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "id", "type", "tier0_path", "path"]))
    elif object_type == "VirtualMachine":
        for item in results:
            item['computer_name'] = item['guest_info']['computer_name']
            item['os_name'] = item['guest_info']['os_name']
            item['target_display_name'] = item['source']['target_display_name']
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "computer_name", "os_name", "target_display_name", "display_name", "external_id"]))
    elif object_type == "VirtualNetworkInterface":
        for item in results:
            if len(item['ip_address_info']) > 0:
                if 'ip_addresses' in item['ip_address_info'][0]:
                    item['ip_addresses'] = item['ip_address_info'][0]['ip_addresses']
            else:
                item['ip_addresses'] = "--"
        if len(results) !=0:
            table = generate_table(results)
        print(table.get_string(fields=["resource_type", "display_name", "owner_vm_type", "owner_vm_id", "mac_address", "ip_addresses"]))

# ============================
# NSX-T - Advanced Firewall
# ============================

def getNsxIdsEnabledClusters(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_response = get_nsx_ids_cluster_enabled_json(proxy, sessiontoken)
    if json_response is not None:
        clustersTable = PrettyTable(['Cluster ID', 'Distributed IDS Enabled'])
        cluster_array = json_response['results']
        for i in cluster_array:
            cluster_config = get_nsx_ids_cluster_config_json(proxy, sessiontoken, i['id'])
            if cluster_config is not None:
                clusterStatus = cluster_config['ids_enabled']
                clusterID = cluster_config['id']
                clustersTable.add_row([clusterID, clusterStatus])
                print(clustersTable)
            else:
                print("Something went wrong.  Please check your syntax and try again.")
                sys.exit(1)
    else:
        print("Something went wrong.  Please check your syntax and try again.")
        sys.exit(1)
        

def enableNsxIdsCluster(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    targetID = kwargs['cluster_id']
    json_data = {
        "ids_enabled": True,
        "cluster": {
            "target_id": targetID
        }
    }
    response = enable_nsx_ids_cluster_json(proxy, sessiontoken, targetID, json_data)
    if response.status_code == 200:
        print(f"IDS enabled on cluster {targetID}")


def disableNsxIdsCluster(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    targetID = kwargs['cluster_id']

    json_data = {
        "ids_enabled": False,
        "cluster": {
            "target_id": targetID
        }
    }
    response = disable_nsx_ids_cluster_json(proxy, sessiontoken, targetID, json_data)
    if response.status_code == 200:
        print("IDS disabled on cluster {}".format(targetID))


def enableNsxIdsAll(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    clusters_json = get_nsx_ids_cluster_enabled_json(proxy, sessiontoken)
    if clusters_json is not None:
        cluster_array = clusters_json['results']
        for i in cluster_array:
            targetID = i['id']
            ids_status = i['ids_enabled']
            if ids_status == False:
                json_body = {
                    "ids_enabled": True,
                    "cluster": {
                        "target_id": targetID
                    }
                }
                response = enable_nsx_ids_cluster_json(proxy, sessiontoken, targetID, json_body)
                if response.status_code != 200:
                    print("Something went wrong.  Please check your syntax and try again.")
                    sys.exit(1)
                else:
                    pass
            else:
                pass
    else:
        print("Something went wrong.  Please check your syntax and try again.")
        sys.exit(1)
    params = {'proxy':proxy, 'sessiontoken':sessiontoken}
    getNsxIdsEnabledClusters(**params)


def disableNsxIdsAll(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    clusters_json = get_nsx_ids_cluster_enabled_json(proxy, sessiontoken)
    if clusters_json is not None:
        clustersTable = PrettyTable(['Cluster ID', 'Distributed IDS Enabled'])
        cluster_array = clusters_json['results']
        for i in cluster_array:
            targetID = i['id']
            ids_status = i['ids_enabled']
            if ids_status == True:
                json_body = {
                    "ids_enabled": False,
                    "cluster": {
                        "target_id": targetID
                    }
                }
                response = disable_nsx_ids_cluster_json(proxy, sessiontoken, targetID, json_body)
                if response.status_code != 200:
                    print("Something went wrong.  Please check your syntax and try again.")
                    sys.exit(1)
                else:
                    pass
            else:
                pass
    else:
        print("Something went wrong.  Please check your syntax and try again.")
        sys.exit(1)
    params = {'proxy':proxy, 'sessiontoken':sessiontoken}
    getNsxIdsEnabledClusters(**params)


def enableNsxIdsAutoUpdate(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_data = {
        "auto_update": True
    }
    response = enable_nsx_ids_auto_update_json(proxy, sessiontoken, json_data)
    if response == 202:
        print("IDS Signature auto-update enabled")
    else:
        print("Something went wrong.  Please check your syntax and try again.")


def NsxIdsUpdateSignatures(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    response = nsx_ids_update_signatures_json(proxy, sessiontoken)
    if response.status_code == 202:
        print("Signature update started")
    else:
        print("Something went wrong.  Please check your syntax and try again.")


def getNsxIdsSigVersions(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    response = get_ids_signature_versions_json(proxy, sessiontoken)
    sigTable = PrettyTable(['Signature Version', 'State', 'Status', 'Update Time (UTC)'])
    sigResponse = response['results']
    for i in sigResponse:
        sigVer = i['version_id']
        sigState = i['state']
        sigStatus = i['status']
        sigTimeUnix = i['update_time']
        sigTimeUnix /= 1000
        sigTime = datetime.utcfromtimestamp(sigTimeUnix).strftime('%Y-%m-%d %H:%M:%S')
        sigTable.add_row([sigVer, sigState, sigStatus, sigTime])
    sigTable.sortby = "State"
    print(sigTable)


def getIdsProfiles(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    response = get_ids_profiles_json(proxy, sessiontoken)
    profileTable = PrettyTable(['Name', 'Severity', 'Filter Name', 'Filter Value'])
    profileResponse = response['results']
    for i in range(len(profileResponse)):
        profileName = profileResponse[i]['display_name']
        profileSev = profileResponse[i]['profile_severity']
        if 'criteria' in profileResponse[i]:
            profileCriteriaArray = profileResponse[i]['criteria']
            for x in range(len(profileCriteriaArray)):
                if 'resource_type' in profileCriteriaArray[x] and profileCriteriaArray[x][
                    'resource_type'] == "IdsProfileFilterCriteria":
                    filterName = profileCriteriaArray[x]['filter_name']
                    filterValue = profileCriteriaArray[x]['filter_value']
                    profileTable.add_row([profileName, profileSev, filterName, filterValue])
                else:
                    pass

        else:
            profileTable.add_row([profileName, profileSev, "", ""])
    print(profileTable)


def search_ids_signatures_product_affected(**kwargs):
    """Returns a table consisting of the IDS Signature Product Affected based on the search term for assistance
    in building the IDS Profile"""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_response = search_nsx_json(proxy, sessiontoken, "IdsSignature", "NULL")
    idsSigs = json_response['results']
    print("Loading Signatures....")
    while 'cursor' in json_response:
        json_response = search_nsx_json_cursor(proxy, sessiontoken, "IdsSignature", "NULL", json_response['cursor'])
        idsSigs2 = json_response['results']
        idsSigs.extend(idsSigs2)
    df = pd.DataFrame(idsSigs)
    sigs = df.drop(columns=['_last_modified_user', '_protection', '_last_modified_time', 'marked_for_delete',
                            '_revision', '_system_owned', '_create_user', '_create_time', 'overridden',
                            'path', 'urls', 'class_type', 'parent_path', 'categories', 'id', 'flow', 'resource_type',
                            'signature_revision', 'relative_path', 'display_name'])
    ids_table = PrettyTable(['Product Affected'])
    ids_prod_affected = sigs['product_affected']
    ids_prod_affected = ids_prod_affected.drop_duplicates()
    user_input = input("Please input your search term: ")
    ids_prod_affected = ids_prod_affected.tolist()
    for i in ids_prod_affected:
        if search(user_input, i, re.IGNORECASE):
            ids_table.add_row([i])
    print(ids_table)


def listIdsPolicies(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_response = get_ids_policies_json(proxy, sessiontoken)
    policyTable = PrettyTable(['Policy Name', 'Stateful', 'Locked'])
    policyResponse = json_response['results']
    for i in range(len(policyResponse)):
        policyName = policyResponse[i]['display_name']
        policyState = policyResponse[i]['stateful']
        policyLocked = policyResponse[i]['locked']
        policyTable.add_row([policyName, policyState, policyLocked])
    print(policyTable)


def create_ids_profile(**kwargs):
    """Create an IDS Profile"""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    display_name = kwargs['objectname']
    # stage the necessary JSON payload
    json_data = {
        "profile_severity": [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ],
        "criteria": [],
        "resource_type": "IdsProfile",
        "display_name": display_name,
        "id": display_name
    }
    # set value for CVSS severity, if configured by user
    if kwargs['cvss'] is not None:
        cvss = kwargs['cvss']
        cvss_criteria =  {
            "filter_name": "CVSS",
            "filter_value": cvss,
            "resource_type": "IdsProfileFilterCriteria"
        }
        filter_operator = {
                "operator": "AND",
                "resource_type": "IdsProfileConjunctionOperator"
            }
    # update 'criteria' key in json payload
        json_data['criteria'].append(cvss_criteria)
        json_data['criteria'].append(filter_operator)
    # set value(s) for products affected, if configured by user
    if kwargs['product_affected'] is not None:
        pa = kwargs['product_affected']
        pa_criteria = {
            "filter_name": "PRODUCT_AFFECTED",
            "filter_value": pa,
            "resource_type": "IdsProfileFilterCriteria"
        }
    # update 'criteria' key in json payload
        json_data['criteria'].append(pa_criteria)
    response_code = patch_ips_profile_json(proxy, sessiontoken, json_data, display_name)
    if response_code == 200:
        print(f'The IDS Profile {display_name} has been created successfully')
    else:
        print(f'There was an error, please check your syntax')
        sys.exit(1)

def delete_ids_profile(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    display_name = kwargs['objectname']
    response_code = delete_ips_profile_json(proxy, sessiontoken, display_name)
    if response_code == 200:
        print(f'The IDS Profile {display_name} has been deleted.')
        params = {"proxy":proxy, "sessiontoken":sessiontoken}
        getIdsProfiles(**params)        
    else:
        print(f'There was an error, please check your syntax')
        sys.exit(1)


def create_ids_policy(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    if kwargs['objectname'] is None:
        print("Please use -n to specify the name of the segment to be configured.  Consult the help for additional options.")
        sys.exit(1)
    display_name = kwargs['objectname']
    json_data = {
        "resource_type": "IdsSecurityPolicy",
        "display_name": display_name,
        "id": display_name,
    }

    response_code = put_ids_policy_json(proxy, sessiontoken, json_data, display_name)
    if response_code == 200:
        print(f'The IDS policy {display_name} has been created successfully')
    else:
        print('There was an error, please check your syntax')
        sys.exit(1)


def get_ids_rules(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    ids_policies_json = get_ids_policies_json(proxy, sessiontoken)
    ids_policies_json = ids_policies_json['results']
    for i in ids_policies_json:
        ids_policy_name = i['display_name']
        ids_table = PrettyTable()
        ids_table.title = f'IDS Rules for IDS Policy {ids_policy_name}'
        ids_table.field_names = ['Display Name', 'Source Group', 'Destination Group', 'IDS Profile', 'Services', 'Scope', 'Action', 'Logged']
        ids_rule_json = get_ids_rule_json(proxy, sessiontoken, ids_policy_name)
        ids_rule_json = ids_rule_json['results']
        for r in ids_rule_json:
            ids_table.add_row([r['display_name'], r['source_groups'], r['destination_groups'], r['ids_profiles'], r['services'], r['scope'], r['action'], r['logged']])
        print(ids_table)


def create_ids_rule(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']

#   Load variables from positional arguments
    display_name = kwargs['objectname']
    idspro = kwargs['ids_profile']
    idspol = kwargs['ids_policy']
    
#   Load variables from optional arguments
    if kwargs['source_group'] is not None:
        srcgrp = kwargs['source_group']
    if kwargs['dest_group'] is not None:
        destgrp = kwargs['dest_group']
        
#   Exit if both source and destination are set to ANY (unpermitted configuration)
    if srcgrp == ["any"] and destgrp == ["any"]:
        print('''
        For IDS, it is not permitted for both SOURCE and DEST to be set to 'ANY'. 
        Either source or destination should have groups that are configured for CGW.
        Use './pyVMC.py inventory show-group cgw' to display currently configured groups for the Compute Gateway.
        ''')
        sys.exit(1)
    else:
        pass

#   stage the JSON payload
    json_data = {
        "resource_type": "IdsRule",
        "id": display_name,
        "display_name": display_name,
        "direction": "IN_OUT",
        "ip_protocol": "IPV4_IPV6",
        "logged": False
    }

#   Load remaining variables from optional arguments
    if kwargs['action'] is not None:
        act = kwargs['action']
        json_data['action'] = act
    if kwargs['scope'] is not None:
        scp = kwargs['scope']
    if kwargs['services'] is not None:
        srvc = kwargs['services']

#   Build variables and lists to use in JSON payload
#   Profile and policy settings
    idsprolstr = [f'/infra/settings/firewall/security/intrusion-services/profiles/{idspro}']
    json_data['ids_profiles'] = idsprolstr
    idspolstr = f'/infra/domains/cgw/intrusion-service-policies/{idspol}'
    json_data["parent_path"] = idspolstr

#   Source group settings
    srcgrplst = []
    if srcgrp == 'ANY':
        srcgrplst = ['ANY']
    else:
        for i in srcgrp:
            srcgrpitem = f'/infra/domains/cgw/groups/{i}'
            srcgrplst.append(srcgrpitem)
    json_data['source_groups'] = srcgrplst

#   Destination group settings
    destgrplst = []
    if destgrp == 'ANY':
        destgrplst = ['ANY']
    else:
        for i in destgrp:
            dstgrpitem = f'/infra/domains/cgw/groups/{i}'
            destgrplst.append(dstgrpitem)
    json_data['destination_groups'] = srcgrplst

    # Services settings
    srvclst = []
    if srvc == 'ANY':
        srvclst = ['ANY']
    else:
        for i in srvc:
            srvcitem = f'/infra/services/{i}'
            srvclst.append(srvcitem)
    json_data['services'] = srvclst

#   Scope settings
    scplst = []
    if scp == 'ANY':
        scplst = ['ANY']
    else:
        for i in scp:
            scpitem = f'/infra/domains/cgw/groups/{i}'
            scplst.append(scpitem)
    json_data['scope'] = scplst
    json_response_code = put_ids_rule_json(proxy, sessiontoken, display_name, idspol, json_data)
    if json_response_code == 200:
        print(f'IDS Rule {display_name} was successfully created under IDS Policy {idspol}')
    else:
        print(f'There was an error, please check your syntax')


def delete_ids_policy(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    ids_policy_name = kwargs['objectname']
    json_response_code = delete_ids_policy_json(proxy, sessiontoken, ids_policy_name)
    if json_response_code == 200:
        print(f'IDS Policy {ids_policy_name} has been deleted')
    else:
        print(f'There was an error, please check your syntax')


def delete_ids_rule(**kwargs):
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    ids_rule_name = kwargs['objectname']
    ids_policy_name = kwargs['ids_policy']
    json_response_code = delete_ids_rule_json(proxy, session_token, ids_rule_name, ids_policy_name)
    if json_response_code == 200:
        print(f'IDS Rule {ids_rule_name} part of IDS Policy {ids_policy_name} has been deleted')
    else:
        print(f'There was an error, please check your syntax')


# ============================
# NSX-T - BGP and Routing
# ============================


def attachT0BGPprefixlist(**kwargs):
    """Attaches identified prefix list to a route-based VPN"""
    proxy = kwargs['proxy']
    session_token =  kwargs['sessiontoken']

    # set the neighbor ID, retrieve the configuration of the neighbor from NSX, clear unwanted keys from JSON
    if kwargs['neighbor_id'] is not None:
        neighbor_id = kwargs['neighbor_id']
        neighbor_json = get_sddc_t0_bgp_single_neighbor_json(proxy, session_token, neighbor_id)
        if neighbor_json != False:
            for key in list(neighbor_json.keys()):
                if key.startswith('_'):
                    del neighbor_json[key]
        else:
            print("Something went wrong, please try again.")
            sys.exit(1)
    else:
        print("Please specify the BGP neighbor ID to configure using --neighbor-id.  Use 'pyVMC.py bgp show --neighbors for a list.'")
        sys.exit(1)

    # If "interactive" mode is FALSE, check that user has provided prefix list ID and route filter choice
    match kwargs['interactive']:
        case False:
            if kwargs['prefix_list_id'] is not None:
                prefix_list_id = kwargs['prefix_list_id']
            else:
                print("Please specify the prefix list ID to configure using --prefix-list-id.  Use 'pyVMC.py rbvpn-prefix-list show' for a list.")
                sys.exit(1)
            if kwargs['route_filter'] is not None:
                route_filter = kwargs['route_filter']
            else:
                print("Please specify the prefix list ID to configure using --prefix-list-id.  Use 'pyVMC.py rbvpn-prefix-list show' for a list.")
                sys.exit(1)
            # proceed to attach prefix list
            neighbor_json['route_filtering'][0][f'{route_filter}_route_filters'] = [f'/infra/tier-0s/vmc/prefix-lists/{prefix_list_id}']
            status_code = attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json)
            if status_code == 200:
                print(f'Status {status_code}. Complete - route filter entry:')
                print()
                pretty_json = json.dumps(neighbor_json["route_filtering"], indent=2)
                print(pretty_json)
                print()
            else:
                print(f'Status {status_code}. Prefix list was NOT attached.')
                sys.exit(1)

        # If Interactive is TRUE, then prompt the user for input on what to do next
        case False:
            # while loop (as above in new prefix list function) - present user with choices - add prefix list, clear prefix lists, commit changes, abort.
            # begin input loop
            test = ''
            while test != "5":
                print("\nPlease select an option:")
                print("\t1- Review neighbor config ")
                print("\t2- Add in_route_filter (only one allowed) ")
                print("\t3- Add out_route_filter (only one allowed) ")
                print("\t4- Clear all prefix lists")
                print("\t5- Commit changes")
                print("\t6- Abort")
                print("\n")
                test=input('What would you like to do? ')
                if test == "1":
                    pretty_json = json.dumps(neighbor_json, indent=2)
                    print(pretty_json)
                    print()
                elif test == "2":
                    prefix_list_id = input('Please enter the prefix list ID exactly ')
                    neighbor_json['route_filtering'][0]["in_route_filters"] = [f'/infra/tier-0s/vmc/prefix-lists/{prefix_list_id}']
                    print()
                    print(f'Prefix list {prefix_list_id} has been added to in_route_filters in JSON for neighbor id {neighbor_id}. Please review and commit.')
                    print()
                elif test =="3":
                    prefix_list_id = input('Please enter the prefix list ID exactly ')
                    neighbor_json['route_filtering'][0]["out_route_filters"] = [f'/infra/tier-0s/vmc/prefix-lists/{prefix_list_id}']
                    print()
                    print(f'Prefix list {prefix_list_id} has been added to out_route_filters in JSON for neighbor id {neighbor_id}. Please review and commit.')
                    print()
                elif test =="4":
                    if neighbor_json.get("in_route_filters"):
                        del neighbor_json["in_route_filters"]
                    if neighbor_json.get("out_route_filters"):
                        del neighbor_json["out_route_filters"]
                    neighbor_json['route_filtering'] = [{'enabled': True, 'address_family': 'IPV4'}]
                elif test == "5":
                    status_code = attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json)
                    if status_code == 200:
                        print(f'Status {status_code}. Complete - route filter entry:')
                        print()
                        pretty_json = json.dumps(neighbor_json["route_filtering"], indent=2)
                        print(pretty_json)
                        print()
                    else:
                        print(f'Status {status_code}. Prefix list was NOT attached.')
                        sys.exit(1)
                elif test == "6":
                    break
                else:
                    print("Please choose 1, 2, 3 or 4 - Try again or check the help.")


def detachT0BGPprefixlists(**kwargs):
    """Detaches all prefix lists from specified T0 BGP neighbor - applicable for a route-based VPN"""
    proxy = kwargs['proxy']
    session_token =  kwargs['sessiontoken']
    if kwargs['neighbor_id'] is not None:
        neighbor_id = kwargs['neighbor_id']
    else:
        print("Please specify the BGP neighbor ID to configure using --neighbor-id.  Use 'pyVMC.py bgp show --neighbors for a list.'")
        sys.exit(1)

    # get the neighbor configuration
    neighbor_json = get_sddc_t0_bgp_single_neighbor_json(proxy, session_token, neighbor_id)
    for key in list(neighbor_json.keys()):
        if key.startswith('_'):
            del neighbor_json[key]

    # clear the route filters from the neighbor route_filtering section
    neighbor_json['route_filtering'] = [{'enabled': True, 'address_family': 'IPV4'}]

    # run the attach function with no route filters
    status_code = attach_bgp_prefix_list_json(proxy, session_token, neighbor_id, neighbor_json)
    if status_code == 200:
        print(f'Status {status_code}. Prefix lists detached from {neighbor_id}')
    else:
        print(f'Status {status_code}. Prefix lists were NOT detached from {neighbor_id}')
        sys.exit(1)

# def newBGPprefixlist(csp_url, session_token):
def newBGPprefixlist(**kwargs):
    """Creates new prefix list for a route based VPN"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
#   capture details for new prefix list
    description= input('Enter a description name for the prefix list:  ').lower()
    display_name= input('Enter a display name for the prefix list:  ').lower()
    prefix_list_id= input('Enter an ID string for the prefix list:  ').lower()
#   create python dictionary to contain the prefix list
    prefix_list = {}
    prefix_list['description'] = description
    prefix_list["display_name"] = display_name
    prefix_list["id"] = prefix_list_id
    prefix_list["prefixes"] = []
#   append individual prefixes to the list
#   begin input loop
    test = ''
    while test != "1":
        print("\nPlease select an option:")
        print("\t1- Commit changes")
        print("\t2- Add a new prefix")
        print("\t3- Review")
        print("\t4- Abort")
        print("\n")
        test=input('What would you like to do? ')
        if test== "2":
#           capture details of new prefix from user
            cidr = input('Enter "ANY" or a network or IP address in CIDR format:  ')
            action= input('Enter the action (PERMIT or DENY):  ').upper()
            if action == "PERMIT" or action == "DENY":
                scope= input('Optional - Enter either le or ge:  ').lower()
                if scope != "":
                    length= int(input('Required - Enter the length of the mask to apply:  '))
            else:
                print('Action must be either "PERMIT" or "DENY"')
                break
#           build new prefix as unique dictionary
            new_prefix = {}
            new_prefix["action"] = action
            new_prefix["network"] = cidr
            if scope !="" and length != "":
                new_prefix[scope] = length
#           append new prefix to list of prefixes in prefix_list
            prefix_list["prefixes"].append(new_prefix)
        elif test == "3":
            print("Please review the prefix list carefully... be sure you are not going to block all traffic!")
            print(prefix_list)
        elif test == "1":
            new_bgp_prefix_list_json(proxy, session_token, prefix_list_id, prefix_list)
            print("prefix list added")
        elif test == "4":
            break
        else:
            print("Please choose 1, 2, 3 or 4 - Try again or check the help.")

def delRBVPNprefixlist(**kwargs):
    """Deletes a route-based VPN prefix list from the SDDC."""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    if kwargs['prefix_list_id'] is not None:
        prefix_list_id = kwargs['prefix_list_id']
    else:
        print("Please specify the prefix list ID to configure using --prefix-list-id.  Use 'pyVMC.py rbvpn-prefix-list show --prefix-lists for a list.'")
        sys.exit(1)
    response = remove_bgp_prefix_list_json(proxy, session_token, prefix_list_id)
    if response == 200:
        print(f'The BGP prefix list {prefix_list_id} has been deleted.')
    else:
        print("The prefix list was not deleted.")
        sys.exit(1)


def getSDDCBGPAS(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    json_response = get_sddc_bgp_as_json(proxy,sessiontoken)
    if json_response != False:
        sddc_bgp_as = json_response['local_as_num']
        print(f'The SDDC BGP Autonomous System is ASN {sddc_bgp_as}')
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)


def setSDDCBGPAS(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['asn'] is not None:
        asn = kwargs['asn']
    else:
        print("Please provide deisred ASN value with -asn [VALUE].")
    json_data = {
    "local_as_num": asn
    }
    response = set_sddc_bgp_as_json(proxy,sessiontoken,json_data)
    if response!= False:
        print("The BGP AS has been updated:")
        bgp_params = {"proxy":proxy,"sessiontoken":sessiontoken}
        getSDDCBGPAS(**bgp_params)
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)


 
def getSDDCMTU(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    json_response = get_sddc_mtu_json(proxy,sessiontoken)
    if json_response != False:
        sddc_MTU = json_response['intranet_mtu']
        print(f'The MTU over the Direct Connect is {sddc_MTU} Bytes.')
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)


def setSDDCMTU(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['mtu'] is not None:
        mtu = kwargs['mtu']
    else:
        print("Please provide deisred MTU value with -mtu [VALUE].")
    json_data = {
    "intranet_mtu" : mtu
    }
    response = set_sddc_mtu_json(proxy,sessiontoken,json_data)
    if response!= False:
        print("The MTU has been updated:")
        params = {'proxy':proxy, 'sessiontoken':sessiontoken}
        getSDDCMTU(**params)
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)


def getSDDCEdgeCluster(proxy_url, sessiontoken):
    """ Gets the Edge Cluster ID """
    json_response = get_sddc_edge_cluster_json(proxy_url, sessiontoken)
    if json_response != False:
        edge_cluster_id = json_response['results'][0]['id']
        return edge_cluster_id
    else:
        return False

def getSDDCEdgeNodes(proxy_url, sessiontoken, edge_cluster_id,edge_id):
    """ Gets the Edge Nodes Path """
    json_response= get_sddc_edge_nodes_json(proxy_url, sessiontoken, edge_cluster_id)
    if json_response != False:
        edge_path = json_response['results'][edge_id]['path']
        return edge_path
    else:
        return False


def getSDDCInternetStats(proxy_url, sessiontoken, edge_path):
    """Displays counters for egress interface"""
    json_response = get_sddc_internet_stats_json(proxy_url, sessiontoken, edge_path)
    if json_response != False:
        total_bytes = json_response['per_node_statistics'][0]['tx']['total_bytes']
        return total_bytes
    else:
        return False


def getSDDCBGPVPN(**kwargs):
    """Retreives preferred path - VPN or DX."""
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    json_response = get_sddc_bgp_vpn_json(proxy, sessiontoken)

    if json_response is not None:
        sddc_bgp_vpn = json_response['route_preference']
        if sddc_bgp_vpn == "VPN_PREFERRED_OVER_DIRECT_CONNECT":
            print("The preferred path is over VPN, with Direct Connect as a back-up.")
        else:
            print("The preferred path is over Direct Connect, with VPN as a back-up.")
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)

def getSDDCEgressInterfaceCtrs(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    edge_cluster_id = getSDDCEdgeCluster(proxy, sessiontoken)

    if edge_cluster_id == False:
        print("Something went wrong, please try again.")
        sys.exit(1)
    else:
        pass
    edge_path_0 = getSDDCEdgeNodes(proxy, sessiontoken, edge_cluster_id, 0)
    if edge_path_0 == False:
        print("Something went wrong, please try again.")
        sys.exit(1)
    else:
        pass
    edge_path_1 = getSDDCEdgeNodes(proxy, sessiontoken, edge_cluster_id, 1)
    if edge_path_1 == False:
        print("Something went wrong, please try again.")
        sys.exit(1)
    else:
        pass
    stat_0 = getSDDCInternetStats(proxy,sessiontoken, edge_path_0)
    if stat_0 is None:
        print("Something went wrong, please try again.")
        sys.exit(1)
    else:
        pass

    stat_1 = getSDDCInternetStats(proxy,sessiontoken, edge_path_1)
    if stat_1 is None:
        print("Something went wrong, please try again.")
        sys.exit(1)
    else:
        pass
    total_stat = stat_0 + stat_1
    print("Current Total Bytes count on Internet interface is " + str(total_stat) + " Bytes.")    


def getSDDCT0BGPneighbors(**kwargs):
    """Prints BGP neighbors for T0 edge gateway"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    bgp_neighbors = get_sddc_t0_bgp_neighbors_json(proxy, session_token)
    if bgp_neighbors != False:
        neighbors = bgp_neighbors['results']
        bgp_table = PrettyTable(['ID','Remote AS Num','Remote Address','In_route_filter','Out_route_filter'])
        for neighbor in neighbors:
            if neighbor.get("in_route_filters"):
                in_filter = neighbor['in_route_filters']
            else:
                in_filter = "-"
            if neighbor.get("out_route_filters"):
                out_filter = neighbor['out_route_filters']
            else:
                out_filter = "-"
            bgp_table.add_row([neighbor['id'],neighbor['remote_as_num'],neighbor['neighbor_address'],in_filter, out_filter])
        print('NEIGHBORS:')
        print(bgp_table)
        if len(sys.argv) == 3:
            if sys.argv[2] == "showjson":
                print('RAW JSON:')
                print(json.dumps(neighbors,indent=2))
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)


def getSDDCT0BGPRoutes(proxy, session_token):
    """Prints BGP routes for T0 edge gateway"""
    bgp_neighbors = get_sddc_t0_bgp_neighbors_json(proxy, session_token)
    if bgp_neighbors == None:
        print("API Error")
        sys.exit(1)

    learnedRoutesTable = PrettyTable(['BGP Neighbor', 'Source Address', 'AS Path', 'Network', 'Next Hop'])
    advertisedRoutesTable = PrettyTable(['BGP Neighbor', 'Source Address', 'Network', 'Next Hop'])
    if 'results' in bgp_neighbors:
        neighbors = bgp_neighbors['results']
    else:
        print("No results.  Something went wrong - please check your syntax and try again.")
        sys.exit(1)
    for i in range(len(neighbors)):
        bgp_neighbor_id = neighbors[i]['id']
        route_learned_json = get_sddc_t0_learned_routes_json(proxy, session_token, bgp_neighbor_id)
        if route_learned_json == None:
            print("API Error")
            sys.exit(1)

        route_advertised_json = get_sddc_t0_advertised_routes_json(proxy, session_token, bgp_neighbor_id)
        if route_advertised_json == None:
            print("API Error")
            sys.exit(1)

#       Building the learned routes table
        edgeLearnedRoutes = route_learned_json['results'][0]['egde_node_routes']
        sourceAddrLearned = edgeLearnedRoutes[0]['source_address']
        bgpLearnedRoutes = edgeLearnedRoutes[1]['routes']
        for x in range(len(bgpLearnedRoutes)):
            learnedRoutesTable.add_row([bgp_neighbor_id,sourceAddrLearned,bgpLearnedRoutes[x]['as_path'],bgpLearnedRoutes[x]['network'],bgpLearnedRoutes[x]['next_hop']])
#       Building the advertised routes table
        edgeAdvertisedRoutes = route_advertised_json['results'][0]['egde_node_routes']
        sourceAddrAdvertised = edgeAdvertisedRoutes[0]['source_address']
        bgpAdvertisedRoutes = edgeAdvertisedRoutes[1]['routes']
        for y in range(len(bgpAdvertisedRoutes)):
            advertisedRoutesTable.add_row([bgp_neighbor_id,sourceAddrAdvertised,bgpAdvertisedRoutes[y]['network'],bgpAdvertisedRoutes[y]['next_hop']])
    print ('BGP Advertised Routes')
    print (advertisedRoutesTable.get_string(sortby="BGP Neighbor"))
    print ('BGP Learned Routes')
    print (learnedRoutesTable.get_string(sortby="BGP Neighbor"))


def getSDDCT0PrefixLists(**kwargs):
    """Prints prefix lists for T0 edge gateway - applicable for route-based VPN"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    prefix_lists = get_sddc_t0_prefixlists_json(proxy, session_token)
    prefix_results = prefix_lists['results']
#   clear results for any prefix lists found that contain "System created prefix list"
    str_check = 'System created prefix list'
    for item in range(len(prefix_results)):
        if "description" in prefix_results[item]:
            if str_check in prefix_results[item]['description']:
                prefix_results[item].clear()
#   remove empty dictionaries
    prefix_results = list(filter(None, prefix_results))
#   print a nicely formatted list of only user-uploaded prefix lists; system created lists were eliminated in above code
    if len(prefix_results) != 0:
        for prefixlist in prefix_results:
            if "description" in prefixlist:
                prefixlisttable = PrettyTable(['ID','Display Name','Description'])
                prefixlisttable.add_row([prefixlist["id"],prefixlist["display_name"],prefixlist["description"]])
            else:
                prefixlisttable = PrettyTable(['ID','Display Name'])
                prefixlisttable.add_row([prefixlist["id"],prefixlist["display_name"]])
            print("PREFIX:")
            print(prefixlisttable)
            prefixtable = PrettyTable(['Sequence','Network','Comparison', 'Action'])
            i = 0
            if prefixlist.get('prefixes'):
                for prefix in prefixlist['prefixes']:
                    i+=1
                    if prefix.get('ge'):
                        comparison = "ge (greater-than-or-equal)"
                    elif prefix.get('le'):
                        comparison = "le (less-than-or-equal)"
                    else:
                        comparison = '-'
                    prefixtable.add_row([i,prefix['network'],comparison,prefix['action']])
                print(f'PREFIX ENTRIES FOR {prefixlist["id"]}:')
                print(prefixtable)
                print("")
    else:
        print("No user created prefixes found.")

def exportRBVPNprefixlist(**kwargs):
    """Exports a route-based VPN prefix list to a local JSON file."""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    if kwargs['prefix_list_id'] is not None:
        prefix_list_id = kwargs['prefix_list_id']
    else:
        print("Please specify the prefix list ID to export using --prefix-list-id.  Use 'pyVMC.py rbvpn-prefix-list show --prefix-lists for a list.'")
        sys.exit(1)
    prefix_lists = get_sddc_t0_prefixlists_json(proxy, session_token)
    prefix_results = prefix_lists['results']
    for prefixlist in prefix_results:
        if prefixlist['id'] == prefix_list_id:
            exportlist = prefixlist
        else:
            continue
    if exportlist is None:
        print("No prefix lists matching that ID found.")
        sys.exit(0)
    # Delete unnecessary keys in the prefix list
    for key in list(exportlist.keys()):
        if key.startswith('_'):
            del exportlist[key]
    delete_list = ["path","relative_path","parent_path","unique_id","marked_for_delete","overridden", "realization_id"]
    for key in delete_list:
        del exportlist[key]
    # Create the export directory if it doesn't already exist
    dir_name = "json"
    create_directory(dir_name)
    # export the prefix list to a JSON file
    filename = f'{prefix_list_id}.json'
    export_file = f'{dir_name}/{filename}'
    with open(export_file, 'w') as outfile:
        json.dump(exportlist, outfile, indent=4)
    print(f'Prefix list exported as {export_file}')

def importRBVPNprefixlist(**kwargs):
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    if kwargs['filename'] is not None:
        filename = kwargs['filename']
    else:
        print("Please specify the file name to import using --filename.  Files to be imported are expeted to reside in /json.")
        sys.exit(0)
    if kwargs['prefix_list_id'] is not None:
        prefix_list_id = kwargs['prefix_list_id']
        # Check to ensure prefix list of same ID does not already exist... if so, exit.
        prefix_lists = get_sddc_t0_prefixlists_json(proxy, session_token)
        prefix_results = prefix_lists['results']
        for prefixlist in prefix_results:
            if prefixlist['id'] == prefix_list_id:
                print("prefix list already exists - please specify a different name or ID.")
                sys.ext(1)
            else:
                continue
    else:
        print("Please specify the prefix list ID to create using --prefix-list-id.")
        sys.exit(0)
    try:
        with open(f'json/{filename}', "r") as filehandle:
            prefix_list = json.load(filehandle)
    except:
        print(f'Import failed - unable to open {filename}')
        return
    new_bgp_prefix_list_json(proxy, session_token, prefix_list_id, prefix_list)
    print(f'prefix list {prefix_list} added')


def getSDDCroutes(**kwargs):
    # for i, j in kwargs.items():
    #     print(i, j)
    proxy_url = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs['strProdURL']
    if kwargs['route-type'] == 't0':
        getSDDCT0routes(proxy_url, sessiontoken)
    elif kwargs['route-type'] == 'bgp':
        getSDDCT0BGPRoutes(proxy_url, sessiontoken)
    elif kwargs['route-type'] == 'static':
        getSDDCT0staticroutes(proxy_url,sessiontoken)
    elif kwargs['route-type'] == 'tgw':
        params = {}
        params.update({"ORG_ID": ORG_ID})
        params.update({"sessiontoken": sessiontoken})
        params.update({"strProdURL": strProdURL})
        if kwargs['sddc_group_id'] is not None:
            params.update({"sddc_group_id": kwargs['sddc_group_id']})
        else:
            print("SDDC Group is required for the TGW route table. Please use './pyVMC.py vtc get-group-info' for a list of SDDC Groups with IDs.")
            sys.exit(1)
        getTGWroutes(**params)


def getSDDCT0routes(proxy_url, session_token):
    """Prints all routes for T0 edge gateway"""
    t0_routes_json = get_sddc_t0_routes_json(proxy_url, session_token)
    t0_routes = {}
    if 'results' in t0_routes_json:
        pass
    else:
        print("No results.  Something went wrong - please check your syntax and try again.")
        sys.exit(1)

    if t0_routes_json == None:
        print("API Error")
        sys.exit(1)
    elif len(t0_routes_json['results']) == 1:
        t0_routes = t0_routes_json['results'][0]['route_entries']
    elif len(t0_routes_json['results']) >1:
        t0_routes0 = t0_routes_json['results'][0]['route_entries']
        t0_routes1 = t0_routes_json['results'][1]['route_entries']
        t0_routes = t0_routes0 + t0_routes1

    df = pd.DataFrame(t0_routes)
    df.drop(['lr_component_id', 'lr_component_type'], axis=1, inplace=True)
    df.drop_duplicates(inplace = True)
    print('T0 Routes')
    print('Route Type Legend:')
    print('t0c - Tier-0 Connected\nt0s - Tier-0 Static\nb   - BGP\nt0n - Tier-0 NAT\nt1s - Tier-1 Static\nt1c - Tier-1 Connected\nisr: Inter-SR')
    print()
    print(df.sort_values(by=[ 'route_type', 'network'], ascending=True).to_string())
    # route_table = PrettyTable(['Route Type', 'Network', 'Admin Distance', 'Next Hop'])
    # for routes in t0_routes:
    #     route_table.add_row([routes['route_type'],routes['network'],routes['admin_distance'],routes['next_hop']])
    # print (route_table.get_string(sort_key = operator.itemgetter(1,0), sortby = "Network", reversesort=True))

def getSDDCT0staticroutes(proxy_url,session_token):
    """Prints static routes configured on T0 edge gateway"""
    t0_static_routes_json = get_sddc_t0_static_routes_json(proxy_url, session_token)
    if t0_static_routes_json == None:
        print("API Error")
        sys.exit(1)
    if 'results' in t0_static_routes_json:
        t0_static_routes = t0_static_routes_json['results']
    else:
        print("No results.  Something went wrong - please check your syntax and try again.")
        sys.exit(1)
    route_table = PrettyTable(['Display Name', 'Network', 'Admin Distance', 'Next Hop'])
    for routes in t0_static_routes:
        route_table.add_row([routes['display_name'],routes['network'],routes['next_hops'][0]['admin_distance'],routes['next_hops'][0]['ip_address']])
    print (route_table.get_string(sort_key = operator.itemgetter(1,0), sortby = "Network", reversesort=True))

def getTGWroutes(**kwargs):
    """===== Show TGW route tables ========="""
    sessiontoken = kwargs['sessiontoken']
    ORG_ID = kwargs['ORG_ID']
    strProdURL = kwargs['strProdURL']
    sddc_group_id = kwargs['sddc_group_id']
    res_params = {'sessiontoken':sessiontoken, 'strProdURL':strProdURL, 'org_id':ORG_ID, 'sddc_group_id':sddc_group_id}
    resource_id = get_resource_id(**res_params)
    print(f'Route table for {sddc_group_id}')
    get_route_tables(strProdURL, resource_id, ORG_ID, sessiontoken)


# ============================
# NSX-T - DNS
# ============================

def getSDDCDNS_Services(**kwargs):
    """
    Retrieves current DNS services configuration.
    """
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    if kwargs['tier1_scope'] is None:
        for i in ("mgw", "cgw"):
            sddc_dns_service = get_sddc_dns_services_json(proxy,sessiontoken,i)
            table = PrettyTable(['ID', 'Name', 'Listener IP'])
            table.add_row([sddc_dns_service['id'], sddc_dns_service['display_name'], sddc_dns_service['listener_ip']])
            print(table)
    else:
        tier1_scope = kwargs['tier1_scope'].lower()
        sddc_dns_service = get_sddc_dns_services_json(proxy,sessiontoken,tier1_scope)
        table = PrettyTable(['ID', 'Name', 'Listener IP'])
        table.add_row([sddc_dns_service['id'], sddc_dns_service['display_name'], sddc_dns_service['listener_ip']])
        # print table
        print(table)


def getSDDCDNS_Zones(**kwargs):
    """ Gets the SDDC Zones """
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_response = get_sddc_dns_zones_json(proxy,sessiontoken)
    sddc_dns = json_response['results']
    table = PrettyTable(['ID', 'Name','DNS Domain Names','upstream_servers'])
    for i in sddc_dns:
        table.add_row([i['id'], i['display_name'], i['dns_domain_names'], i['upstream_servers']])
    # return table
    print(table)


# ============================
# NSX-T - Firewall - Gateway
# ============================

def newSDDCCGWRule(**kwargs):
    proxy = kwargs["proxy"]
    sessiontoken = kwargs["sessiontoken"]
    display_name = kwargs["display_name"]

    action = kwargs["action"]
    sequence_number = kwargs["sequence"]

    # define scope (list of interfaces) to apply rule to
    scope_string = kwargs["scope"]
    scope_index = '/infra/labels/cgw-'
    scope = [scope_index + x for x in scope_string]

    # define list of services for rule
    list_index = '/infra/services/'
    services_string = kwargs["services"]
    services = []
    if len(services_string) == 1 and str.lower(services_string[0]) == "any":
        services = ["any"]
    else:
        for i in services_string:
            if str.lower(i) == "any":
                print("Service definition error: 'ANY' may not be used in conjuction with other services.  Either list them individually, or use 'ANY' alone.")
                sys.exit(1)
            service = f'{list_index}{i}'
            services.append(service)

    # group index to be used for both source and dest group definitions
    predefined_grp = ["connected_vpc", "directConnect_prefixes", "s3_prefixes", "deployment_group_dgw_prefixes", "deployment_group_tgw_prefixes", "deployment_group_vpc_prefixes", "deployment_group_sddc_prefixes"]
    group_index = '/infra/domains/cgw/groups/'

    # define source groups for rule
    sg_string = kwargs["source"]
    source_groups = []

    if len(sg_string) == 1 and str.lower(sg_string[0]) == "any":
        source_groups = ["any"]
    else:
        for i in sg_string:
            if str.lower(i) == "any":
                print("Source definition error: 'ANY' should not be used in conjuction with other sources.  Either list them individually, or use 'ANY' alone.")
                sys.exit(1)
            elif i in predefined_grp:
                source = f'/infra/tier-0s/vmc/groups/{i}'
            else:
                source = f'{group_index}{i}'
            source_groups.append(source)

    # define destination groups for rule
    dg_string = kwargs["dest"]
    destination_groups = []
    if len(dg_string) == 1 and str.lower(dg_string[0]) == "any":
        destination_groups = ["any"]
    else:
        for i in dg_string:
            if str.lower(i) == "any":
                print("Destination definition error: 'ANY' should not be used in conjuction with other sources.  Either list them individually, or use 'ANY' alone.")
                sys.exit(1)
            elif i in predefined_grp:
                dest = f'/infra/tier-0s/vmc/groups/{i}'
            else:
                dest = f'{group_index}{i}'
            destination_groups.append(dest)

    json_data = {
    "action": action,
    "destination_groups": destination_groups,
    "direction": "IN_OUT",
    "disabled": False,
    "display_name": display_name,
    "id": display_name,
    "ip_protocol": "IPV4_IPV6",
    "logged": False,
    "profiles": [ "ANY" ],
    "resource_type": "Rule",
    "scope": scope,
    "services": services,
    "source_groups": source_groups,
    "sequence_number": sequence_number
    }
    new_rule = create_gwfw_rule(proxy, sessiontoken, "cgw", display_name, json_data)
    if new_rule == 200:
        print("\n The rule has been created.")
        params = {"proxy":proxy, "sessiontoken":sessiontoken}
        getSDDCCGWRule(**params)
    else:
        print("Something went wrong. Try again.")
        exit(1)


def newSDDCMGWRule(**kwargs):
    proxy = kwargs["proxy"]
    sessiontoken = kwargs["sessiontoken"]
    display_name = kwargs["display_name"]

    action = kwargs["action"]
    sequence_number = kwargs["sequence"]

    # define list of services for rule
    list_index = '/infra/services/'
    services_string = kwargs["services"]
    services = []
    for i in services_string:
        if str.lower(i) == "any":
            print("Service definition error: 'ANY' may not be usedfor MGW gateway firewall rules.  Please list your services explicitly (i.e. HTTPS).")
            sys.exit(1)
        service = f'{list_index}{i}'
        services.append(service)

    # group index to be used for both source and dest group definitions
    group_index = '/infra/domains/mgw/groups/'

    # set up comparison list for mgt groups
    mgw_groups_json = get_sddc_inventory_groups_json(proxy, sessiontoken, "mgw")
    mgw_groups = mgw_groups_json['results']
    string_compare = []
    for item in mgw_groups:
        string_compare.append(item["id"])

    # define source groups for rule
    sg_string = kwargs["source"]
    source_groups = []
    if str.lower("any") in sg_string:
        source_groups = ["any"]
    else:
        for item in sg_string:
            if item not in string_compare:
                print(f'Invalid group:{item} - must be an existing Management Group in the Inventory.')
                params = {"proxy":proxy, "sessiontoken":sessiontoken, "gateway": "mgw"}
                print()
                get_inv_groups(**params)
                exit(1)
            else:
                item = f'{group_index}{item}'
                source_groups.append(item)
 
    # define destination groups for rule
    dg_string = kwargs["dest"]
    if len(dg_string) > 1:
        print("Invalid selection - there may be only one destination group for a MGW firewall rule.")
        exit(1)
    else:
        if dg_string[0] not in string_compare:
            print("Invalid destination group - must be an existing Management Group in the Inventory.")
            params = {"proxy":proxy, "sessiontoken":sessiontoken, "gateway": "mgw"}
            get_inv_groups(**params)
            exit(1)
        else:
            destination_groups = []
            for item in dg_string:
                item = f'{group_index}{item}'
                destination_groups.append(item)

    json_data = {
    "action": action,
    "destination_groups": destination_groups,
    "direction": "IN_OUT",
    "disabled": False,
    "display_name": display_name,
    "id": display_name,
    "ip_protocol": "IPV4_IPV6",
    "logged": False,
    "profiles": [ "ANY" ],
    "resource_type": "Rule",
    "scope": ["/infra/labels/mgw"],
    "services": services,
    "source_groups": source_groups,
    "sequence_number": sequence_number
    }
    new_rule = create_gwfw_rule(proxy, sessiontoken, "mgw", display_name, json_data)
    if new_rule == 200:
        print("\n The rule has been created.")
        params = {"proxy":proxy, "sessiontoken":sessiontoken}
        getSDDCMGWRule(**params)
    else:
        print("Incorrect syntax. Try again.")
        exit(1)


def removeSDDCCGWRule(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    gw = "cgw"
    rule_id = kwargs['rule_id']
    response = delete_gwfw_rule(proxy, sessiontoken, gw, rule_id)
    if response == 200:
        print("\n The rule has been deleted.")
        params = {"proxy":proxy, "sessiontoken":sessiontoken}
        getSDDCCGWRule(**params)
    else:
        print("Incorrect syntax. Try again.")
        exit(1)


def removeSDDCMGWRule(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    gw = "mgw"
    rule_id = kwargs['rule_id']
    response = delete_gwfw_rule(proxy, sessiontoken, gw, rule_id)
    if response == 200:
        print("\n The rule has been deleted.")
        params = {"proxy":proxy, "sessiontoken":sessiontoken}
        getSDDCMGWRule(**params)
    else:
        print("Incorrect syntax. Try again.")
        exit(1)


def getSDDCCGWRule(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    gw = "cgw"
    json_response = get_gwfw_rules(proxy, sessiontoken, gw)
    sddc_CGWrules = json_response['results']
    table = PrettyTable(['id', 'Name','Source','Destination', 'Services','Action', 'Applied To', 'Sequence Number'])
    for i in sddc_CGWrules:
        # a, b and c are used to strip the infra/domain/cgw terms from the strings for clarity.
        a = i['source_groups']
        a = [z.replace('/infra/domains/cgw/groups/','') for z in a]
        a = [z.replace('/infra/tier-0s/vmc/groups/','') for z in a]
        b= i['destination_groups']
        b = [z.replace('/infra/domains/cgw/groups/','') for z in b]
        b = [z.replace('/infra/tier-0s/vmc/groups/','') for z in b]
        c = i['services']
        c = [z.replace('/infra/services/','') for z in c]
        d= i['scope']
        d = [z.replace('/infra/labels/cgw-','') for z in d]
        table.add_row([i['id'], i['display_name'], a, b, c,i['action'], d, i['sequence_number']])
    print(table)


def getSDDCMGWRule(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    gw = "mgw"
    json_response = get_gwfw_rules(proxy, sessiontoken, gw)
    sddc_MGWrules = json_response['results']
    table = PrettyTable(['ID', 'Name', 'Source', 'Destination', 'Services', 'Action', 'Sequence Number'])
    for i in sddc_MGWrules:
        # a and b are used to strip the infra/domain/mgw terms from the strings for clarity.
        a = i['source_groups']
        a = [z.replace('/infra/domains/mgw/groups/','') for z in a]
        b= i['destination_groups']
        b = [z.replace('/infra/domains/mgw/groups/','') for z in b]
        c = i['services']
        c = [z.replace('/infra/services/','') for z in c]
        table.add_row([i['id'], i['display_name'], a, b, c, i['action'], i['sequence_number']])
    print(table)


# ============================
# NSX-T - Firewall - Distributed
# ============================


def newSDDCDFWRule(**kwargs):
    """Creating a new DFW rule"""
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    action = kwargs['action']
    section_id = kwargs['section_id']

    # Check if section exists - error if not.
    section_names = getSDDCDFWSectionlist(proxy, sessiontoken)
    if section_id not in section_names:
        print('Section does not exist.  No action taken.')
        sys.exit(1)

    # Check if rule already exists with same ID.
    rule_check = get_sddc_dfw_rule_json(proxy, sessiontoken, section_id)
    if rule_check is not None:
        dfwrules = rule_check['results']
        rule_names = []
        for i in dfwrules:
            rule_names.append(i['id'])
    if display_name in rule_names:
        print('Rule already exists.  No action taken.')
        sys.exit(1)
    

    if kwargs['sequence'] is not None:
        sequence_number = kwargs['sequence']
    else:
        sequence_number = 0

    # group index to be used for both source and dest group definitions
    predefined_grp = ["connected_vpc", "directConnect_prefixes", "s3_prefixes", "deployment_group_dgw_prefixes", "deployment_group_tgw_prefixes", "deployment_group_vpc_prefixes", "deployment_group_sddc_prefixes"]
    group_index = '/infra/domains/cgw/groups/'
    sg_string = kwargs["source"]
    dg_string = kwargs["dest"]

    # define source groups for rule
    source_groups = []
    if len(sg_string) == 1 and str.lower(sg_string[0]) == "any":
        source_groups = ["any"]
    else:
        for i in sg_string:
            if str.lower(i) == "any":
                print("Source definition error: 'ANY' should not be used in conjuction with other sources.  Either list them individually, or use 'ANY' alone.")
                sys.exit(1)
            elif i in predefined_grp:
                source = f'/infra/tier-0s/vmc/groups/{i}'
            else:
                source = f'{group_index}{i}'
            source_groups.append(source)

    # define destination groups for rule
    destination_groups = []
    if len(dg_string) == 1 and str.lower(dg_string[0]) == "any":
        destination_groups = ["any"]
    else:
        for i in dg_string:
            if str.lower(i) == "any":
                print("Destination definition error: 'ANY' should not be used in conjuction with other sources.  Either list them individually, or use 'ANY' alone.")
                sys.exit(1)
            elif i in predefined_grp:
                dest = f'/infra/tier-0s/vmc/groups/{i}'
            else:
                dest = f'{group_index}{i}'
            destination_groups.append(dest)

    if source_groups == ["any"] and destination_groups == ["any"]:
        print('''
        For DFW, it is not permitted for both SOURCE and DEST to be set to 'ANY'. 
        Either source or destination should have groups that are configured for CGW.
        Use './pyVMC.py inventory show-group cgw' to display currently configured groups for the Compute Gateway.
        ''')
        sys.exit(1)
    else:
        pass

    # Defining aervice entries
    services_string = kwargs['services']
    list_index = '/infra/services/'
    services = []
    if len(services_string) == 1 and str.lower(services_string[0]) == "any":
        services = ["ANY"]
    else:
        for i in services_string:
            if str.lower(i) == "any":
                print("Service definition error: 'ANY' may not be used in conjuction with other services.  Either list them individually, or use 'ANY' alone.")
                sys.exit(1)
            service = f'{list_index}{i}'
            services.append(service)

    json_data = {
    "action": action,
    "destination_groups": destination_groups,
    "direction": "IN_OUT",
    "disabled": False,
    "display_name": display_name,
    "id": display_name,
    "ip_protocol": "IPV4_IPV6",
    "logged": False,
    "profiles": [ "ANY" ],
    "resource_type": "Rule",
    "services": services,
    "source_groups": source_groups,
    "sequence_number": sequence_number
    }
    json_response_status_code = put_sddc_dfw_rule_json(proxy, sessiontoken, section_id, display_name, json_data)
    if json_response_status_code == 200:
        print("\n The rule has been created.")
        params = {'proxy':proxy, 'sessiontoken':sessiontoken, 'section_id':section_id}
        getSDDCDFWRule(**params)
    else:
        print("Incorrect syntax. Try again.")
        sys.exit(1)


def newSDDCDFWSection(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    display_name = kwargs['display_name']

    # Check to see if section already exists
    section_names = getSDDCDFWSectionlist(proxy, sessiontoken)
    if display_name in section_names:
        print('Section already exists.  No action taken.')
        sys.exit(1)

    if kwargs['category'] is not None:
        category = kwargs['category']
    else:
        category = "Application"
    json_data = {
    "resource_type":"SecurityPolicy",
    "display_name": display_name,
    "id": display_name,
    "category": category,
    }
    status_code = put_sddc_dfw_section_json(proxy, sessiontoken, display_name, json_data)
    if status_code == 200:
        print("Success:")
        print(f'\nThe section {display_name} has been created in the {category} category.')
        params = {'proxy':proxy, 'sessiontoken':sessiontoken}
        getSDDCDFWSection(**params)
    else:
        print("There was an error. Check the syntax.")
        sys.exit(1)

def getSDDCDFWSectionlist(proxy, sessiontoken):
    sections_response = get_sddc_dfw_section_json(proxy, sessiontoken)
    if sections_response is not None:
        sections = sections_response['results']
        section_names = []
        for i in sections:
            section_names.append(i['id'])
        return section_names
    else:
        print("Something went wrong.  No sections returned")
        sys.exit(1)

def getSDDCDFWRule(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    section_id = kwargs['section_id']
    # Check if section exists - if the section doesn't exist we get a 400 "Bad Request"
    section_names = getSDDCDFWSectionlist(proxy, sessiontoken)
    if section_id not in section_names:
        print('Section does not exist.  No action taken.')
        sys.exit(1)
    elif section_id in section_names:
        rules_response = get_sddc_dfw_rule_json(proxy, sessiontoken, section_id)
        if rules_response is not None:
            sddc_DFWrules = rules_response['results']
            table = PrettyTable(['ID', 'Name', 'Source', 'Destination', 'Services', 'Action', 'Sequence Number'])
            for i in sddc_DFWrules:
                # a and b are used to strip the infra/domain/mgw terms from the strings for clarity.
                a = i['source_groups']
                a = [z.replace('/infra/domains/cgw/groups/','') for z in a]
                a = [z.replace('/infra/tier-0s/vmc/groups/','') for z in a]
                b= i['destination_groups']
                b = [z.replace('/infra/domains/cgw/groups/','') for z in b]
                b = [z.replace('/infra/tier-0s/vmc/groups/','') for z in b]
                c = i['services']
                c = [z.replace('/infra/services/','') for z in c]
                table.add_row([i['id'], i['display_name'], a, b, c, i['action'], i['sequence_number']])
            print(table)
        else:
            print("Something went wrong.  Please try again.")
            sys.exit(1)            
    else:
        print("Something went wrong.  No sections returned")
        sys.exit(1)


def getSDDCDFWSection(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    json_response = get_sddc_dfw_section_json(proxy, sessiontoken)
    if json_response is not None:
        sddc_DFWsection = json_response['results']
        table = PrettyTable(['id', 'Name', 'Category', 'Sequence Number'])
        for i in sddc_DFWsection:
            table.add_row([i['id'], i['display_name'], i['category'], i['sequence_number']])
        print(table)
    else:
        print("Somtehing went wrong.  Please try again.")
        sys.exit(1)

def removeSDDCDFWRule(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    section_id = kwargs['section_id']
    rule_id = kwargs['rule_id']
    section_names = getSDDCDFWSectionlist(proxy, sessiontoken)
    if section_id not in section_names:
        print('Section does not exist.  No action taken.')
        sys.exit(1)

    status = delete_sddc_dfw_rule_json(proxy, sessiontoken, section_id, rule_id)
    if status == 200:
        print(f'The rule {rule_id} has been deleted.')
        params = {'proxy':proxy, 'sessiontoken':sessiontoken, 'section_id':section_id}
        getSDDCDFWRule(**params)
    else :
        print("Issues deleting the security rule. Check the syntax.")

def removeSDDCDFWSection(**kwargs):
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    section_id = kwargs['section_id']
    status = delete_sddc_dfw_section_json(proxy, sessiontoken, section_id)
    if status == 200:
        print(f'The section {section_id} has been deleted.')
        params = {'proxy':proxy, 'sessiontoken':sessiontoken, 'section_id':section_id}
        getSDDCDFWSection(**params)
    else :
        print("Issues deleting the DFW section. Check the syntax.")


# ============================
# NSX-T - Firewall Services
# ============================


def newSDDCService(**kwargs):
    """ Create a new SDDC Service based on service_entries """
    # Test for interactive flag - if False, check to ensure additional arguments were give for service entry
    if kwargs['interactive'] is False and (kwargs['l4_protocol'] is None or kwargs['dest_ports'] is None):
        print("Error - if not using interactive mode, at least protocol and destination port(s) must be configured. Source port(s) optional, based on your application.")
        sys.exit(1)
    elif kwargs['interactive'] is True and (kwargs['l4_protocol'] is not None or kwargs['dest_ports'] is not None or kwargs['source_ports'] is not None):
        print("Error - if using interactive mode, please only specify the name of the desired service.  All other parameters will be obtained interactively.")
        sys.exit(1)
    else:
        pass
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    service_id = kwargs['objectname']
    interactive = kwargs['interactive']

    if interactive == True:
        service_entry_list = []
            # Start a loop that will run until the user enters 'quit'.
            # Ask the user for a name.
        destination_port = ""
        while destination_port != 'done':
            destination_port_list = []
            source_port_list = []
            service_entry_id = input("Please enter the Service Entry ID:")
            l4_protocol = input("Please enter the L4 Protocol:")
            source_port = ""
            destination_port = ""
            while source_port != 'done':
                source_port = input("Plese enter the Source Ports or type 'done' when your list is finished:")
                if source_port != "done":
                    source_port_list.append(source_port)
            while (destination_port != 'next') and (destination_port != "done"):
                source_port = ""
                destination_port = input("Plese enter the Destination Ports, type 'next' when you want to define another service entry or 'done' if you have finished:")
                if (destination_port != 'next') and (destination_port != "done"):
                    destination_port_list.append(destination_port)
            service_entry = {
                "l4_protocol": l4_protocol,
                "source_ports": source_port_list,
                "destination_ports" : destination_port_list,
                "resource_type" : "L4PortSetServiceEntry",
                "id" : service_entry_id,
                "display_name" : service_entry_id     }
            service_entry_list.append(service_entry)
    else:
        source_port_list = kwargs['source_ports']
        destination_port_list = kwargs['dest_ports']
        l4_protocol = kwargs['l4_protocol']
        service_entry_list = [
            {
            "l4_protocol": l4_protocol,
            "source_ports": source_port_list,
            "destination_ports": destination_port_list,
            "resource_type": "L4PortSetServiceEntry",
            "display_name": f'{service_id}_svc_entry'
            }
            ]
    json_data = {
    "service_entries":service_entry_list,
    "id" : service_id,
    "display_name" : service_id,
    }
    response = new_sddc_service_json(proxy,sessiontoken,service_id,json_data)
    if response == 200:
        print(f'Service {service_id} successfully updated.')
        params = {'proxy':proxy, 'sessiontoken':sessiontoken, 'objectname':service_id}
        getSDDCService(**params)
    else:
        print("Issues creating the service - please check your syntax and try again.")
        sys.exit(1)


def removeSDDCService(**kwargs):
    """ Remove an SDDC Service """
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    service_id = kwargs['objectname']
    response = delete_sddc_service_json(proxy, sessiontoken, service_id)
    if response == 200 :
        print(f'The group {service_id} has been deleted.')
    else :
        print("There was an error. Try again.")
        sys.exit(1)

def import_service(**kwargs):
    """ Populates the services list with a set of a provider's services, can also list providers and delete the provider's services from the list"""

    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    list_providers = kwargs['list_providers']
    test_only = kwargs['test_only']
    delete_mode = kwargs['delete_mode']

    # JSON files should be placed in this path
    import_path = 'import'
    
    # Display the list of providers in the import_path
    if (list_providers):
        dirpath = Path(import_path)
        table = PrettyTable(['Providers'])
        for provider in os.listdir(dirpath):
            table.add_row([provider])
        
        print(table)
        return
    
    # If we're not displaying a provider list, then we need a provider specified to work with
    if not kwargs['provider_name']:
        print("Provider name is required")
        return

    # Ensure the provider argument points to a valid file
    fname = Path(import_path) / kwargs['provider_name']
    if not os.path.exists(fname):
        print(f'Invalid provider: {fname} not found.')
        return
    
    with open(fname, 'r') as infile:
        json_data = json.load(infile)

    # Setting these variables lets us write a single print statement whether we're in import or delete mode.
    if delete_mode:
        action_past_tense = "deleted"
        action_present_tense = "Deleting"
        action_noun = "Delete"
    else:
        action_past_tense = "imported"
        action_present_tense = "Importing"
        action_noun = "Import"

    # Test mode makes no changes to the SDDC, it prints the services found in the provider
    if (test_only):
        print(f'Test mode - no services will be {action_past_tense}.')

        table = PrettyTable(['ID','Display Name'])
        for svc in json_data:
            table.add_row([svc['id'],svc['display_name']])
        print(table)
    else:
        print(f"{action_present_tense} services in provider {kwargs['provider_name']}...")
        table = PrettyTable(['ID','Display Name',f'{action_noun} Success'])
        for svc in json_data:
            print(f"{action_present_tense} {svc['id']}... ",end = '')
            if delete_mode:
                retval = delete_sddc_service_json(proxy, sessiontoken, svc['id'])
            else:
                retval = new_sddc_service_json(proxy,sessiontoken,svc['id'],svc,patch_mode=True)
                
            if retval is not None and retval == 200:
                api_success = True
                print("Success")
            else:
                api_success = False
                print("Error")
            table.add_row([svc['id'],svc['display_name'],api_success])

        print(f"{action_noun} results: ")
        print(table)

def getSDDCService(**kwargs):
    """ Gets the SDDC Services """
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['objectname'] is not None:
        service_id = kwargs['objectname']
        response = get_sddc_single_service_json(proxy,sessiontoken, service_id)
        if response is not None:
            status = response.status_code
            if status == 200:
                json_response = response.json()
                service_entries = json_response['service_entries']
                table = PrettyTable(['ID', 'Name', 'Protocol', 'Source Ports', 'Destination Ports'])
                for i in service_entries:
                    table.add_row([i['id'], i['display_name'], i['l4_protocol'], i['source_ports'], i['destination_ports']])
                print(table)
            else:
                print("No service found by that name.")
                sys.exit(1)
    else:
        response = get_sddc_services_json(proxy,sessiontoken)
        if response is not None:
            status = response.status_code
            if status == 200:
                json_response = response.json()
                sddc_services = json_response['results']
                table = PrettyTable(['ID', 'Name','System Owned'])
                for i in sddc_services:
                    table.add_row([i['id'], i['display_name'], i['_system_owned']])
                print(table)
            else:
                print("Plese check your syntax and try again.")
                sys.exit(1)


# ============================
# NSX-T - Inventory Groups
# ============================

def new_inv_group(**kwargs):

    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    scope = kwargs['gateway']
    group_id = kwargs['objectname']
    group_type = kwargs['type']
    members = kwargs['members']

    #Build the basic JSON object
    json_data = {}
    json_data["id"] = group_id
    json_data["resource_type"] = "Group"
    json_data["display_name"] = group_id
    json_data['expression'] = []

    match scope:
        case "mgw":
            print('''
            
            Management inventory groups only allow ip-addresses as members.
            Setting type to 'ip-based.'
            '''
            )
            group_type = "ip-based"

    match group_type:
        case "ip-based":
            json_data['expression'] = [ {
                "ip_addresses" : members,
                "resource_type" : "IPAddressExpression"
            } ]
        case "member-based":
            json_data['expression'] = [ {
                "resource_type" : "ExternalIDExpression",
                'member_type' : "VirtualMachine",
                'external_ids' : members
            } ]
        case "group-based":
            group_list_with_path = []
            for item in members:
                group_list_with_path.append('/infra/domains/cgw/groups/' + item)

            #The data portion of the expression key is a dictionar
            expression_data = {}
            expression_data["paths"] = group_list_with_path
            expression_data["resource_type"] = "PathExpression"
            expression_data["parent_path"] = "/infra/domains/cgw/groups/" + group_id

            #The expression key itself is a list
            expression_list = []
            expression_list.append(expression_data)

            #Build the JSON object
            json_data["expression"] = expression_list
            json_data["extended_expression"] = []

        case "criteria-based":
            if kwargs['key'] is not None and kwargs['operator'] is not None and kwargs['filter_value'] is not None:
                key = kwargs['key']
                operator = kwargs['operator']
                filter_value = kwargs['filter_value']
            else:
                print("When specifying 'criteria-based' for group type, you must also specify --key, --operator, and --filter_value.  Please try again.")
                sys.exit(1)
            if key == "Tag" and operator == "NOTEQUALS":
                print("Incorrect syntax. The tag method does not support the NOTEQUALS Operator. Try again.")
                sys.exit(1)
            json_data['expression'] = [ {
                "resource_type" : "Condition",
                'member_type' : "VirtualMachine",
                'key' : key,
                'operator' : operator,
                'value' : filter_value
            } ]
    response = put_sddc_inventory_group_json_response(proxy, sessiontoken, json_data, scope, group_id)
    if response is not None:
        params = {"proxy":proxy, "sessiontoken":sessiontoken, "gateway":scope, "objectname":group_id}
        get_inv_groups(**params)
    else:
        print("Something went wrong. Please check your syntax and try again.")

def remove_inv_group(**kwargs):
    """ Remove an SDDC Group """
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    gw = kwargs['gateway']
    group_id = kwargs['objectname']
    json_response_status_code = delete_inventory_group_json_response(proxy, sessiontoken, gw, group_id)
    if json_response_status_code == 200:
        print("The group " + group_id + " has been deleted")
    else:
        print("Something went wrong - please check your syntax and try again.")


def getVMExternalID(proxy_url,sessiontoken,vm_name):
    response_dictionary = get_vms_json(proxy_url, sessiontoken)
    extracted_dictionary = response_dictionary['results']
#   Below, we're extracting the Python dictionary for the specific VM and then we extract the external_ID/ Instance UUID from the dictionary.
    extracted_VM = next(item for item in extracted_dictionary if item["display_name"] == vm_name)
    extracted_VM_external_id = extracted_VM['external_id']
    return extracted_VM_external_id


def get_inv_groups(**kwargs):
    """ Gets the SDDC Groups. Use 'mgw' or 'cgw' as the parameter """
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    gw = kwargs['gateway']
    if kwargs['objectname'] is None:
        if gw == "both":
            gw = ["mgw", "cgw"]
            for item in gw:
                json_response = get_sddc_inventory_groups_json(proxy, sessiontoken, item)
                gw_group = json_response['results']
                gw_table = PrettyTable(['ID', 'Name'])
                for i in gw_group:
                    gw_table.add_row([i['id'], i['display_name']])
                print(f'Here are the {str.upper(item)} Groups:')
                print(gw_table)
        else:
            json_response = get_sddc_inventory_groups_json(proxy, sessiontoken, gw)
            gw_group = json_response['results']
            gw_table = PrettyTable(['ID', 'Name'])
            for i in gw_group:
                gw_table.add_row([i['id'], i['display_name']])
            print(f'Here are the {str.upper(gw)} Groups:')
            print(gw_table)
    elif kwargs['objectname'] is not None and gw == "both":
        print("When specifying a specific group, please be sure to specify either CGW or MGW for the group domain.")
        sys.exit(1)
    else:
        group_id = kwargs['objectname']
        """ Gets a single SDDC Group. Use 'mgw' or 'cgw' as the parameter.  Displays effective membership and criteria for group"""
        json_response = get_sddc_inventory_group_id_json(proxy, sessiontoken, gw, group_id)

    #   Define tables
        table = PrettyTable(['Member Type', 'Key', 'Operator', 'Value', 'Conjunction Operator'])
        vm_table = PrettyTable(['VM Name'])
        segment_table = PrettyTable(['Segment Name', 'Path'])
        segment_port_table = PrettyTable(['Segment Port Name'])
        ip_address_table = PrettyTable(['IP Address'])
        vif_table = PrettyTable(['VIFs'])
        group_table = PrettyTable(['Group Path'])
        mac_table = PrettyTable(['MAC Addresses'])
        ad_group_table = PrettyTable(['AD Groups'])

        # Checking for groups with defined criteria with the following command.
        if json_response['expression'] == []:
            print("This group has no criteria defined.")
        elif 'expression' in json_response:
            group_criteria = json_response['expression']
            for g in group_criteria:
                if g["resource_type"] == "Condition":
                    group = json_response['expression']
                    print("The group " + group_id + " has these criteria defined:")
                    for i in group:
                        if 'member_type' in i.keys():
                            table.add_row([i['member_type'], i['key'], i['operator'], i['value'], "-"])
                        elif 'conjunction_operator' in i.keys():
                            table.add_row(["", "", "", "", i['conjunction_operator']])
                        else:
                            print("There has been an error")
                    print(table)
                    print("Based on the above criteria, the effective group membership is:")
                    for i in group:
                        if i['resource_type'] == 'ConjunctionOperator':
                            continue
                        elif i['member_type'] == 'VirtualMachine':
                            group_vm_membership_json = get_inventory_group_vm_membership_json(proxy, sessiontoken, gw, group_id)
                            group_vm_membership = group_vm_membership_json['results']
                            for x in group_vm_membership:
                                vm_table.add_row([x['display_name']])
                            print("Here is the list of VMs included in this group")
                            print(vm_table)
                        elif i['member_type'] == 'Segment':
                            group_segment_membership_json = get_inventory_group_segment_json(proxy, sessiontoken, gw, group_id)
                            group_segment_membership = group_segment_membership_json['results']
                            for y in group_segment_membership:
                                segment_table.add_row([y['display_name']])
                            print("Here is the list of Segments included in this group")
                            print(segment_table)
                        elif i['member_type'] == 'SegmentPort':
                            group_segment_port_membership_json = get_inventory_group_segment_port_json(proxy, sessiontoken, gw, group_id)
                            group_segment_port_membership = group_segment_port_membership_json['results']
                            for z in group_segment_port_membership:
                                segment_port_table.add_row([z['display_name']])
                            print("Here is the list of Segment Ports included in this group")
                            print(segment_port_table)
                        elif i['member_type'] == 'IPSet':
                            group_ip_address_membership_json = get_inventory_group_ip_address_json(proxy, sessiontoken, gw, group_id)
                            group_id_address_membership = group_ip_address_membership_json['results']
                            for a in group_id_address_membership:
                                ip_address_table.add_row([a['displan_name']])
                            print("Here is the list of IP Addresses included in this group")
                            print(ip_address_table)
                        else:
                            print("No effective group member")

                elif g["resource_type"] == "IPAddressExpression":
                    ip_addr = get_inventory_group_ip_address_json(proxy, sessiontoken, gw, group_id)
                    ips = ip_addr['results']
                    for i in ips:
                        ip_address_table.add_row([i])
                    print("The group " + group_id + " is based on the IP addresses criteria:")
                    print(ip_address_table)
                elif g["resource_type"] == "ExternalIDExpression" and g['member_type'] == 'VirtualMachine':
                    group_vm = get_inventory_group_vm_membership_json(proxy, sessiontoken, gw, group_id)
                    vms = group_vm['results']
                    for v in vms:
                        vm_table.add_row([v['display_name']])
                    print(f"The VMs in group {group_id} are:")
                    print(vm_table)
                elif g["resource_type"] == "ExternalIDExpression" and g['member_type'] == 'VirtualNetworkInterface':
                    group_vif = get_inventory_group_vif_json(proxy, sessiontoken, gw, group_id)
                    vifs = group_vif['results']
                    for v in vifs:
                        vif_table.add_row([v['display_name']])
                    print(f'The VIFs included in the group {group_id} are:')
                    print(vif_table)
                elif g['resource_type'] == "PathExpression":
                    paths = g['paths']
                    for p in paths:
                        if '/infra/domains/cgw/groups/' in p:
                            group_table.add_row([p])
                        elif '/infra/tier-1s/' in p:
                            group_segments = get_inventory_group_segment_json(proxy, sessiontoken, gw, group_id)
                            segments = group_segments['results']
                            for s in segments:
                                segment_table.add_row([s['display_name'], s['path']])
                    print(f"The group {group_id} contain these groups/segments")
                    print(group_table)
                    print(segment_table)
                elif g['resource_type'] == 'MACAddressExpression':
                    mac_addrs = g['mac_addresses']
                    for m in mac_addrs:
                        mac_table.add_row([m])
                    print(f'The group {group_id} contains these MAC Addresses')
                    print(mac_table)
                elif g['resource_type'] == 'ConjunctionOperator':
                    continue
                else:
                    print("We currently do not support displaying groups of this configuration")
        else:
            print("whoops")
        return


def get_inv_group_assoc(**kwargs):
    """ Find where a SDDC Group is being used. Use 'mgw' or 'cgw' as the parameter """
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    gw = kwargs['gateway']
    group_id = kwargs['objectname']
    json_response = get_inventory_group_association_json(proxy, sessiontoken, gw, group_id)
    if json_response is not None:
        try:
            inv_group = json_response['results']
            if len(inv_group) == 0:
                print("No object is associated with this group.")
            else:
                table = PrettyTable(['ID', 'Name'])
                for i in inv_group:
                    table.add_row([i['target_id'], i['target_display_name']])
                print(table)
        except:
            print("There were no 'results' in the returned JSON response.")
            sys.exit(1)
    else:
        print("No results returned.  Something may have gone wrong - please check your syntax and try again.")
        sys.exit(1)

# ============================
# NSX-T - NAT
# ============================


def delete_nat_rule(**kwargs):
    """Deletes specified SDDC NAT rule"""
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    nat_id = kwargs['objectname']
    tier1_id = kwargs['tier1_id']

    result = remove_sddc_nat_json(proxy, sessiontoken, nat_id, tier1_id)
    if result is not None:
        print("\n")
        params = {'proxy':proxy, 'sessiontoken':sessiontoken, 'objectname':nat_id, 'tier1_id':tier1_id}
        get_nat_rules(**params)
    else:
        print('Something went wrong.  Please check your syntax and try again.')
        sys.exit(1)

def new_nat_rule(**kwargs):
    """ Creates a new NAT rule """

    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    nat_id = kwargs['objectname']
    tier1_id = kwargs['tier1_id']
    action = kwargs['action']
    logging = kwargs['logging']
    status = kwargs['disabled']
    public_ip = kwargs['public_ip']
    private_ip = kwargs['private_ip']

    if action == 'REFLEXIVE' and kwargs['service'] is not None:
        print('Reflexive rules may not be configured with a service / port.  Please check your configuration and try again.')
    else:
        pass

    if kwargs['disabled'] == True:
        status = True
    elif kwargs['disabled'] == False:
        status = False
    if kwargs['logging'] == True:
        logging = True
    elif kwargs['logging'] == False:
        logging = False

    json_data = {}
    json_data["sequence_number"] = 0
    json_data["logging"] = logging
    json_data["enabled"] = status
    json_data["id"] = nat_id
    json_data["firewall_match"] = "MATCH_INTERNAL_ADDRESS"
    json_data["scope"] = []

    match action:
        case  "REFLEXIVE":
            json_data["action"] = f'REFLEXIVE'
            json_data["translated_network"] = public_ip
            json_data["source_network"] = private_ip

        case "DNAT":
            json_data['action'] = 'DNAT'
            json_data["destination_network"] = public_ip
            json_data["translated_network"] = private_ip
            if kwargs['translated_port'] is not None:
                json_data["translated_ports"] =  kwargs['translated_port']

    match tier1_id:
        case "cgw":
            json_data["scope"] = ["/infra/labels/cgw-public"]

    if kwargs['service'] is not None:
        service = kwargs['service']
        json_data["service"] = f'/infra/services/{service}'

    json_response_status_code = new_sddc_nat_json(proxy, sessiontoken, nat_id, tier1_id, json_data) 
    if json_response_status_code is not None:
        print(f"NAT {nat_id} created successfully")
    else:
        print("Something went wrong.   Please check your syntax and try again.")


def get_nat_rules(**kwargs):
    """Prints out all SDDC NAT rules"""
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    tier1_id = kwargs['tier1_id']
    json_response = get_sddc_nat_info_json(proxy, sessiontoken, tier1_id)
    if json_response is not None:
        sddc_NAT = json_response['results']
        table = PrettyTable(['ID', 'Name', 'Public IP', 'Ports', 'Internal IP', 'Enabled?'])
        for i in sddc_NAT:
            if 'destination_network' in i:
                table.add_row([i['id'], i['display_name'], i['destination_network'], i['translated_ports'], i['translated_network'], i['enabled']])
            else:
                table.add_row([i['id'], i['display_name'], i['translated_network'], "any", i['source_network'], i['enabled']])
        print(table)
    else:
        print("Something went wrong.  Please check your syntax and try again.")
        sys.exit(1)

def get_nat_stats(**kwargs):
    """Prints out statistics for specific NAT rule"""
    proxy = kwargs['proxy']
    sessiontoken = kwargs['sessiontoken']
    nat_id = kwargs['objectname']
    tier1_id = kwargs['tier1_id']
    json_response = get_nat_stats_json(proxy, sessiontoken, nat_id, tier1_id)
    if json_response is not None:
        sddc_NAT_stats = json_response['results'][0]['rule_statistics']
        table = PrettyTable(['NAT Rule', 'Active Sessions', 'Total Bytes', 'Total Packets'])
        for i in sddc_NAT_stats:
            #  For some reason, the API returns an entry with null values and one with actual data. So I am removing this entry.
            if (i['active_sessions'] == 0) and (i['total_bytes'] == 0) and (i['total_packets'] == 0):
                # What this code does is simply check if all entries are empty and skip (pass below) before writing the stats.
                pass
            else:
                table.add_row([nat_id, i['active_sessions'], i['total_bytes'], i['total_packets']])
        print(table)
    else:
        print("Something went wrong.  Please check your syntax and try again.")
        sys.exit(1)

# ============================
# NSX-T - Public IP Addressing
# ============================

def newSDDCPublicIP(**kwargs):
    """ Gets a new public IP for compute workloads. Requires a description to be added to the public IP."""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    ip_id = kwargs['ip_id']
    json_data = {
    "display_name" : ip_id 
    }
    json_response_status_code = put_sddc_public_ip_json(proxy, sessiontoken, ip_id, json_data)
    if json_response_status_code == 200:
        print(f'Public IP {ip_id} successfully updated.')
        params = {'proxy':proxy, 'sessiontoken':sessiontoken}
        getSDDCPublicIP(**params)
    else:
        print("Issues updating the IP - please check your syntax and try again.")
        sys.exit(1)


def deleteSDDCPublicIP(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    ip_id = kwargs['ip_id']
    json_response_status_code = delete_sddc_public_ip_json(proxy, sessiontoken, ip_id)
    if json_response_status_code == 200:
        print(f'Public IP {ip_id} successfully deleted.')
        params = {'proxy':proxy, 'sessiontoken':sessiontoken}
        getSDDCPublicIP(**params)
    else :
        print("Issues deleting the Public IP. Check the syntax.")

def setSDDCPublicIP(**kwargs):
    """ Update the description of an existing  public IP for compute workloads."""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    ip_id = kwargs['ip_id']
    notes = kwargs['notes']
    json_data = {
    "display_name" : notes
    }
    json_response_status_code = put_sddc_public_ip_json(proxy, sessiontoken, ip_id, json_data)
    if json_response_status_code == 200:
        print(f'Public IP {ip_id} successfully updated.')
        params = {'proxy':proxy, 'sessiontoken':sessiontoken}
        getSDDCPublicIP(**params)
    else:
        print("Issues updating the IP - please check your syntax and try again.")
        sys.exit(1)


def getSDDCPublicIP(**kwargs):
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_response = get_sddc_public_ip_json(proxy, sessiontoken)
    if json_response is not None:
        sddc_public_ips = json_response['results']
        table = PrettyTable(['IP', 'id', 'Notes'])
        for i in sddc_public_ips:
            table.add_row([i['ip'], i['id'], i['display_name']])
        print(table)
    else:
        print("Something went wrong.  Please check your syntax.")
        sys.exit(1)

# ============================
# NSX-T - T1 Gateways
# ============================

def t1_show(**kwargs):
    """Shows a list of T1 gateways"""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_response = get_t1_json(proxy, sessiontoken)
    if json_response != False:
        t1_gateways = json_response['results']
        table = PrettyTable(['Name', 'id', 'Type'])
        for i in t1_gateways:
            if 'type' not in i:
                i['type'] = None
            table.add_row([i["display_name"], i["id"], i["type"]])
        print(table)
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)

def t1_create(**kwargs):
    """Creates a new Tier-1 gateway"""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    t1_id = kwargs["tier1_id"]
    t1_type = kwargs['tier1_type']
    json_data = {
        "type": t1_type
    }
    status = create_t1_json(proxy, sessiontoken, t1_id, json_data)
    if status == 200:
        print(f'Tier1 gateway {t1_id} has been configured as {t1_type}')
    else:
        print("T1 was not created.  Please check your syntax and try again.")
        sys.exit(1)

def t1_configure(**kwargs):
    """ Configures a Tier1 router as 'ROUTED', 'ISOLATED', or 'NATTED'... Creates a new T1 if it does not exist already."""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    t1_id = kwargs["tier1_id"]
    json_data = {"type": kwargs["t1type"]}
    status = configure_t1_json(proxy, sessiontoken, t1_id, json_data)
    if status == 200:
        print(f'Tier1 gateway {t1_id} has been configured as {kwargs["t1type"]}')
    else:
        print("T1 was not created.  Please check your syntax and try again.")
        sys.exit(1)

def t1_remove(**kwargs):
    """ Deletes a Tier1 router as"""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    t1_id = kwargs["tier1_id"]
    if t1_id =="cgw" or t1_id =="mgw":
        print(" ")
        print("Seriously?")
        print(" ")
        print("That's a terrible idea!")
        print("Are you trying to break the environment?")
        print("Do not try to delete the default CGW of MGW.")
        print(" ")
        sys.exit(1)
    json_response = get_t1_json(proxy, sessiontoken)
    if json_response != False:
        t1_gateways = json_response['results']
        if t1_id not in [i["display_name"] for i in t1_gateways]:
            print(f'Tier1 gateway {t1_id} does not exist. Check the name and try again.')
            sys.exit(1)
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)
    status = delete_t1_json(proxy, sessiontoken, t1_id)
    if status ==200:
        print(f'Tier1 gateway {t1_id} has been deleted.')
    else: 
        print("T1 was not removed.  Please check your syntax and try again.")
        sys.exit(1)


# ============================
# NSX-T - Segments
# ============================

def new_segment(**kwargs):
    """
    Creates a new network segment - requires options to configure correctly.
    Supports new, 'flexible' networks under M18 and later as well as 'fixed' networks pre-M18
    """
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    if kwargs['objectname'] is None or kwargs['gateway'] is None:
        print("Please specify a name for the segment, and the gateway/network.")
        sys.exit(1)
    if kwargs['segment_type'] == "flexible" and kwargs['tier1_id'] is None:
        print("Please specify either the segment type as 'fixed' (-st fixed) OR segment type as 'flexible' as well as the ID of the Tier1 for connectivity (-t1id TIER1ID).  Use pyVMC -h for additional options.")
        sys.exit(1)
    if kwargs['segment_type'] == "fixed" and kwargs['tier1_id'] is not None:
        print("Invalid configuration - 'fixed' segments may only be connected to the default CGW.  To attach to a customer Tier1, please create a 'flexible' segment.")
        sys.exit(1)
    rt_set = [None, "ROUTED", "DISCONNECTED"]
    if kwargs['segment_type'] == "fixed" and kwargs['routing_type'] not in rt_set:
        print("Invalid configuration. For a 'fixed' segment, the routing type must be left blank or set explicitly to 'ROUTED' or 'DISCONNECTED.'")
        sys.exit(1)

    segment_name = kwargs["objectname"]
    gateway = kwargs['gateway']

    # Search for segment to determine if it already exists
    segment=search_nsx_json(proxy, sessiontoken, "Segment", segment_name)
    if len(segment['results']) > 0:
        print("The segment already appears to exist.")
        sys.exit(1)


    # Establish baseline json payload
    json_data = {
        "display_name":segment_name,
        "id":segment_name,
        "advanced_config":{"connectivity":"ON"},
        "subnets":[
            {
                "gateway_address": gateway
            }
        ]
        }
    #set segment type as either "fixed" or "flexible"
    segment_type = kwargs['segment_type']
    tier1_id = kwargs['tier1_id']

    if segment_type == "fixed":
        json_data["connectivity_path"] = "/infra/tier-1s/cgw"
        if kwargs['routing_type'] == "DISCONNECTED":
            json_data["advanced_config"]["connectivity"] = "OFF"
        else:
            json_data["advanced_config"]["connectivity"] = "ON"
    elif segment_type == "flexible" and tier1_id is not None:
        json_data["connectivity_path"] = f'/infra/tier-1s/{tier1_id}'
    else:
        print("Please specify either the segment type as 'fixed' (-st fixed) OR segment type as 'flexible' as well as the ID of the Tier1 for connectivity (-t1id TIER1ID).  Use pyVMC -h for additional options.")
    if kwargs['dhcp_range'] is not None:
        json_data["subnets"][0]["dhcp_ranges"] = [f'{kwargs["dhcp_range"]}']
    if kwargs['domain_name'] is not None:
        json_data["domain_name"] = kwargs["domain_name"]

    print(json.dumps(json_data, indent = 2))

    status = new_segment_json(proxy, sessiontoken, segment_name, segment_type, json_data)
    if status == 200:
        print(f'The following network has been created: {segment_name}')
        vars = {"proxy":proxy, "sessiontoken":sessiontoken, "object_type":"Segment", "object_id":segment_name}
        search_nsx(**vars)
    else:
        print("The segment was not created. Please check your syntax and try again.")
        sys.exit(1)
      
def configure_segment(**kwargs):
    """
    Reconfigures an existing network segment - requires options to configure correctly.
    If segment does not exist, prompts user to create using 'new-segment'
    Supports new, 'flexible' networks under M18 and later as well as 'fixed' networks pre-M18
    """
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    segment_name = kwargs["objectname"]
    # Quick search to see if the segment exists of not.
    segment=search_nsx_json(proxy, sessiontoken, "Segment", segment_name)
    # If the segment exists, capture the path for the API call, and the existing configuration in JSON.
    if len(segment['results']) > 0:
        json_init=segment['results'][0]
        segment_path = segment['results'][0]['path']
    else:
        print("The segment does not exist.  Please create a segment using 'new-segment'.")
        sys.exit(1)
    # Establish a list of keys to keep - these represent the values we are willing/able to update.
    keep_list = ['display_name', 'connectivity_path', 'advanced_config', 'resource_type', 'subnets']
    # Construct a new JSON using just the keys we want to keep
    json_data = dict([(key, val) for key, val in 
           json_init.items() if key in keep_list])
    # Update the json_data with the configuration specified by the user.
    if kwargs['connectivity'] is not None:
        json_data["advanced_config"]["connectivity"] = f'{kwargs["connectivity"]}'
    if kwargs['tier1_id'] is not None:
        if segment_path == "/infra/tier-1s/cgw":
            print("This is a fixed segment - you may not alter the connectivity path.  Please create a 'flexible' segment.")
        else:
            json_data["connectivity_path"] = f'/infra/tier-1s/{kwargs["tier1_id"]}'
#
    # make the call to the API
    status = configure_segment_json(proxy, sessiontoken, segment_path, json_data)
    # present results.
    if status == 200:
        print(f'The following network has been modified: {segment_name}')
        vars = {"proxy":proxy, "sessiontoken":sessiontoken, "object_type":"Segment", "object_id":segment_name}
        search_nsx(**vars)
    else:
        print("The segment was not modified.  Please check your syntax and try again.")
        sys.exit(1)

def remove_segment(**kwargs):
    """
    Removes a network segment - requires options to configure correctly.
    Supports new, 'flexible' networks under M18 and later as well as 'fixed' networks pre-M18
    """
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    segment_name = kwargs["objectname"]
    segment=search_nsx_json(proxy, sessiontoken, "Segment", segment_name)
    if len(segment['results']) > 0:
        segment_path = segment['results'][0]['path']
        status = remove_segment_json(proxy, sessiontoken, segment_path)
        if status == 200:
            print(f'The following network has been removed: {segment_name}')
        else:
            print("The segment was not removed.  Please check your syntax and try again.")
            sys.exit(1)
    else:
        print("The segment does not exist.")

def newSDDCStretchednetworks(proxy_url, sessiontoken, display_name, tunnel_id, l2vpn_path):
    """ Creates a new stretched/extended Network. """
    json_data = {
                "type":"EXTENDED",
                "display_name":display_name,
                "id":display_name,
                "advanced_config":{"connectivity":"ON"},
                "l2_extension": {
                "l2vpn_paths": [
                l2vpn_path
                ],
                "tunnel_id": tunnel_id}
    }
    print(json_data)
    new_sddc_stretched_networks_json(proxy_url, sessiontoken, display_name, json_data)
    print("The following network has been created:")
    table = PrettyTable(['Name', 'Tunnel ID', 'Routing Type'])
    table.add_row([display_name, tunnel_id, "extended"])
    return table


def getSDDCnetworks(**kwargs):
    """Prints out all Compute Gateway segemtns in all the SDDCs in the Org"""
    sessiontoken = kwargs['sessiontoken']
    proxy = kwargs['proxy']
    json_response = get_cgw_segments_json(proxy, sessiontoken)
    if json_response != False:
        sddc_networks = json_response['results']
        table = PrettyTable(['Name', 'id', 'Type', 'Network', 'Default Gateway'])
        table_extended = PrettyTable(['Name', 'id','Tunnel ID'])
        for i in sddc_networks:
            if ( i['type'] == "EXTENDED"):
                table_extended.add_row([i['display_name'], i['id'], i['l2_extension']['tunnel_id']])
            elif ( i['type'] == "DISCONNECTED"):
                table.add_row([i['display_name'], i['id'], i['type'],"-", "-"])
            else:
                table.add_row([i['display_name'], i['id'], i['type'], i['subnets'][0]['network'], i['subnets'][0]['gateway_address']])
        print("Routed Networks:")
        print(table)
        print("Extended Networks:")
        print(table_extended)
    else:
        print("Something went wrong, please try again.")
        sys.exit(1)

def createLotsNetworks(proxy_url, sessiontoken,network_number):
    """ Creates lots of networks! """
    myHeader = {"Content-Type": "application/json","Accept": "application/json", 'csp-auth-token': sessiontoken}
    for x in range(0,network_number):
        display_name = "network-name"+str(x)
        myURL = (proxy_url + "/policy/api/v1/infra/tier-1s/cgw/segments/" + display_name)
    #  '/tier-1s/cgw' might only be applicable for multi tier-1s architecture. To be confirmed.
    # print(myURL)
        json_data = {
                "subnets":[{"gateway_address":"10.200."+str(x)+".1/24"}],
                "type":"ROUTED",
                "display_name":display_name,
                "advanced_config":{"connectivity":"ON"},
                "id":"network-test"+str(x)
                }
        response = requests.put(myURL, headers=myHeader, json=json_data)
        json_response_status_code = response.status_code


# ============================
# NSX-T - VPN
# ============================


def show_sddc_l2vpn(**kwargs):
    """Prints out L2VPN sessions"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']

    i = get_l2vpn_session_json(proxy, session_token)
    sddc_l2vpn_sessions = i['results']
    table = PrettyTable(['Name', 'ID', 'Enabled?'])
    for i in sddc_l2vpn_sessions:
        table.add_row([i['display_name'], i['id'], i['enabled']])
    sys.exit(table)


def show_sddc_ipsec_vpn(**kwargs):
    """Prints out SDDC VPN session information"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    json_response = get_sddc_vpn_info_json(proxy, session_token)
    sddc_vpn = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Local Address', 'Remote Address'])
    for i in sddc_vpn:
        table.add_row([i['display_name'], i['id'], i['local_endpoint_path'].strip("/infra/tier-0s/vmc/ipsec-vpn-services/default/local-endpoints/"), i['peer_address']])
    sys.exit(table)


def show_vpn_ike_profile(**kwargs):
    """Prints out VPN IKE profiles for the SDDC"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']

    json_response = get_vpn_ike_profile_json(proxy, session_token)
    sddc_vpn_ipsec_profiles = json_response['results']
    table = PrettyTable(['Name', 'ID', 'IKE Version', 'Digest', 'DH Group', 'Encryption'])
    for i in sddc_vpn_ipsec_profiles:
        table.add_row([i['display_name'], i['id'], i['ike_version'], i['digest_algorithms'], i['dh_groups'], i['encryption_algorithms']])
    sys.exit(table)


def show_sddc_ipsec_profile(**kwargs):
    """Prints out VPN IPSEC profiles for the SDDC"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']

    json_response = get_vpn_ipsec_profile_json(proxy, session_token)
    sddc_vpn_ipsec_tunnel_profiles = json_response['results']

    table = PrettyTable(['Name', 'ID', 'Digest', 'DH Group', 'Encryption'])
    for i in sddc_vpn_ipsec_tunnel_profiles:
        table.add_row([i['display_name'], i['id'], i['digest_algorithms'], i['dh_groups'], i['encryption_algorithms']])
    sys.exit(table)


def show_sddc_dpd_profile(**kwargs):
    """Prints out VPN DPD profiles for the SDDC"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']

    json_response = get_vpn_dpd_profile_json(proxy, session_token)
    dpd_profiles = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Probe Mode', 'Probe Interval', 'Retry Count'])
    for d in dpd_profiles:
        table.add_row([d['display_name'], d['id'], d['dpd_probe_mode'], d['dpd_probe_interval'], d['retry_count']])
    sys.exit(table)


def show_sddc_vpn_endpoints(**kwargs):
    """ Gets the IPSec Local Endpoints """
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']

    json_response = get_ipsec_vpn_endpoints_json(proxy, session_token)
    sddc_vpn_ipsec_endpoints = json_response['results']
    table = PrettyTable(['Name', 'ID', 'Address'])
    for i in sddc_vpn_ipsec_endpoints:
        table.add_row([i['display_name'], i['id'], i['local_address']])
    print(table)
    sys.exit(0)


def show_tier1_vpn_services(**kwargs):
    """Gets the VPN Services for all Tier-1 Gateways"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']

    #retrieve list of Tier-1 IDs
    tier1_json = get_t1_json(proxy, session_token)
    tier1 = tier1_json['results']
    tier1_lst = []
    for t in tier1:
        tier1_lst.append(t['id'])
    table = PrettyTable(['Name', 'Service Type', 'Tier-1 Gateway'])
    for l in tier1_lst:
        ipsec_json = get_tier1_ipsec_vpn_services_json(proxy, session_token, l)
        l2vpn_json = get_tier1_l2vpn_services_json(proxy, session_token, l)
        if ipsec_json['result_count'] > 0:
            ipsec_serv = ipsec_json['results']
            for i in ipsec_serv:
                table.add_row([i['display_name'], 'IPSEC', l])
        else:
            pass
        if l2vpn_json['result_count'] > 0:
            l2vpn_serv = l2vpn_json['results']
            for i in l2vpn_serv:
                table.add_row([i['display_name'], 'L2VPN', l])
        else:
            pass
    sys.exit(table)


def show_tier1_vpn_le(**kwargs):
    """Prints all the Tier-1 VPN Local Endpoints per gateway"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    tier1_json = get_t1_json(proxy, session_token)
    tier1 = tier1_json['results']
    tier1_lst = []
    for t in tier1:
        tier1_lst.append(t['id'])
    table = PrettyTable(['Name', 'Local Address', 'Tier-1 Gateway', 'IPSec Service'])
    for l  in tier1_lst:
        ipsec_json = get_tier1_ipsec_vpn_services_json(proxy, session_token, l)
        if ipsec_json['result_count'] > 0:
            ipsec_serv = ipsec_json['results']
            for i in ipsec_serv:
                ipsec_serv_name = i['display_name']
                le_json = get_tier1_vpn_le_json(proxy, session_token, l, ipsec_serv_name)
                if le_json['result_count'] > 0:
                    le = le_json['results']
                    for v in le:
                        table.add_row([v['display_name'], v['local_address'], l, ipsec_serv_name])
                else:
                    pass
        else:
            pass
    sys.exit(table)


def show_tier1_ipsec_vpn(**kwargs):
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    table = PrettyTable(['Name', 'VPN Type', 'Peer Address', 'Authentication Mode', 'Local Endpoint', 'Tier-1 Gateway', 'VPN Service'])

    tier1_json = get_t1_json(proxy, session_token)
    tier1 = tier1_json['results']
    tier1_lst = []
    for t in tier1:
        tier1_lst.append(t['id'])

    for l  in tier1_lst:
        ipsec_json = get_tier1_ipsec_vpn_services_json(proxy, session_token, l)
        if ipsec_json['result_count'] > 0:
            ipsec_serv = ipsec_json['results']
            for i in ipsec_serv:
                ipsec_serv_name = i['display_name']
                vpn_json = get_tier1_vpn_session_json(proxy, session_token, l, ipsec_serv_name)
                vpn_data = vpn_json['results']
                for v in vpn_data:
                    rt = v['resource_type']
                    le_path = v['local_endpoint_path']
                    le = get_tier1_le_details_json(proxy, session_token, le_path)
                    match rt:
                        case "RouteBasedIPSecVpnSession":
                            vt = "Route Based"
                        case "PolicyBasedIPSecVpnSession":
                            vt = "Policy Based"
                    table.add_row([v['display_name'], vt, v['peer_address'], v['authentication_mode'], le['local_address'], l, ipsec_serv_name])
    sys.exit(table)


def show_tier1_vpn_details(**kwargs):
    """Print details of a single Tier-1 VPN"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    t1g = kwargs['tier1_gateway']
    vpn_serv = kwargs['vpn_service']
    display_name = kwargs['display_name']

    vpn_json = get_tier1_vpn_details_json(proxy, session_token, t1g, vpn_serv, display_name)
    ike_path = vpn_json['ike_profile_path']
    tun_path = vpn_json['tunnel_profile_path']
    dpd_path = vpn_json['dpd_profile_path']
    le_path = vpn_json['local_endpoint_path']

    le_json = get_tier1_vpn_le_details_json(proxy, session_token, le_path)
    local_addr = le_json['local_address']

    ike_json = get_vpn_ike_profile_details_json(proxy, session_token, ike_path)
    ike_table = PrettyTable(['Profile Name', 'IKE Version', 'Digest Algoritms', 'Encryption Algorithms', 'Diffie-Helman Groups'])
    ike_table.title = 'IKE Profile Details'
    ike_table.add_row([ike_json['display_name'], ike_json['ike_version'], ike_json['digest_algorithms'], ike_json['encryption_algorithms'], ike_json['dh_groups']])

    ipsec_json = get_vpn_ipsec_profile_details_json(proxy, session_token, tun_path)
    ipsec_table = PrettyTable(['Profile Name', 'Digest Algorithm', 'Encryption Algorithm', 'Diffie-Helman Groups', 'PFS Status'])
    ipsec_table.title = 'IPSec Tunnel Profile Details'
    ipsec_table.add_row([ipsec_json['display_name'], ipsec_json['digest_algorithms'], ipsec_json['encryption_algorithms'], ipsec_json['dh_groups'], ipsec_json['enable_perfect_forward_secrecy']])

    dpd_json = get_vpn_dpd_profile_details_json(proxy, session_token, dpd_path)
    dpd_table = PrettyTable(['Profile Name', 'Probe Mode', 'Probe Interval', 'Retry Count'])
    dpd_table.title = 'Dead Peer Detection Profile Details'
    dpd_table.add_row([dpd_json['display_name'], dpd_json['dpd_probe_mode'], dpd_json['dpd_probe_interval'], dpd_json['retry_count']])

    match vpn_json['resource_type']:
        case "PolicyBasedIPSecVpnSession":
            rt = "Policy Based"
            rules_json = vpn_json['rules']
            vpn_table = PrettyTable(['Name', 'VPN Type', 'Peer Address', 'Local Endpoint', 'Src Addresses', 'Dest Addresses'])
            vpn_table.title = 'VPN Details'
            src_addr = []
            dst_addr = []
            for r in rules_json:
                sources = r['sources']
                destinations = r['destinations']
                for s in sources:
                    src_addr.append(s['subnet'])
                for d in destinations:
                    dst_addr.append(d['subnet'])
            vpn_table.add_row([display_name, 'Policy-Based', vpn_json['peer_address'], local_addr, src_addr, dst_addr])

        case "RouteBasedIPSecVpnSession":
            rt = "Route Based"
            vpn_table = PrettyTable(['Name', 'VPN Type', 'Peer Address', 'BGP Tunnel CIDR', 'Local Endpoint', 'Authentication Mode'])
            vpn_table.title = 'VPN Details'
            ip_subnets = vpn_json['tunnel_interfaces'][0]['ip_subnets']
            for i in ip_subnets:
                ip = i['ip_addresses'][0]
                prefix = i['prefix_length']
                bgp_cidr = f"{ip}/{prefix}"
            vpn_table.add_row([display_name, 'Route-Based', vpn_json['peer_address'], bgp_cidr, local_addr, vpn_json['authentication_mode']])

        case other:
            print('Incorrect VPN Resource Type')
            sys.exit(1)

    print(vpn_table)
    print(ike_table)
    print(ipsec_table)
    print(dpd_table)
    sys.exit(0)


def show_tier1_l2vpn(**kwargs):
    """Prints table of all Tier-1 L2VPN sessions"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']

    l2vpn_table = PrettyTable(['Display Name', 'IPSec Transport Tunnel', 'Tier-1 Gateway', 'L2VPN Service', 'Peer Address', 'Local Endpoint'])

    tier1_json = get_t1_json(proxy, session_token)
    tier1 = tier1_json['results']
    tier1_lst = []
    for t in tier1:
        tier1_lst.append(t['id'])

    for t in tier1_lst:
        l2vpn_json = get_tier1_l2vpn_services_json(proxy, session_token, t)
        if l2vpn_json['result_count'] > 0:
            l2vpn_serv = l2vpn_json['results']
            for i in l2vpn_serv:
                l2vpn_serv_name = i['display_name']
                l2vpn_sessions_json = get_tier1_l2vpn_json(proxy, session_token, t, l2vpn_serv_name)
                l2vpn_sessions = l2vpn_sessions_json['results']
                for l in l2vpn_sessions:
                    transport = l['transport_tunnels']
                    for x in transport:
                        ipsec_path = x
                    ipsec_vpn_json = get_tier1_l2vpn_ipsec_json(proxy, session_token, ipsec_path)
                    ipsec_name = ipsec_vpn_json['display_name']
                    peer_addr = ipsec_vpn_json['peer_address']
                    le_json = get_tier1_vpn_le_details_json(proxy, session_token, ipsec_vpn_json['local_endpoint_path'])
                    local_addr = le_json['local_address']

                    l2vpn_table.add_row([l2vpn_serv_name, ipsec_name, t, l2vpn_serv_name, peer_addr, local_addr])
    sys.exit(l2vpn_table)


def show_tier1_l2vpn_details(**kwargs):
    """Prints table of all associated information for a L2VPN session"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    t1g = kwargs['tier1_gateway']
    l2vpn_serv = kwargs['vpn_service']
    display_name = kwargs['display_name']

    l2vpn_table = PrettyTable(['Display Name', 'IPSec Transport Tunnel', 'Tier-1 Gateway', 'L2VPN Service', 'Peer Address', 'Local Endpoint'])
    l2vpn_table.title = 'L2VPN Session Details'
    ipsec_tun_table = PrettyTable(['Display Name', 'BGP Address CIDR', 'Authentication Mode'])
    ipsec_tun_table.title = 'L2VPN IPSec Transport Tunnel Details'
    ike_table = PrettyTable(['Profile Name', 'IKE Version', 'Digest Algoritms', 'Encryption Algorithms', 'Diffie-Helman Groups'])
    ike_table.title = 'IKE Profile Details'
    ipsec_table = PrettyTable(['Profile Name', 'Digest Algorithm', 'Encryption Algorithm', 'Diffie-Helman Groups', 'PFS Status'])
    ipsec_table.title = 'IPSec Tunnel Profile Details'
    dpd_table = PrettyTable(['Profile Name', 'Probe Mode', 'Probe Interval', 'Retry Count'])
    dpd_table.title = 'Dead Peer Detection Profile Details'

    l2vpn_json = get_tier1_l2vpn_details_json(proxy, session_token, t1g, l2vpn_serv, display_name)
    transport = l2vpn_json['transport_tunnels']
    for x in transport:
        ipsec_path = x
    ipsec_vpn_json = get_tier1_l2vpn_ipsec_json(proxy, session_token, ipsec_path)
    ike_path = ipsec_vpn_json['ike_profile_path']
    tun_path = ipsec_vpn_json['tunnel_profile_path']
    dpd_path = ipsec_vpn_json['dpd_profile_path']
    le_path = ipsec_vpn_json['local_endpoint_path']

    ip_subnets = ipsec_vpn_json['tunnel_interfaces'][0]['ip_subnets']
    for i in ip_subnets:
        ip = i['ip_addresses'][0]
        prefix = i['prefix_length']
        bgp_cidr = f"{ip}/{prefix}"

    le_json = get_tier1_vpn_le_details_json(proxy, session_token, le_path)
    local_addr = le_json['local_address']

    l2vpn_table.add_row([l2vpn_json['display_name'], ipsec_vpn_json['display_name'], t1g, l2vpn_serv, ipsec_vpn_json['peer_address'], local_addr])
    ipsec_tun_table.add_row([ipsec_vpn_json['display_name'], bgp_cidr, ipsec_vpn_json['authentication_mode']])

    ike_json = get_vpn_ike_profile_details_json(proxy, session_token, ike_path)
    ike_table.add_row([ike_json['display_name'], ike_json['ike_version'], ike_json['digest_algorithms'], ike_json['encryption_algorithms'], ike_json['dh_groups']])

    ipsec_json = get_vpn_ipsec_profile_details_json(proxy, session_token, tun_path)
    ipsec_table.add_row([ipsec_json['display_name'], ipsec_json['digest_algorithms'], ipsec_json['encryption_algorithms'], ipsec_json['dh_groups'], ipsec_json['enable_perfect_forward_secrecy']])

    dpd_json = get_vpn_dpd_profile_details_json(proxy, session_token, dpd_path)
    dpd_table.add_row([dpd_json['display_name'], dpd_json['dpd_probe_mode'], dpd_json['dpd_probe_interval'], dpd_json['retry_count']])

    print(l2vpn_table)
    print(ipsec_tun_table)
    print(ike_table)
    print(ipsec_table)
    print(dpd_table)
    sys.exit(0)


def new_sddc_ipsec_vpn_ike_profile(**kwargs):
    """ Creates the configured IPSec VPN Ike Profile """
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    ike_ver = kwargs['ike_version']
    dh_group = kwargs['dh_group']
    digest_algo = kwargs['digest_algo']
    encrypt_algo = kwargs['encrypt_algo']

    # Check for incompatible IKE profile options
    if 'AES_GCM_256' in encrypt_algo and ike_ver != 'IKE_V2':
        sys.exit(f'AES GCM encryption algorithms require IKE V2')
    elif 'AES_GCM_192' in encrypt_algo and ike_ver != 'IKE_V2':
        sys.exit(f'AES GCM encryption algorithms require IKE V2')
    elif 'AES_GCM_128' in encrypt_algo and ike_ver != 'IKE_V2':
        sys.exit(f'AES GCM encryption algorithms require IKE V2')
    elif 'AES_GCM_256' in encrypt_algo and digest_algo:
        sys.exit(f'AES GCM encryption algorithm cannot be configured with a digest algorithm')
    elif 'AES_GCM_192' in encrypt_algo and digest_algo:
        sys.exit(f'AES GCM encryption algorithm cannot be configured with a digest algorithm')
    elif 'AES_GCM_128' in encrypt_algo and digest_algo:
        sys.exit(f'AES GCM encryption algorithm cannot be configured with a digest algorithm')
    else:
        pass

    # Build JSON data
    json_data = {
        "resource_type": "IPSecVpnIkeProfile",
        "display_name": display_name,
        "id": display_name,
        "encryption_algorithms": encrypt_algo,
        "digest_algorithms": digest_algo,
        "dh_groups": dh_group,
        "ike_version": ike_ver
    }
    json_response_status_code = new_ipsec_vpn_ike_profile_json(proxy, session_token, display_name, json_data)
    if json_response_status_code == 200:
        sys.exit(f'IKE Profile {display_name} was created successfully')
    else:
        print('There was an error')
        sys.exit(1)


def new_sddc_ipsec_vpn_tunnel_profile(**kwargs):
    """ Creates the configured IPSec VPN Tunnel Profile """
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    dh_group = kwargs['dh_group']
    digest_algo = kwargs['digest_algo']
    encrypt_algo = kwargs['encrypt_algo']
    pfs = kwargs['pfs_disable']

    if not pfs:
        pfs = False
    else:
        pfs = True

    # Check for incompatible IPSec Tunnel profile options
    if 'NO_ENCRYPTION_AUTH_AES_GMAC_128' in encrypt_algo and digest_algo:
        sys.exit('Digest algorithm should not be configured with NO_ENCRYPTION_AUTH_AES_GMAC selected as the encryption algorithm')
    elif 'NO_ENCRYPTION_AUTH_AES_GMAC_192' in encrypt_algo and digest_algo:
        sys.exit('Digest algorithm should not be configured with NO_ENCRYPTION_AUTH_AES_GMAC selected as the encryption algorithm')
    elif 'NO_ENCRYPTION_AUTH_AES_GMAC_256' in encrypt_algo and digest_algo:
        sys.exit('Digest algorithm should not be configured with NO_ENCRYPTION_AUTH_AES_GMAC selected as the encryption algorithm')
    else:
        pass

    #Build JSON Data
    json_data = {
        "resource_type": "IPSecVpnTunnelProfile",
        "display_name": display_name,
        "id": display_name,
        "encryption_algorithms": encrypt_algo,
        "digest_algorithms": digest_algo,
        "dh_groups": dh_group,
        "enable_perfect_forward_secrecy": pfs
    }
    json_response_status_code = new_ipsec_vpn_profile_json(proxy, session_token, display_name, json_data)
    if json_response_status_code == 200:
        sys.exit(f'IPSec Tunnel Profile {display_name} was created successfully')
    else:
        print('There was an error')
        sys.exit(1)


def new_sddc_ipsec_vpn_dpd_profile(**kwargs):
    """Creates a new IPSEC VPN DPD Profile"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    probe_mode = kwargs['probe_mode']
    probe_inter = kwargs['interval']
    status = kwargs['disable']
    retry = kwargs['retry_count']

#   Set DPD status to enabled or disabled
    if not status:
        status = False
    else:
        status = True

#   Set the DPD retry count
    if retry is None:
        retry = 10
    else:
        pass

#   Check for invalid settings by the user
    if probe_mode == 'PERIODIC' and probe_inter in range(3, 360):
        pass
    elif probe_mode == 'ON-DEMAND' and probe_inter in range(1, 10):
        pass
    else:
        sys.exit(f'The selected DPD Probe Interval {probe_inter} is invalid with the selected Probe Mode {probe_mode}.')

#   Build the JSON payload
    json_data = {
        "resource_type": "IPSecVpnDpdProfile",
        "display_name": display_name,
        "id": display_name,
        "enabled": status,
        "dpd_probe_mode": probe_mode,
        "dpd_probe_interval": probe_inter,
        "retry_count": retry
    }

#   Send the put request
    json_response_status_code = new_ipsec_vpn_dpd_profile_json(proxy, session_token, json_data, display_name)
    if json_response_status_code == 200:
        sys.exit(f'DPD Profile {display_name} has been created successfully.')
    else:
        print('There was an error')
        sys.exit(1)


def new_t1_vpn_service(**kwargs):
    """Creates a new Tier-1 VPN Services"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    t1g = kwargs['tier1_gateway']
    service = kwargs['service_type']

    if service == 'ipsec':
        json_data = {
            "resource_type": "IPSecVpnService",
            "display_name": display_name,
            "id": display_name,
            "enabled": True
        }
        json_response_status_code = new_t1_ipsec_vpn_service_json(proxy, session_token, json_data, display_name, t1g)
        if json_response_status_code == 200:
            sys.exit(f'T1 IPSec VPN service {display_name} has been created successfully.')
        else:
            print('There was an error')
            sys.exit(1)
    elif service == 'l2vpn':
        json_data = {
            "resource_type": "L2VPNService",
            "display_name": display_name,
            "id": display_name
        }
        json_response_status_code = new_t1_l2vpn_service_json(proxy, session_token, json_data, display_name, t1g)
        if json_response_status_code == 200:
            sys.exit(f'T1 L2VPN service {display_name} has been created successfully.')
        else:
            print('There was an error')
            sys.exit(1)
    else:
        print(f'The supplied service is not correct.  Please either provide "ipsec" or "l2vpn" as your option')
        sys.exit(1)


def new_t1_local_endpoint(**kwargs):
    """Creates a new Local Endpoint attached to a Tier-1 gateway"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    t1g = kwargs['tier1_gateway']
    vpn_service = kwargs['vpn_service']
    local_addr = kwargs['local_address']

    if validate_ip_address(local_addr):
        pass
    else:
        sys.exit(f'The provided local address {local_addr} is not a valid IPV4 address')

    json_data = {
        "resource_type": "IPSecVpnLocalEndpoint",
        "display_name": display_name,
        "local_id": local_addr,
        "local_address": local_addr
    }

    json_response_status_code = new_t1_local_endpoint_json(proxy, session_token, json_data, display_name, t1g, vpn_service)
    if json_response_status_code == 200:
        sys.exit(f'T1 local endpoint {display_name} has been created successfully.')
    else:
        print('There was an error')
        sys.exit(1)


def new_t1_ipsec_session(**kwargs):
    """Creates a new Tier-1 Gateway VPN Session"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    t1g = kwargs['tier1_gateway']
    vpn_service = kwargs['vpn_service']
    dpd_profile = kwargs['dpd_profile']
    ike_profile = kwargs['ike_profile']
    tunnel_profile = kwargs['tunnel_profile']
    local_endpoint = kwargs['local_endpoint']
    vpn_type = kwargs['vpn_type']
    remote_addr = kwargs['remote_address']
    psk = kwargs['psk']
    bgp_tunnel_address = kwargs['bgp_ip_address']
    bgp_subnet_prefix = kwargs['bgp_subnet_prefix']
    dest_addr = kwargs['destination_addr']
    src_addr = kwargs['source_addr']
    json_data = {}

#   Validate the provided remote IP address
    if validate_ip_address(remote_addr):
        pass
    else:
        sys.exit(f'The provided local address {remote_addr} is not a valid IPV4 address')

    json_data['display_name'] = display_name

#   Build the JSON payload for both route-based and policy-based VPNs
    if vpn_type == 'route-based':
        if bgp_tunnel_address is not None and bgp_subnet_prefix is not None:
            #Build the Route-based VPN JSON payload
            json_data = {
                "resource_type": "RouteBasedIPSecVpnSession",
                "display_name": display_name,
                "id": display_name,
                "tunnel_profile_path": f'/infra/ipsec-vpn-tunnel-profiles/{tunnel_profile}',
                "ike_profile_path": f'/infra/ipsec-vpn-ike-profiles/{ike_profile}',
                "dpd_profile_path": f'/infra/ipsec-vpn-dpd-profiles/{dpd_profile}',
                "local_endpoint_path": f'/infra/tier-1s/{t1g}/ipsec-vpn-services/{vpn_service}/local-endpoints/{local_endpoint}',
                "psk": psk,
                "peer_address": remote_addr,
                "peer_id": remote_addr,
                "tunnel_interfaces": [{
                    "ip_subnets": [{
                        "ip_addresses": bgp_tunnel_address,
                        "prefix_length": bgp_subnet_prefix
                    }]
                }]
            }
        else:
            sys.exit(f'A BGP tunnel address and subnet prefix must be defined for a route-based VPN. Please include "-b" and "-s" in your command definition.')
    elif vpn_type == 'policy-based':
        if dest_addr is not None and src_addr is not None:
            #Build the Source and Destination subnet arrays
            dest_array = []
            src_array = []
            for d in dest_addr:
                dest_subnet = {
                    "subnet": d
                    }
                dest_array.append(dest_subnet)

            for s in src_addr:
                src_subnet = {
                    "subnet": s
                    }
                src_array.append(src_subnet)

#           Build the Policy-based VPN JSON payload
            json_data = {
                "resource_type": "PolicyBasedIPSecVpnSession",
                "display_name": display_name,
                "id": display_name,
                "tunnel_profile_path": f'/infra/ipsec-vpn-tunnel-profiles/{tunnel_profile}',
                "ike_profile_path": f'/infra/ipsec-vpn-ike-profiles/{ike_profile}',
                "dpd_profile_path": f'/infra/ipsec-vpn-dpd-profiles/{dpd_profile}',
                "local_endpoint_path": f'/infra/tier-1s/{t1g}/ipsec-vpn-services/{vpn_service}/local-endpoints/{local_endpoint}',
                "psk": psk,
                "peer_address": remote_addr,
                "peer_id": remote_addr,
                "rules": [
                    {
                        "resource_type": "IPSecVpnRule",
                        "display_name": display_name,
                        "id": display_name,
                        "sources": src_array,
                        "destinations": dest_array
                    }
                ]
            }
        else:
            sys.exit(f'A policy-based VPN must have at least one source network and destination network defined. Please include "-src" and "-dest" in your command definition.')
    else:
        print(f'The VPN Type selected {vpn_type} is not valid')
        sys.exit(1)
#   Send the PUT request to the API endpoint
    json_response_status_code = new_t1_ipsec_session_json(proxy, session_token, json_data, display_name, t1g, vpn_service)
    if json_response_status_code == 200:
        sys.exit(f'Tier-1 IPSec VPN Session {display_name} has been created successfully.')
    else:
        print('There was an error')
        sys.exit(1)


def new_t1_l2vpn_session(**kwargs):
    """Create a new Tier-1 L2VPN Session"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    t1g = kwargs['tier1_gateway']
    vpn_service = kwargs['vpn_service']
    l2vpn_service = kwargs['l2vpn_service']
    local_endpoint = kwargs['local_endpoint']
    remote_addr = kwargs['remote_address']
    tunnel_addr = kwargs['tunnel_bgp_address']
    tunnel_subnet = kwargs['tunnel_bgp_subnet']
    psk = kwargs['psk']

    ipsec_name = f'L2VPN-{display_name}'

    ipsec_json = {
        "resource_type": "RouteBasedIPSecVpnSession",
        "display_name": ipsec_name,
        "id": ipsec_name,
        "local_endpoint_path": f'/infra/tier-1s/{t1g}/ipsec-vpn-services/{vpn_service}/local-endpoints/{local_endpoint}',
        "tunnel_profile_path": f'/infra/ipsec-vpn-tunnel-profiles/nsx-default-l2vpn-tunnel-profile',
        "ike_profile_path": f'/infra/ipsec-vpn-ike-profiles/nsx-default-l2vpn-ike-profile',
        "dpd_profile_path": f'/infra/ipsec-vpn-dpd-profiles/nsx-default-l3vpn-dpd-profile',
        "psk": psk,
        "peer_address": remote_addr,
        "peer_id": remote_addr,
        "tunnel_interfaces": [{
            "ip_subnets": [{
                "ip_addresses": tunnel_addr,
                "prefix_length": tunnel_subnet
            }]
        }]
    }
    ipsec_json_response_code = new_t1_ipsec_session_json(proxy, session_token, ipsec_json, ipsec_name, t1g, vpn_service)
    if ipsec_json_response_code == 200:
        l2vpn_json = {
            "resource_type": "L2VPNSession",
            "display_name": display_name,
            "id": display_name,
            "transport_tunnels": [f"/infra/tier-1s/{t1g}/ipsec-vpn-services/{vpn_service}/sessions/{ipsec_name}"],
            "enabled": True
        }
        l2vpn_json_response_code = new_t1_l2vpn_session_json(proxy, session_token, l2vpn_json, display_name, t1g, l2vpn_service)
        if l2vpn_json_response_code == 200:
            sys.exit(f'Tier-1 L2VPN Session {display_name} created successfully.')
        else:
            print('There was an error in the creation of the L2VPN Session')
            sys.exit(1)
    else:
        print('There was an error in the creation of the IPSEC Session')
        sys.exit(1)


def new_sddc_ipsec_vpn(**kwargs):
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    dpd_profile = kwargs['dpd_profile']
    ike_profile = kwargs['ike_profile']
    tunnel_profile = kwargs['tunnel_profile']
    vpn_type = kwargs['vpn_type']
    remote_addr = kwargs['remote_address']
    psk = kwargs['psk']
    bgp_tunnel_address = kwargs['bgp_ip_address']
    bgp_subnet_prefix = kwargs['bgp_subnet_prefix']
    dest_addr = kwargs['destination_addr']
    src_addr = kwargs['source_addr']
    json_data = {}

    if validate_ip_address(remote_addr):
        pass
    else:
        sys.exit(f'The provided local address {remote_addr} is not a valid IPV4 address')

    json_data['display_name'] = display_name

    #   Build the JSON payload for both route-based and policy-based VPNs
    match vpn_type:
        case 'route-based':
            if bgp_tunnel_address is not None and bgp_subnet_prefix is not None:
                # Build the Route-based VPN JSON payload
                json_data = {
                    "resource_type": "RouteBasedIPSecVpnSession",
                    "display_name": display_name,
                    "id": display_name,
                    "tunnel_profile_path": f'/infra/ipsec-vpn-tunnel-profiles/{tunnel_profile}',
                    "ike_profile_path": f'/infra/ipsec-vpn-ike-profiles/{ike_profile}',
                    "dpd_profile_path": f'/infra/ipsec-vpn-dpd-profiles/{dpd_profile}',
                    "local_endpoint_path": f'/infra/tier-0s/vmc/ipsec-vpn-services/default/local-endpoints/Public-IP1',
                    "psk": psk,
                    "peer_address": remote_addr,
                    "peer_id": remote_addr,
                    "tunnel_interfaces": [{
                        "ip_subnets": [{
                            "ip_addresses": bgp_tunnel_address,
                            "prefix_length": bgp_subnet_prefix
                        }]
                    }]
                }
            else:
                sys.exit(
                    f'A BGP tunnel address and subnet prefix must be defined for a route-based VPN. Please include "-b" and "-s" in your command definition.')
        case 'policy-based':
            if dest_addr is not None and src_addr is not None:
                # Build the Source and Destination subnet arrays
                dest_array = []
                src_array = []
                for d in dest_addr:
                    dest_subnet = {
                        "subnet": d
                    }
                    dest_array.append(dest_subnet)

                for s in src_addr:
                    src_subnet = {
                        "subnet": s
                    }
                    src_array.append(src_subnet)

                #           Build the Policy-based VPN JSON payload
                json_data = {
                    "resource_type": "PolicyBasedIPSecVpnSession",
                    "display_name": display_name,
                    "id": display_name,
                    "tunnel_profile_path": f'/infra/ipsec-vpn-tunnel-profiles/{tunnel_profile}',
                    "ike_profile_path": f'/infra/ipsec-vpn-ike-profiles/{ike_profile}',
                    "dpd_profile_path": f'/infra/ipsec-vpn-dpd-profiles/{dpd_profile}',
                    "local_endpoint_path": f'/infra/tier-0s/vmc/ipsec-vpn-services/default/local-endpoints/Public-IP1',
                    "authentication_mode": "PSK",
                    "psk": psk,
                    "peer_address": remote_addr,
                    "peer_id": remote_addr,
                    "rules": [
                        {
                            "resource_type": "IPSecVpnRule",
                            "display_name": display_name,
                            "id": display_name,
                            "sources": src_array,
                            "destinations": dest_array
                        }
                    ]
                }
                print(json.dumps(json_data, indent=2))
            else:
                sys.exit(f'A policy-based VPN must have at least one source network and destination network defined. Please include "-src" and "-dest" in your command definition.')
        case other:
            print(f'The VPN Type selected {vpn_type} is not valid')
            sys.exit(1)
    json_response_status_code = new_sddc_ipsec_session_json(proxy, session_token, json_data, display_name)
    if json_response_status_code == 200:
        sys.exit(f'SDDC IPSec VPN Session {display_name} has been created successfully.')
    else:
        print('There was an error')
        sys.exit(1)


def new_sddc_l2vpn(**kwargs):
    """ Creates the configured L2 VPN """
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    remote_addr = kwargs['remote_address']
    endpoint = kwargs['endpoint']

    match endpoint:
        case "Public-IP":
            endpoint = "Public-IP1"
        case "Private-IP":
            endpoint = "Private-IP1"

    ike_profile_json = {
        "dh_groups": [
            "GROUP14"
        ],
        "digest_algorithms": [
            "SHA2_256"
        ],
        "encryption_algorithms": [
            "AES_128"
        ],
        "ike_version": "IKE_V2",
        "display_name": "__l2vpn__internal__",
        "id": "__l2vpn__internal__",
        "resource_type": "IPSecVpnIkeProfile"
    }

    ipsec_tun_json = {
        "dh_groups": [
            "GROUP14"
        ],
        "digest_algorithms": [],
        "encryption_algorithms": [
            "AES_GCM_128"
        ],
        "enable_perfect_forward_secrecy": True,
        "display_name": "__l2vpn__internal__",
        "id": "__l2vpn__internal__",
        "resource_type": "IPSecVpnTunnelProfile"
    }

    dpd_json = {
        "dpd_probe_interval": "60",
        "dpd_probe_mode": "PERIODIC",
        "display_name": "__l2vpn__internal__",
        "id": "__l2vpn__internal__",
        "resource_type": "IPSecVpnDpdProfile"
    }

    #Create IPSec VPN tunnel
    ipsec_json = {
        "resource_type": "RouteBasedIPSecVpnSession",
        "id": "__l2vpn__internal__",
        "display_name": "L2VPN",
        "tunnel_interfaces": [
            {
                "ip_subnets": [
                    {
                        "ip_addresses": [
                            "169.254.31.253"
                        ],
                        "prefix_length": 30
                    }
                ],
                "resource_type": "IPSecVpnTunnelInterface",
                "id": "default-tunnel-interface",
                "display_name": "default-tunnel-interface"
            }
        ],
        "local_endpoint_path": f"/infra/tier-0s/vmc/ipsec-vpn-services/default/local-endpoints/{endpoint}",
        "ike_profile_path": "/infra/ipsec-vpn-ike-profiles/__l2vpn__internal__",
        "tunnel_profile_path": "/infra/ipsec-vpn-tunnel-profiles/__l2vpn__internal__",
        "dpd_profile_path": "/infra/ipsec-vpn-dpd-profiles/__l2vpn__internal__",
        "tcp_mss_clamping": {
            "direction": "NONE"
        },
        "authentication_mode": "PSK",
        "psk": "None",
        "peer_address": remote_addr,
        "peer_id": remote_addr
    }
    # print(json.dumps(ipsec_json, indent=2))
    dpd_response_code = new_ipsec_vpn_dpd_profile_json(proxy, session_token, dpd_json, "__l2vpn__internal__")
    ike_response_code = new_ipsec_vpn_ike_profile_json(proxy, session_token, "__l2vpn__internal__", ike_profile_json)
    tun_response_code = new_ipsec_vpn_profile_json(proxy, session_token, "__l2vpn__internal__", ipsec_tun_json)
    if dpd_response_code == 200 and ike_response_code == 200 and tun_response_code == 200:
        json_respon_status_code = new_sddc_ipsec_session_json(proxy, session_token, ipsec_json, "__l2vpn__internal__")
        if json_respon_status_code == 200:
            l2vpn_json = {
                "transport_tunnels": [
                    "/infra/tier-0s/vmc/ipsec-vpn-services/default/sessions/__l2vpn__internal__"
                ],
                "tcp_mss_clamping": {
                    "direction": "BOTH"
                },
                "resource_type": "L2VPNSession",
                "id": "__l2vpn__internal__",
                "display_name": display_name
            }
            json_response_status_code = new_l2vpn_json(proxy, session_token, "__l2vpn__internal__", l2vpn_json)
            if json_response_status_code == 200:
                sys.exit(f"SDDC L2VPN {display_name} has been created successfully")
            else:
                print(f"There was an error creating {display_name} L2VPN")
                sys.exit(1)
        else:
            print(f"There was an error creating the IPSec tunnel for {display_name} L2VPN")
            sys.exit(1)
    else:
        print("There was an error creating one of the tunnel encryption profiles")
        sys,exit(1)


def remove_sddc_ipsec_vpn(**kwargs):
    """Removes a SDDC IPSec VPN"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    vpn_id = ""
    vpn_json = get_sddc_vpn_info_json(proxy, session_token)
    vpn_info = vpn_json['results']
    for v in vpn_info:
        # print(json.dumps(v, indent=2))
        if v['display_name']== display_name:
            vpn_id = v['id']
            if v['resource_type'] == 'RouteBasedIPSecVpnSession':
                print(f"{display_name} is a Route-based VPN. Route based VPN deletion is not currently supported by the API")
                sys.exit(0)
            elif v['resource_type'] == 'PolicyBasedIPSecVpnSession':
                json_response_status_code = delete_ipsec_vpn_json(proxy, session_token, vpn_id)
                if json_response_status_code == 200:
                    sys.exit(f"IPSec VPN {display_name} has been deleted")
                else:
                    print(f"There was an error deleting {display_name}")
                    sys.exit(1)
        else:
            print(f"The SDDC IPSec VPN {display_name} doesn exist")
            sys.exit(0)


def remove_sddc_l2vpn(**kwargs):
    """Removes a SDDC L2VPN"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']

    json_response_status_code = delete_l2vpn_json(proxy, session_token, "__l2vpn__internal__")
    vpn_response_status_code = delete_ipsec_vpn_json(proxy, session_token, "__l2vpn__internal__")
    ike_response_status_code = delete_ipsec_vpn_ike_profile_json(proxy, session_token, "__l2vpn__internal__")
    tun_response_status_code = delete_ipsec_vpn_profile_json(proxy, session_token, "__l2vpn__internal__")
    dpd_response_status_code = delete_ipsec_vpn_dpd_profile_json(proxy, session_token, "__l2vpn__internal__")
    if json_response_status_code == 200 and ike_response_status_code == 200 and tun_response_status_code == 200 and dpd_response_status_code == 200 and vpn_response_status_code == 200:
        sys.exit(f"L2VPN {display_name} has been deleted")
    else:
        print(f"There was an error deleting {display_name}")
        sys.exit(1)


def remove_tier1_ipsec_vpn(**kwargs):
    """Removes a IPSec VPN attached to a Tier-1 Gateway"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    tier1_gateway = kwargs['tier1_gateway']
    vpn_service = kwargs['vpn_service']

    json_response_status_code = delete_tier1_ipsec_vpn_json(proxy, session_token, display_name, tier1_gateway, vpn_service)
    if json_response_status_code == 200:
        sys.exit(f"Tier-1 IPSec VPN Session {display_name} was deleted successfully")
    else:
        print(f"There was an error deleting Tier1 IPSec VPN Session {display_name}")
        sys.exit(1)


def remove_tier1_l2vpn(**kwargs):
    """Remove a L2VPN attached to a Tier-1 gateway"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    tier1_gateway = kwargs['tier1_gateway']
    vpn_service = kwargs['vpn_service']

    json_response_status_code = delete_tier1_l2vpn_json(proxy, session_token, display_name, tier1_gateway, vpn_service)
    if json_response_status_code == 200:
        sys.exit(f"Tier-1 L2VPN Session {display_name} was deleted successfully")
    else:
        print(f"There was an error deleting Tier1 L2VPN Session {display_name}")
        sys.exit(1)


def remove_tier1_vpn_local_endpoint(**kwargs):
    """Removes a Tier-1 VPN Local Endpoint"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    tier1_gateway = kwargs['tier1_gateway']
    vpn_service = kwargs['vpn_service']

    json_response_status_code = delete_tier1_vpn_le_json(proxy, session_token, display_name, tier1_gateway, vpn_service)
    if json_response_status_code == 200:
        sys.exit(f"Tier-1 VPN Local Endpoint {display_name} was deleted successfully")
    else:
        print(f"There was an error deleting Tier1 VPN Local Endpoint {display_name}")
        sys.exit(1)


def remove_tier1_vpn_service(**kwargs):
    """Removes a Tier-1 VPN Service"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    tier1_gateway = kwargs['tier1_gateway']
    service_type = kwargs['vpn_type']

    match service_type:
        case "ipsec":
            vpn_service = "ipsec-vpn-services"
        case "l2vpn":
            vpn_service = "l2vpn-services"
        case other:
            print("Invalid service type selected")
            sys.exit(1)

    json_response_status_code = delete_tier1_vpn_service_json(proxy, session_token, display_name, tier1_gateway, vpn_service)
    if json_response_status_code == 200:
        sys.exit(f"Tier-1 VPN service {display_name} was deleted successfully")
    else:
        print(f"There was an error deleting Tier1 VPN service {display_name}")
        sys.exit(1)


def remove_vpn_profile(**kwargs):
    """Removes a custom-built VPN IKE Profile"""
    proxy = kwargs['proxy']
    session_token = kwargs['sessiontoken']
    display_name = kwargs['display_name']
    profile_type = kwargs['profile_type']

    match profile_type:
        case "ike":
            profile = "ipsec-vpn-ike-profiles"
        case "ipsec":
            profile = "ipsec-vpn-tunnel-profiles"
        case "dpd":
            profile = "ipsec-vpn-dpd-profiles"
        case other:
            print("Invalid profile type")
            sys.exit(1)

    json_response_status_code = delete_vpn_profile(proxy, session_token, display_name, profile)
    if json_response_status_code == 200:
        sys.exit(f"Tier-1 VPN service {display_name} was deleted successfully")
    else:
        print(f"There was an error deleting Tier1 VPN service {display_name}")
        sys.exit(1)        


# ============================
# VCDR - Cloud File System
# ============================

def getVCDRCloudFS(**kwargs):
    """Get a list of all deployed cloud file systems in your VMware Cloud DR organization."""
    strVCDRProdURL = kwargs['strVCDRProdURL']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['cloud_fs_id'] is None:
        json_response = get_vcdr_cloud_fs_json(strVCDRProdURL, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        cloud_fs = json_response["cloud_file_systems"]
        table = PrettyTable(['Cloud FS Name', 'Cloud FS ID'])
        for i in cloud_fs:
            table.add_row([i['name'], i['id']])
        print(table)
    else:
        cloud_fs_id = kwargs['cloud_fs_id']
        json_response = get_vcdr_cloud_fs_details_json(strVCDRProdURL, cloud_fs_id, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        print(" ")
        print(f"Cloud FS Name: {json_response['name']}")
        print(f"Capacity GiB: {json_response['capacity_gib']:,.2f}")
        print(f"Used GiB: {json_response['used_gib']:,.2f}")
        print(f"Recovery SDDC: {json_response['recovery_sddc_id']}")
        print(" ")


# ============================
# VCDR - Protected Sites
# ============================
def getVCDRSites(**kwargs):
    """Get a list of all protected sites associated with an individual cloud file system."""
    strVCDRProdURL = kwargs['strVCDRProdURL']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['cloud_fs_id'] is None:
        print("Please specify the ID of the cloud file system using '-cloud-fs-id'")
        sys.exit(1)
    cloud_fs_id = kwargs['cloud_fs_id']
    if kwargs['site_id'] is None:
        json_response = get_vcdr_sites_json(strVCDRProdURL, cloud_fs_id, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        sites = json_response["protected_sites"]
        table = PrettyTable(['Site Name', 'Site ID'])
        for i in sites:
            table.add_row([i['name'], i['id']])
        print(table)
    else:
        site_id = kwargs['site_id']
        json_response = get_vcdr_site_details_json(strVCDRProdURL, cloud_fs_id, site_id, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        print(" ")
        print(f"Site Name: {json_response['name']}")
        print(f"Site Type: {json_response['type']}")
        print(" ")


# ============================
# VCDR - Protected VM
# ============================
def getVCDRVM(**kwargs):
    """Get a list of all protected VMs currently being replicated to the specified cloud file system."""
    strVCDRProdURL = kwargs['strVCDRProdURL']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['cloud_fs_id'] is None:
        print("Please specify the ID of the cloud file system using '-cloud-fs-id'")
        sys.exit(1)
    cloud_fs_id = kwargs['cloud_fs_id']
    json_response = get_vcdr_vm_json(strVCDRProdURL, cloud_fs_id, sessiontoken)
    if json_response == None:
        print("API Error")
        sys.exit(1)
    else:
        vms = json_response["vms"]
        table = PrettyTable(['VM Name', 'VCDR VM ID', 'VM Size'])
        for i in vms:
            table.add_row([i['name'], i['vcdr_vm_id'], i['size']])
        print(table)


# ============================
# VCDR - Protection Groups
# ============================
def getVCDRPG(**kwargs):
    """Get a list of all protection groups associated with an individual cloud file system."""
    strVCDRProdURL = kwargs['strVCDRProdURL']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['cloud_fs_id'] is None:
        print("Please specify the ID of the cloud file system using '-cloud-fs-id'")
        sys.exit(1)
    else:
        cloud_fs_id = kwargs['cloud_fs_id']
        if kwargs['protection_group_id'] is None:
            json_response = get_vcdr_pg_json(strVCDRProdURL, cloud_fs_id, sessiontoken)
            if json_response == None:
                print("API Error")
                sys.exit(1)
            pgs = json_response["protection_groups"]
            table = PrettyTable(['Protection Group Name', 'Protection Group ID'])
            for i in pgs:
                table.add_row([i['name'], i['id']])
            print(table)
        else:
            pg_id = kwargs['protection_group_id']
            json_response = get_vcdr_pg_details_json(strVCDRProdURL, cloud_fs_id, pg_id, sessiontoken)
            if json_response == None:
                print("API Error")
                sys.exit(1)
            # print(json.dumps(json_response, indent = 2))
            print(" ")
            print(f"Protection Group Name: {json_response['name']}")
            print(f"Protection Group Health: {json_response['health']}")
            print(f"Protected Site ID: {json_response['protected_site_id']}")
            print(f"Snapshot Schedule Active?: {json_response['snapshot_schedule_active']}")
            print(f"Snapshot Frequency Type?: {json_response['snapshot_frequency_type']}")
            # print(f"Used GiB: {json_response['used_gib']:,.2f}")
            criteria = json_response["members_specs"]
            print(f"Protected vCenter: {criteria[0]['vcenter_id']}")
            if "vcenter_vm_name_patterns" in criteria[0]:
                print(f"VM Naming Patterns: {criteria[0]['vcenter_vm_name_patterns']}")
            if "vcenter_tags" in criteria[0]:
                print(f"VM Tags: {criteria[0]['vcenter_tags']}")
            if "vcenter_folder_paths" in criteria[0]:
                print(f"VM Folders: {criteria[0]['vcenter_folder_paths']}")
            print(f"Snapshot Schedule Specifications:  {json_response['schedule_specs']}")
            print(" ")

# ============================
# VCDR - Protection Group Snapshots
# ============================
def getVCDRPGSnaps(**kwargs):
    """Get a list of all snapshots in a specific protection group."""
    strVCDRProdURL = kwargs['strVCDRProdURL']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['cloud_fs_id'] is None:
        print("Please specify the ID of the cloud file system using '-cloud-fs-id'")
        sys.exit(1)
    if kwargs['protection_group_id'] is None:
        print("Please specify the ID of the protection group using '-protection-group-id'")
        sys.exit(1)
    cloud_fs_id = kwargs['cloud_fs_id']
    pg_id = kwargs['protection_group_id']
    if kwargs['protection_group_snap_id'] is None:
        json_response = get_vcdr_pg_snaps_json(strVCDRProdURL, cloud_fs_id, pg_id, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        snaps = json_response["snapshots"]
        table = PrettyTable(['Snapshot Name', 'Snaphot ID'])
        for i in snaps:
            table.add_row([i['name'], i['id']])
        print(table)
    else:
        snap_id = kwargs['protection_group_snap_id']
        json_response = get_vcdr_pg_snap_details_json(strVCDRProdURL, cloud_fs_id, pg_id, snap_id, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        create_stamp_int = int(json_response['creation_timestamp'])
        create_stamp = datetime.utcfromtimestamp(create_stamp_int/1e9)
        expire_stamp_int = int(json_response['expiration_timestamp'])
        expire_stamp = datetime.utcfromtimestamp(expire_stamp_int/1e9)
        print(" ")
        print(f"Snapshot Name: {json_response['name']}")
        # print(f"Snapshot Creation: {json_response['creation_timestamp']}")
        print(f"Snapshot Creation: {create_stamp}")
        print(f"Snapshot Expiration: {expire_stamp}")
        print(f"Snapshot Trigger: {json_response['trigger_type']}")
        print(f"Number of VM: {json_response['vm_count']}")
        print(" ")

# ============================
# VCDR - Recovery SDDC
# ============================
def getVCDRSDDCs(**kwargs):
    """List VMware Cloud (VMC) Recovery Software-Defined Datacenters (SDDCs)."""
    strVCDRProdURL = kwargs['strVCDRProdURL']
    sessiontoken = kwargs['sessiontoken']
    if kwargs['recovery_sddc_id'] is None:
        json_response = get_vcdr_sddcs_json(strVCDRProdURL, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        sddcs = json_response["data"]
        table = PrettyTable(['Recovery SDDC Name', 'Recovery SDDC ID'])
        for i in sddcs:
            table.add_row([i['name'], i['id']])
        print(table)
    else:
        """Get details of a specific Recovery SDDC."""
        sddc_id = kwargs['recovery_sddc_id']
        json_response = get_vcdr_sddc_details_json(strVCDRProdURL, sddc_id, sessiontoken)
        if json_response == None:
            print("API Error")
            sys.exit(1)
        print(" ")
        print(f"Recovery SDDC Name: {json_response['name']}")
        print(f"Recovery SDDC Region: {json_response['region']}")
        print(f"Recovery SDDC AZs: {json_response['availability_zones']}")
        print(" ")
