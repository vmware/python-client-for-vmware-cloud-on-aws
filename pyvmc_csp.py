import json
import requests

def getSddcs (strProdURL, orgID, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse

def getSDDCInfo (strProdURL, orgID, sessiontoken, sddcID):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/sddcs/{sddcID}"
    response = requests.get(myURL, headers=myHeader)
    jsonresponse = response.json()
    return jsonresponse

def getConnectedAccounts(strProdURL, orgID, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/account-link/connected-accounts"
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse

def getCompatSubnets (strProdURL, orgID, sessiontoken, linkedAWSID, region):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f"{strProdURL}/vmc/api/orgs/{orgID}/account-link/compatible-subnets"
    params = {'org': orgID, 'linkedAccountId': linkedAWSID,'region': region}
    response = requests.get(myURL, headers=myHeader, params=params)
    jsonResponse = response.json()
    return jsonResponse

def getCSPUsers (strCSPProdURL, orgID, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{strCSPProdURL}/csp/gateway/am/api/v2/orgs/{orgID}/users'
    response = requests.get(myURL, headers=myHeader)
    jsonResponse = response.json()
    return jsonResponse
