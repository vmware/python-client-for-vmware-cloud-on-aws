import json
import requests

def vpnPublicIP (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/cloud-service/api/v1/infra/sddc-user-config'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

def getCGWSegments (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/segments'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

def getSDDCNATInfo (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code

def getNATStats (proxy_url, sessiontoken, nat_id):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-1s/cgw/nat/USER/nat-rules/{nat_id}/statistics'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code

def getSDDCVpnInfo (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/ipsec-vpn-services/default/sessions'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    json_response_status_code = response.status_code
    return json_response, json_response_status_code

def getVPNIPSecProfile (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-tunnel-profiles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

def getVPNIKEProfile (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/ipsec-vpn-ike-profiles'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

def getL2VPNService (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

def getL2VPNSession (proxy_url, sessiontoken):
    myHeader = {'csp-auth-token': sessiontoken}
    myURL = f'{proxy_url}/policy/api/v1/infra/tier-0s/vmc/locale-services/default/l2vpn-services/default/sessions'
    response = requests.get(myURL, headers=myHeader)
    json_response = response.json()
    return json_response

