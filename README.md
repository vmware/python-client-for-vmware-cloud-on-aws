# python-client-for-vmware-cloud-on-aws

## Overview

# pyVMC
Welcome to the Python Client for VMware Cloud on AWS !

## What is the Python Client for VMware Cloud on AWS ? 
It is a Python tool developed for VMware Cloud on AWS. PyVMC was created by Nicolas Vibert and Matt Dreyer.

## What are the pre-requisites for PyVMC ?
- Python3 installed on your machine
- a VMware Cloud on AWS account

## How do I use PyVMC ?
- clone repo
- install dependencies
```
$ pip install -r requirements.txt
```
- copy config.ini.example to config.ini and add your own token
- Edit the config.ini with your own SDDC ID,  Organization (Org) ID and your access token.

## Do I need to know Python?
No! You can simply use it to consume and manage your VMware Cloud on AWS SDDC (Software-Defined Data Center). 

## Is it officially supported by VMware?
Sorry but no, this is a community-based effort. Use it at your own risk. It has extensively been tested though and we'll endeavour to fix any bugs.

## Which version of VMware Cloud on AWS has it been tested against?
Versions 1.9, 1.10, 1.11, 1.12, 1.14, and 1.15. We don't guarantee support with previous versions. 
I will, however, endeavour to verify compatibility as we release new versions.

## What if I find a bug or need a new feature?
Please raise it on GitHub and we will look into it.

## Where can I find documentation about VMware Cloud on AWS:
Please check the online documentation:
https://docs.vmware.com/en/VMware-Cloud-on-AWS/index.html

## Where can I find documentation about each pyVMC commands?

Initial Release:
https://nicovibert.com/2020/02/25/pyvmc-python-vmware-cloud-aws/

First main update:
https://nicovibert.com/2020/06/01/fling-update-pyvmc-1-1-release-and-a-walkthrough-through-some-python-code/

Additional Blog Posts:
http://www.patrickkremer.com/pyvmc/

## Release Notes

This tool enables users to:

Here are the currently supported commands:

- AWS Account and VPC
    - set-sddc-connected-services: change whether to use S3 over the Internet or via the ENI
    - show-compatible-subnets [LINKEDACCOUNTID] [REGION]: show compatible native AWS subnets connected to the SDDC
    - show-connected-accounts: show native AWS accounts connected to the SDDC
    - show-sddc-connected-vpc: show the VPC connected to the SDDC
    - show-shadow-account: show the Shadow AWS Account VMC is deployed in

- BGP and Networking
    - attach-t0-prefix-list [BGP NEIGHBOR ID]: attach a BGP Prefix List to a T0 BGP neighbor
    - detach-t0-prefix-lists [BGP NEIGHBOR ID]: detach all prefix lists from specified neighbor
    - new-t0-prefix-list: create a new T0 BGP Prefix List
    - remove-t0-prefix-list [PREFIX LIST ID]: you can see current prefix list with 'show-t0-prefix-lists': remove a T0 BGP Prefix List
    - set-bgp-as [ASN]: update the BGP AS number
    - set-mtu: set the MTU configured over the Direct Connect
    - show-mtu: show the MTU configured over the Direct Connect
    - show-egress-interface-counters: show current Internet interface egress counters
    - show-sddc-bgp-as: show the BGP AS number
    - show-sddc-bgp-vpn: show whether DX is preferred over VPN
    - show-t0-bgp-neighbors: show T0 BGP neighbors
    - show-t0-prefix-lists: show T0 prefix lists
    - show-t0-routes: show routes at the T0 router
    - show-t0-bgp-routes: show learned and advertised routes via BGP

- DNS
    - show-dns-services: show DNS services
    - show-dns-zones: show DNS zones

- Inventory Groups
    - new-group [CGW/MGW] [Group_ID]: create a new group
    - remove-group [CGW/MGW][Group_ID]: remove a group
    - show-group [CGW/MGW] [Group_ID]: show existing groups
    - show-group-association [CGW/MGW] [Group_ID]: show security rules used by a groups

- Firewall - Distributed
    - new-dfw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SECTION] [SEQUENCE-NUMBER]: create a new DFW security rule
    - new-dfw-section [NAME][CATEGORY]: create a new DFW section
    - remove-dfw-rule [SECTION_ID][RULE_ID]: delete a DFW rule
    - remove-dfw-section [RULE_ID]: delete a DFW section
    - show-dfw-section: show the DFW sections
    - show-dfw-section-rules [SECTION]: show the DFW security rules within a section

- Firewall - T0
    - new-cgw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SCOPE] [SEQUENCE-NUMBER]: create a new CGW security rule
    - new-mgw-rule [NAME] [SOURCE-GROUPS] [DESTINATION-GROUPS] [SERVICE] [ACTION] [SEQUENCE-NUMBER]: create a new MGW security rule
    - remove-cgw-rule [RULE_ID]: delete a CGW security rule
    - remove-mgw-rule [RULE_ID]: delete a MGW security rule
    - show-cgw-rule: show the CGW security rules
    - show-mgw-rule: show the MGW security rules

- Firewall Services
    - new-service: create a new service
    - remove-service [SERVICE-ID]: remove a service
    - show-services [SERVICE-ID]: show a specific service
    - show-services: show services

- NAT
    - new-nat-rule: To create a new NAT rule
    - remove-nat-rule: remove a NAT rule
    - show-nat: show the configured NAT rules
    - show-nat [NAT-RULE-ID] for statistics of a rule: show the statistics for a specific NAT rule

- Public IP addressing
    - new-sddc-public-ip: request a new public IP
    - remove-sddc-public-ip: remove an existing public IP
    - set-sddc-public-ip: update the description of an existing public IP
    - show-sddc-public-ip: show the public IPs

- SDDC
    - get-access-token: show your access token
    - show-sddc-state: get a view of your selected SDDC
    - show-sddcs: display a lit of your SDDCs
    - show-vms: get a list of your VMs
- TKG
    - enable-tkg: Enable Tanzu Kubernetes Grid on an SDDC
    - disable-tkg: Disable Tanzu Kubernetes Grid on an SDDC

- User and Group management
    - add-users-to-csp-group [GROUP_ID] [EMAILS]: CSP user to a group
    - show-csp-group-diff [GROUP_ID] [showall|skipmembers|skipowners]: this compares the roles in the specified group with every user in the org and prints ou
    - show-csp-service-roles: show CSP service roles for the currently logged in user
    - find-csp-user-by-service-role [service role name]: search for CSP users with a specific service role
    - show-org-users: show the list of organization users

- Virtual Machine Networking
    - show-network: show your current networks
    - new-network [NAME] DISCONNECTED [GATEWAY_ADDRESS]  for a disconnected network
    - new-network [NAME] EXTENDED [GATEWAY_ADDRESS] [TUNNEL_ID] for an extended network
    - new-network [NAME] ROUTED [GATEWAY_ADDRESS] [DHCP_RANGE] [DOMAIN_NAME] for a DHCP network
    - new-network [NAME] ROUTED [GATEWAY_ADDRESS] for a static network
    - remove-network: remove a network

- VPN
    - new-l2vpn [NAME] [LOCAL_ENDPOINT] [REMOTE_PEER]: create a new L2VPN
    - remove-l2VPN [ID]: remove a L2VPN
    - remove-vpn [VPN-ID]: remove a VPN
    - remove-vpn-ike-profile [ID]: remove a VPN IKE profile
    - remove-vpn-ipsec-tunnel-profile [ID]: To remove a VPN IPSec Tunnel profile
    - show-l2vpn: show l2 vpn
    - show-l2vpn-services: show l2 vpn services
    - show-vpn: show the configured VPN
    - show-vpn [VPN_ID]: show the VPN statistics
    - show-vpn-ike-profile: show the VPN IKE profiles
    - show-vpn-internet-ip: show the public IP used for VPN services
    - show-vpn-ipsec-tunnel-profile: show the VPN tunnel profile
    - show-vpn-ipsec-endpoints: show the VPN IPSec endpoints

- VTC (VMware Transit Connect)
    - SDDC Group Operations
        - create-sddc-group [name]: Create an SDDC group
        - delete-sddc-group: Delete an SDDC group
        - get-group-info: Display details for an SDDC group
    - SDDC Operations
        - get-sddc-info: Display a list of all SDDCs
        - get-nsx-info: Display NSX credentials and URLs
        - attach-sddc: Attach an SDDC to a vTGW
        - detach-sddc: Detach an SDDC from a vTGW
    - AWS Operations
        - connect-aws: Connect an vTGW to an AWS account
        - disconnect-aws: Disconnect a vTGW from an AWS account
    - VPC Operations
        - attach-vpc: Attach a VPC to a vTGW
        - detach-vpc Detach VPC from a vTGW
        - vpc-prefixes: Add or remove vTGW static routes
    - DXGW Operations
        - attach-dxgw: Attach a Direct Connect Gateway to a vTGW
        - detach-dxgw: Detach a Direct Connect Gateway from a vTGW
    - TGW Operations
        - show-tgw-routes: Show the vTGW route table
            - show-tgw-routes [group name]: Show the vTGW route table for the specified group

## Contributing

The python-client-for-vmware-cloud-on-aws project team welcomes contributions from the community. Before you start working with python-client-for-vmware-cloud-on-aws, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License

SPDX-License-Identifier: BSD-2-Clause
