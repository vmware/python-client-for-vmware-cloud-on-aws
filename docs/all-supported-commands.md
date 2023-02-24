# pyVMC all supported Commands
## Table of Contents
<!-- TOC -->
- [Current Supported Commands](#current-supported-commands)
- [Authentication](#authentication)
- [Getting Help](#getting-help)
- [1. CSP - Cloud Service Portal related commands](#1-csp-commands)
- [2. SDDC - Software Defined Datacenter related commands](#2-sddc-commands)
- [3. TKG - Tanzu Kubernetes Service related commands](#3-tkg-commands)
- [4. VTC -  VMware Transit Connect related commands](#4-vtc-commands)
- [5. NSX related commands](#5-nsx-related-commands)
  - [5.1 Segment - Virtual Machine network segment related commands](#51-segment-commands)
  - [5.2 VPN -  Virtual private network related commands](#52-vpn-commands)
  - [5.3 NAT - Network Address Translation related commands](#53-nat-commands)
  - [5.4 T1 - T1 gateways related commands](#54-t1-commands)
  - [5.5 GWFW - NSX Gateway Firewall related commands](#55-gwfw-commands)
  - [5.6 DFW - NSX Distributed Firewall related commands](#56-dfw-commands)
  - [5.7 NSXAF - NSX Advanced Firewall related commands](#57-nsxaf-commands)
  - [5.8 Inventory - NSX Inventory related commands](#58-inventory-commands)
  - [5.9 System - NSX-T System related commands](#59-system-commands)
  - [5.10 serach-nsx - NSX Manager inventory related commands](#510-serach-nsx-commands)
- [6. VCDR - VMware Cloud Disaster Recovery related commands](#6-vcdr-commands)
- [7. Flexcomp - VMware Cloud Flex Compute related commands](#7-flex-compute-commands)


## Current Supported Commands
Here are the currently supported 'super' commands:
```shell
    csp                                 Commands related to the Cloud Service Portal itself.
    sddc                                Commands related to the Software Defined Datacenter (SDDC) itself.
    tkg                                 Commands related to the Tanzu Kubernetes Service (TKG).
    segment                             Create, delete, update, and show Virtual Machine network segments.
    vpn                                 Create, delete, update, and show virtual private network (VPN) settings.
    nat                                 Show and update Network Address Translation (NAT) rules.
    t1                                  Create, delete, update, and show secondary T1 gateways.
    vtc                                 Commands related to VMware Transit Connect (VTC).
    gwfw                                Show and update policies and rules associated with NSX Gateway Firewall (mgw, cgw, etc.).
    dfw                                 Show and update policies and rules associated with NSX Distributed Firewall.
    nsxaf                               Commands related to the NSX Advanced Firewall - e.g. IDS.
    inventory                           Show and update objects in the NSX Inventory (groups, services, etc).
    system                              Show and update configuration data associated with the NSX-T System (DNS, public IP, etc).
    search-nsx                          Search the NSX Manager inventory.
    vcdr                                Create, delete, update, and show information about VMware Cloud Disaster Recovery.
    flexcomp                            Commands related to the Cloud Flex Compute itself.
```
## Authentication
pyVMC supports both **refresh_token** and **OAuth AppId/Secret** way to authenticate.
Values for it needs to be specified in config.ini file. Default auth method is to use **refresh_token**.

If one wants to use OAuth, then **--oauth** switch needs to be provided when running the command.

Examples:

Using default 'refresh_token'
```shell
./pyVMC.py sddc show-sddcs
```

Using OAuth
```shell
./pyVMC.py sddc show-sddcs --oauth
```
## Getting Help

To see the supported commands for any given category / super-command, simply use '-h'... for example:

```shell
./pyVMC.py vcdr -h
usage:  vcdr [-h] {scfs,pg,snaps,rsddc,psite,vms} ...

positional arguments:
  {scfs,pg,snaps,rsddc,psite,vms}
                        vcdr sub-command help
    scfs                VCDR cloud file system - use '-h' for help.
    pg                  VCDR Protection Groups - use '-h' for help.
    snaps               VCDR Snapshots - use '-h' for help.
    rsddc               VCDR Recovery SDDC - use '-h' for help.
    psite               VCDR Protected Site - use '-h' for help.
    vms                 VCDR cloud file system - use '-h' for help.

optional arguments:
  -h, --help            show this help message and exit
```

Similarly, to see the options for any given command, run the individual command with the -h option:

```shell
./pyVMC.py vcdr scfs -h               
usage: vcdr scfs [-h] {show} ...

positional arguments:
  {show}      vcdr scfs sub-command help
    show      Show information about the VCDR Scale-out file System(s).

optional arguments:
  --oauth [OAUTH]       Used to specify use of OAuth app ID and secret in config.ini instead of 'refresh_token' (default)
  -h, --help  show this help message and exit
```

## 1. CSP commands
```shell
usage:  csp [-h]
            {show-csp-services,show-csp-service-roles,get-access-token,add-users-to-csp-group,show-csp-group-diff,show-csp-group-members,show-csp-groups,search-csp-org-users,find-csp-user-by-service-role,show-org-users}
            ...

positional arguments:
  {show-csp-services,show-csp-service-roles,get-access-token,add-users-to-csp-group,show-csp-group-diff,show-csp-group-members,show-csp-groups,search-csp-org-users,find-csp-user-by-service-role,show-org-users}
                                        csp sub-command help
    show-csp-services                   Show the entitled services in the
                                        VMware Cloud Service Console.
    show-csp-service-roles              Show the entitled service roles in the
                                        VMware Cloud Service Console.
    get-access-token                    show your access token
    add-users-to-csp-group              CSP user to a group
    show-csp-group-diff                 this compares the roles in the
                                        specified group with every user in the
                                        org and prints out a user-by-user diff
    show-csp-group-members              show CSP group members
    show-csp-groups                     To show CSP groups which contain
                                        GROUP_SEARCH_TERM string
    search-csp-org-users                Search for users in the CSP or org.
    find-csp-user-by-service-role       Search for CSP users with a specific
                                        service role. First use show-csp-
                                        service-roles to see entitled roles
    show-org-users                      Show all organization users

optional arguments:
  -h, --help                            show this help message and exit
```

## 2. SDDC commands
```shell
usage:  sddc [-h]
             {show-compatible-subnets,show-connected-accounts,set-sddc-connected-services,show-sddc-connected-vpc,show-shadow-account,show-sddc-state,show-sddc-hosts,show-sddcs,show-vms}
             ...

positional arguments:
  {show-compatible-subnets,show-connected-accounts,set-sddc-connected-services,show-sddc-connected-vpc,show-shadow-account,show-sddc-state,show-sddc-hosts,show-sddcs,show-vms}
                                        sddc sub-command help
    show-compatible-subnets             show compatible native AWS subnets
                                        connected to the SDDC
    show-connected-accounts             show native AWS accounts connected to
                                        the SDDC
    set-sddc-connected-services         change whether to use S3 over the
                                        Internet(false) or via the ENI(true)
    show-sddc-connected-vpc             show the VPC connected to the SDDC
    show-shadow-account                 show the Shadow AWS Account VMC is
                                        deployed in
    show-sddc-state                     get a view of your selected SDDC
    show-sddc-hosts                     display a list of the hosts in your
                                        SDDC
    show-sddcs                          display a list of your SDDCs
    show-vms                            get a list of your VMs
    create                              create an SDDC
    delete                              delete an sddc
    watch-task                          watch a task for a long running sddc create or delete
    cancel-task                         cancel a long running task
    
optional arguments:
  -h, --help                            show this help message and exit
```

## 3. TKG commands
```shell
usage:  tkg [-h] {enable-tkg,disable-tkg} ...

positional arguments:
  {enable-tkg,disable-tkg}  sddc sub-command help
    enable-tkg              Enable Tanzu Kubernetes Grid on an SDDC
    disable-tkg             Disable Tanzu Kubernetes Grid on an SDDC

optional arguments:
  -h, --help                show this help message and exit
```

## 4 VTC commands
```shell
usage:  vtc [-h]
            {connect-aws,disconnect-aws,attach-dxgw,detach-dxgw,get-sddc-info,get-nsx-info,attach-sddc,detach-sddc,create-sddc-group,delete-sddc-group,get-group-info,attach-vpc,detach-vpc,vpc-prefixes}
            ...

positional arguments:
  {connect-aws,disconnect-aws,attach-dxgw,detach-dxgw,get-sddc-info,get-nsx-info,attach-sddc,detach-sddc,create-sddc-group,delete-sddc-group,get-group-info,attach-vpc,detach-vpc,vpc-prefixes}
                                        vtc sub-command help
    connect-aws                         Connect an vTGW to an AWS account
    disconnect-aws                      Disconnect a vTGW from an AWS account
    attach-dxgw                         Attach a Direct Connect Gateway to a
                                        vTGW
    detach-dxgw                         Detach a Direct Connect Gateway from a
                                        vTGW
    get-sddc-info                       Display a list of all SDDCs
    get-nsx-info                        Display NSX credentials and URLs
    attach-sddc                         Attach an SDDC to a vTGW
    detach-sddc                         Detach an SDDC from a vTGW
    create-sddc-group                   Create an SDDC group
    delete-sddc-group                   Delete an SDDC group
    get-group-info                      Display details for an SDDC group
    attach-vpc                          Attach a VPC to a vTGW
    detach-vpc                          Detach VPC from a vTGW
    vpc-prefixes                        Add or remove vTGW static routes

optional arguments:
  -h, --help                            show this help message and exit
```

## 5. NSX related commands
### 5.1 Segment commands
```shell
usage:  segment [-h] {create,delete,show,update} ...

positional arguments:
  {create,delete,show,update}
                        segment sub-command help
    create              Create a new virtual machine network segment.
    delete              Delete a virtual machine network segment.
    show                Show the current virtual machine network segments.
    update              Update the configuration of a virtual machine network
                        segment.

optional arguments:
  -h, --help            show this help message and exit
```
### 5.2 VPN commands
```shell
usage:  vpn [-h]
            {new-l2vpn,remove-l2VPN,remove-vpn,remove-vpn-ike-profile,remove-vpn-ipsec-tunnel-profile,show-l2vpn,show-l2vpn-services,show-vpn,show-vpn-ike-profile,show-vpn-internet-ip,show-vpn-ipsec-tunnel-profile,show-vpn-ipsec-endpoints,rbvpn-prefix-list,rbvpn-neighbors}
            ...

positional arguments:
  {new-l2vpn,remove-l2VPN,remove-vpn,remove-vpn-ike-profile,remove-vpn-ipsec-tunnel-profile,show-l2vpn,show-l2vpn-services,show-vpn,show-vpn-ike-profile,show-vpn-internet-ip,show-vpn-ipsec-tunnel-profile,show-vpn-ipsec-endpoints,rbvpn-prefix-list,rbvpn-neighbors}
                        vpn sub-command help
    new-l2vpn           create a new L2VPN
    remove-l2VPN        remove a L2VPN
    remove-vpn          remove a VPN
    remove-vpn-ike-profile
                        remove a VPN IKE profile
    remove-vpn-ipsec-tunnel-profile
                        To remove a VPN IPSec Tunnel profile
    show-l2vpn          show l2 vpn
    show-l2vpn-services
                        show l2 vpn services
    show-vpn            show the configured VPN
    show-vpn            show the VPN statistics
    show-vpn-ike-profile
                        show the VPN IKE profiles
    show-vpn-internet-ip
                        show the public IP used for VPN services
    show-vpn-ipsec-tunnel-profile
                        show the VPN tunnel profile
    show-vpn-ipsec-endpoints
                        show the VPN IPSec endpoints
    rbvpn-prefix-list   Create and configure route-based VPN prefix lists.
    rbvpn-neighbors     Show and configure BGP Neighbors for route-based VPN.

optional arguments:
  -h, --help            show this help message and exit
```
### 5.3 NAT commands
```shell
usage:  nat [-h] {new-nat-rule,remove-nat-rule,show-nat} ...

positional arguments:
  {new-nat-rule,remove-nat-rule,show-nat}
                        nat sub-command help
    new-nat-rule        To create a new NAT rule
    remove-nat-rule     remove a NAT rule
    show-nat            show the configured NAT rules

optional arguments:
  -h, --help            show this help message and exit
```
### 5.4 T1 commands
```shell
usage:  t1 [-h] {create,delete,update} ...

positional arguments:
  {create,delete,update}
                        t1 sub-command help
    create              Create a new, secondary T1 gateway.
    delete              Delete a secondary T1 gateway.
    update              Update the configuration of a secondary T1 gateway.

optional arguments:
  -h, --help            show this help message and exit
```
### 5.5 GWFW commands
```shell
usage:  gwfw [-h]
             {new-cgw-rule,new-mgw-rule,remove-cgw-rule,remove-mgw-rule,show-cgw-rule,show-mgw-rule}
             ...

positional arguments:
  {new-cgw-rule,new-mgw-rule,remove-cgw-rule,remove-mgw-rule,show-cgw-rule,show-mgw-rule}
                        gwfw sub-command help
    new-cgw-rule        create a new CGW security rule
    new-mgw-rule        create a new MGW security rule
    remove-cgw-rule     delete a CGW security rule
    remove-mgw-rule     delete a MGW security rule
    show-cgw-rule       show the CGW security rules
    show-mgw-rule       show the MGW security rules

optional arguments:
  -h, --help            show this help message and exit
```
### 5.6 DFW commands
```shell
usage:  dfw [-h]
            {new-dfw-rule,new-dfw-section,remove-dfw-rule,remove-dfw-section,show-dfw-section,show-dfw-section-rules}
            ...

positional arguments:
  {new-dfw-rule,new-dfw-section,remove-dfw-rule,remove-dfw-section,show-dfw-section,show-dfw-section-rules}
                        dfw sub-command help
    new-dfw-rule        create a new DFW security rule
    new-dfw-section     create a new DFW section
    remove-dfw-rule     delete a DFW rule
    remove-dfw-section  delete a DFW section
    show-dfw-section    show the DFW sections
    show-dfw-section-rules
                        show the DFW security rules within a section

optional arguments:
  -h, --help            show this help message and exit
```
### 5.7 NSXAF commands
```shell
usage:  nsxaf [-h]
              {show-nsxaf-status,show-ids-cluster-status,enable-cluster-ids,disable-cluster-ids,enable-all-cluster-ids,disable-all-cluster-ids,enable-ids-auto-update,ids-update-signatures,show-ids-signature-versions,show-ids-profiles,search-product-affected,create-ids-profile,show-ids-policies,create-ids-policy,show-ids-rules,create-ids-rule}
              ...

positional arguments:
  {show-nsxaf-status,show-ids-cluster-status,enable-cluster-ids,disable-cluster-ids,enable-all-cluster-ids,disable-all-cluster-ids,enable-ids-auto-update,ids-update-signatures,show-ids-signature-versions,show-ids-profiles,search-product-affected,create-ids-profile,show-ids-policies,create-ids-policy,show-ids-rules,create-ids-rule}
                                        nsxaf sub-command help
    show-nsxaf-status                   Display the status of the NSX Advanced
                                        Firewall Add-on
    show-ids-cluster-status             Show IDS status for each cluster in
                                        the SDDC
    enable-cluster-ids                  Enable IDS on cluster
    disable-cluster-ids                 Disable IDS on cluster
    enable-all-cluster-ids              Enable IDS on all clusters
    disable-all-cluster-ids             Disable IDS on all clusters
    enable-ids-auto-update              Enable IDS signature auto update
    ids-update-signatures               Force update of IDS signatures
    show-ids-signature-versions         Show downloaded signature versions
    show-ids-profiles                   Show all IDS profiles
    search-product-affected             Search through the active IDS
                                        signature for specific product
                                        affected. Useful when building an IDS
                                        Profile
    create-ids-profile                  Create an IDS profile with either
                                        Product Affected, CVSS or both.
    show-ids-policies                   List all IDS policies
    create-ids-policy                   Create an IDS policy
    show-ids-rules                      List all IDS rules
    create-ids-rule                     Create an IDS rule using previously
                                        created IDS profile and inventory
                                        groups

optional arguments:
  -h, --help                            show this help message and exit
```
### 5.8 Inventory commands
```shell
usage:  inventory [-h]
                  {new-group,remove-group,show-group,show-group-association,new-service,remove-service,show-services}
                  ...

positional arguments:
  {new-group,remove-group,show-group,show-group-association,new-service,remove-service,show-services}
                        inventory sub-command help
    new-group           create a new group
    remove-group        remove a group
    show-group          show existing groups
    show-group-association
                        show security rules used by a groups
    new-service         create a new service
    remove-service      remove a service
    show-services       show services

optional arguments:
  -h, --help            show this help message and exit
```
### 5.9 System commands
```shell
usage:  system [-h]
               {show-dns-services,show-dns-zones,new-sddc-public-ip,remove-sddc-public-ip,set-sddc-public-ip,show-sddc-public-ip,mtu,asn,dx-admin-cost,show-egress-interface-counters,show-routes}
               ...

positional arguments:
  {show-dns-services,show-dns-zones,new-sddc-public-ip,remove-sddc-public-ip,set-sddc-public-ip,show-sddc-public-ip,mtu,asn,dx-admin-cost,show-egress-interface-counters,show-routes}
                        system sub-command help
    show-dns-services   Show currently configured DNS services
    show-dns-zones      Show currently configured DNS zone services.
    new-sddc-public-ip  request a new public IP
    remove-sddc-public-ip
                        remove an existing public IP
    set-sddc-public-ip  update the description of an existing public IP
    show-sddc-public-ip
                        show the public IPs
    mtu                 Show and update configuration data associated with
                        Maximum Transmission Unit value for the Intranet
                        Interface.
    asn                 Show and update configuration data associated with
                        Autonomous System Number value for the Intranet
                        Interface.
    dx-admin-cost       Use to view currently configured routing preference /
                        admin cost - VPN or DX.
    show-egress-interface-counters
                        show current Internet interface egress counters
    show-routes         Show SDDC routes

optional arguments:
  -h, --help            show this help message and exit
```
### 5.10 serach-nsx commands
```shell
usage:  search-nsx [-h] [--nsxm [NSXM]]
                   [-ot {BgpNeighborConfig,BgpRoutingConfig,Group,IdsSignature,PrefixList,RouteBasedIPSecVPNSession,Segment,Service,StaticRoute,Tier0,Tier1,VirtualMachine,VirtualNetworkInterface}]
                   [-oid OBJECT_ID]

optional arguments:
  -h, --help                            show this help message and exit
  --nsxm [NSXM]                         Used to specify NSX Manager instead of NSX proxy (Default).
  -ot {BgpNeighborConfig,BgpRoutingConfig,Group,IdsSignature,PrefixList,RouteBasedIPSecVPNSession,Segment,Service,StaticRoute,Tier0,Tier1,VirtualMachine,VirtualNetworkInterface}, --object_type {BgpNeighborConfig,BgpRoutingConfig,Group,IdsSignature,PrefixList,RouteBasedIPSecVPNSession,Segment,Service,StaticRoute,Tier0,Tier1,VirtualMachine,VirtualNetworkInterface}
                                        The type of object to search for.
  -oid OBJECT_ID, --object_id OBJECT_ID
                                        The name of the object you are searching for.
```

## 6. VCDR commands
```shell
usage:  vcdr [-h] {scfs,pg,snaps,rsddc,psite,vms} ...

positional arguments:
  {scfs,pg,snaps,rsddc,psite,vms}
                        vcdr sub-command help
    scfs                VCDR cloud file system - use '-h' for help.
    pg                  VCDR Protection Groups - use '-h' for help.
    snaps               VCDR Snapshots - use '-h' for help.
    rsddc               VCDR Recovery SDDC - use '-h' for help.
    psite               VCDR Protected Site - use '-h' for help.
    vms                 VCDR cloud file system - use '-h' for help.

optional arguments:
  -h, --help            show this help message and exit
```

## 7. Flex Compute commands
```shell
usage:  flexcomp [-h]
        {activity-status,show-all-namespaces,validate-network,create-flexcompute,delete-flexcomp,show-flex-comp-regions,show-flex-comp-templates,show-all-vms,show-all-images,create-vm,power-operation,delete-vm}
        ...

positional arguments:
  {activity-status,show-all-namespaces,validate-network,create-flexcompute,delete-flexcomp,show-flex-comp-regions,show-flex-comp-templates,show-all-vms,show-all-images,create-vm,power-operation,delete-vm}
                                        flexcomp sub-command help
    activity-status                     Get activity status of long running tasks
    show-all-namespaces                 Show all present Cloud Flex Compute Name Spaces
    validate-network                    Validate network CIDR before creating Cloud Flex Compute Name Space
    create-flexcompute                  Create new Cloud Flex Compute
    delete-flexcomp                     Delete existing Cloud Flex Compute
    show-flex-comp-regions              Show available Cloud Flex Compute regions
    show-flex-comp-templates            Show available Cloud Flex Compute resource templates to create Name Space
    show-all-vms                        Show all VMs in Cloud Flex Compute instance
    show-all-images                     Show all images available to create VMs from
    create-vm                           Create VM
    power-operation                     Perform Power Operations on VM
    delete-vm                           Delete VM. Make sure VM is in powerd OFF state.

options:
  -h, --help
```