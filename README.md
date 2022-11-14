# 1.python-client-for-vmware-cloud-on-aws

## 1.1 Table of Contents
<!-- TOC -->

<!-- TOC -->

## 1.2 Overview

Welcome to the Python Client for VMware Cloud on AWS!  PyVMC is a Python tool developed for assisting system administrators with the deployment, configuration, and management of the VMware Cloud on AWS service. PyVMC was created by Nicolas Vibert and Matt Dreyer.  While it started as a series of a few commands used for creating some network and firewall rules, it has grown to become a fairly comprehensive CLI that can be used for anything from adding users to your VMware Cloud organization, viewing and manipulating the route tables associated with your SDDC, configuring and updating IDS rules, or even enabling and monitoring services like Tanzu Kubernetes Service or VMware Cloud DR.

## 1.3 Getting Started

### 1.3.1 Install Python
This tool is dependent on Python3, you can find installation instructions for your operating system in the Python documentation (https://wiki.python.org/moin/BeginnersGuide/Download).

### 1.3.2 Download code
If you know git, clone the repo with

```git clone https://github.com/vmware/python-client-for-vmware-cloud-on-aws.git ```

If you don't know git, you can download the code from the Flings site (https://flings.vmware.com/python-client-for-vmc-on-aws)

### 1.3.3 Install Python modules and packages
When you navigate to the python-client-for-vmware-cloud-on-aws folder, you will find a requirements.txt file that lists all your Python packages. They can all be installed by running the following command on Linux/Mac:

```pip3 install -r requirements.txt```

On Windows, use

```python -m pip install -r requirements.txt```


### 1.3.4 Update config.ini
Obtain a refresh token from the VMware Cloud Service Portal, as well as the ORG ID and SDDC  ID of the environment you wish to interact with .  Copy config.ini.example to config.ini and edit the config.ini with your own SDDC ID, Organization (Org) ID and your access token.

### 1.3.5 Do I need to know Python?
No! You can simply use it to consume and manage your VMware Cloud on AWS SDDC (Software-Defined Data Center). 

## 1.4 Support 

### 1.4.1 Is it officially supported by VMware?
Sorry but no, this is a community-based effort. Use it at your own risk. It has extensively been tested though and we'll endeavour to fix any bugs.

### 1.4.2 Which version of VMware Cloud on AWS has it been tested against?
Versions 1.9, 1.10, 1.11, 1.12, 1.14... all the way up through 1.20. We don't guarantee support with previous versions. 
We will, however, endeavour to verify compatibility as we release new versions.

### 1.4.3 What if I find a bug or need a new feature?
Please raise it on GitHub and we will look into it.

## 1.5 Documentation

### 1.5.1  Where can I find documentation about VMware Cloud on AWS:
Please check the online documentation:
https://docs.vmware.com/en/VMware-Cloud-on-AWS/index.html

### 1.5.2 Where can I find documentation about each pyVMC commands?

Here are the currently supported 'super' commands:
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

To see the supported commands for any given category / super-command, simply use '-h'... for example:

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


Check the docs folder for a comprehensive listing of all currently supported commands.

## 1.6 Release Notes:
In this latest release, all commands have been refactored to use a command / sub-command syntax.  This provides for greater ease of use, as commands can be grouped by category.  Furthermore, a comprehensive argument framework has been implemented (argparse) which allows for passing parameters via the command line for better support for scripting. 

For example, in previous versions BGP prefix filters for your route-based VPN could only be created interactively at the command line.  Now, however, prefix lists can be imported as JSON files to make it a lot easier to update your T0 route table via script for specific use cases - e.g. disaster recovery.

New Features:
 - all commands refactored to use argument parsing with python argparse module
 - prefix list commands for route based VPN have been renamed to rbvpn-prefix-list, found under the 'system' super command
 - moving forward, all commands will be updated (over time) to use standardized create / update / delete verbs (CrUD) where applicable
 - 

New Commands / options:
 - asn: replaces previous ASN commands show-sddc-bgp-as / set-sddc-bgp-as
 - csp: new super-command for all commands related to CSP
 - dfw: new supercommand for distributed firewall sub-commands (use -h to see sub-commands)
 - dns: replaces previous commands show-dns-services / show-dns-zones
 - dx-admin-cost: replaces previous command show-sddc-bgp-vpn
 - gwfw: new supercommand for gateway firewall sub-commands (use -h to see sub-commands)
 - mtu: replaces previous MTU commands show-mtu / set-mtu
 - nat: replaces previous commands new-nat-rule / remove-nat-rule / show-nat-rule
 - nsxaf: new super-command for all subcommands related to NSX Advanced Firewall (IDS, etc) (use -h to see sub-commands)
 - rbvpn-neighbors: replaces previous command show-t0-bgp-neighbors
 - rbvpn-prefix-list: replaces new-t0-prefix-list, remove-t0-prefix-list, attach-t0-prefix-list, detach-t0-prefix-list.  Added ability to import or export prefix lists to / from JSON files
 - segment: replaces previous commands for creating and deleting VM networks (new-network, new-segment, etc)
 - show-routes command to replace show-t0-routes, show-static-routes, show-bgp-routes, show-tgw-routes
 - system: new super-command for all commands related to the SDDC/NSX system (DNS, ASN, MTU, etc) (use -h to see sub-commands)
 - t1: replaces previous commands for creating and deleting tier1 gateways (configure-t1, remove-t1)
 - tkg: new super-command for all subcommands related to Tanzu Kubernetes Service (use -h to see sub-commands)
 - vcdr: new super command replaces all previous vcdr commands (use -h to see sub-commands)
 - vpn:  new super command replaces all previous vpn commands (use -h to see sub-commands)
 - vtc: new super-command for all subcommands related to VMware Transit Connect (use -h to see sub-commands)

## 1.7 Known Issues:


## 1.8 Contributing

The python-client-for-vmware-cloud-on-aws project team welcomes contributions from the community. Before you start working with python-client-for-vmware-cloud-on-aws, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## 1.9 License

SPDX-License-Identifier: BSD-2-Clause
