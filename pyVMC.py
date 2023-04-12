#!/usr/bin/env python3
# The shebang above is to tell the shell which interpreter to use. This make the file executable without "python3" in front of it (otherwise I had to use python3 pyvmc.py)
# I also had to change the permissions of the file to make it run. "chmod +x pyVMC.py" did the trick.
# I also added "export PATH="MY/PYVMC/DIRECTORY":$PATH" (otherwise I had to use ./pyvmc.y)
# For git BASH on Windows, you can use something like this #!/C/Users/usr1/AppData/Local/Programs/Python/Python38/python.exe

# Python Client for VMware Cloud on AWS

################################################################################
### Copyright (C) 2019-2023 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################


"""

Welcome to PyVMC ! 

VMware Cloud on AWS API Documentation is available at: https://code.vmware.com/apis/920/vmware-cloud-on-aws
CSP API documentation is available at https://console.cloud.vmware.com/csp/gateway/api-docs
vCenter API documentation is available at https://code.vmware.com/apis/366/vsphere-automation


You can install python 3.10 from https://www.python.org/downloads/windows/ (Windows) or https://www.python.org/downloads/mac-osx/ (MacOs).

You can install the dependent python packages locally (handy for Lambda) with:
pip3 install requests or pip3 install requests -t . --upgrade
pip3 install configparser or pip3 install configparser -t . --upgrade
pip3 install PTable or pip3 install PTable -t . --upgrade

With git BASH on Windows, you might need to use 'python -m pip install' instead of pip3 install

"""
import argparse
import sys
from pyvmc_fxns import *


# --------------------------------------------
# ---------------- Main ----------------------
# --------------------------------------------
def main():

#   Should we have a separate module for argument handling?
#   Should we have a separate module for parsing the config.ini?

    from argparse import SUPPRESS

    class MyFormatter(argparse.RawDescriptionHelpFormatter):
        def __init__(self,prog):
            super(MyFormatter, self).__init__(prog,max_help_position=40)
    # this is the top level parser
    # ap = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
    ap = argparse.ArgumentParser(formatter_class=MyFormatter, usage=SUPPRESS,
                                    epilog="Welcome to pyVMC!\n\n"
                                    "Examples:\n\n"
                                    "Show a list of network segments:\n"
                                    "./pyVMC.py search-nsx Segment\n\n"
                                    "Show the SDDC route table:\n"
                                    "./pyVMC.py system show-routes t0 \n \u00A0 \n")

    # create a subparser for the subsequent sections    
    subparsers = ap.add_subparsers(help='sub-command help')

# ============================
# GLOBAL Auth Parser
# ============================
    """Parser to be used as parent for ALL FUNCTIONS AND SUBPARSERS.
    This will allow the user to specify either to use a refresh token or an OAuth app.
    Excluding this parser as a parent will ALSO exclude the exclude the option to use OAuth as an authentication method..
    *** Be sure to include this parser as a parent for ALL subparsers ***
    """
    auth_flag = argparse.ArgumentParser(add_help=False)
    auth_flag.add_argument('--oauth', nargs='?', default = "refresh_token", const= "oauth", help = "Used to specify use of OAuth app ID and secret in config.ini instead of 'refresh_token' (default).")

# ============================
# GLOBAL NSX Parser
# ============================
    """Parser to be used as parent for ALL NSX functions.
    This will allow the user to specify either the NSX proxy or the NSX Manager URL be included in the payload to the function.
    Excluding this parser as a parent will ALSO exclude the NSX Proxy / Manager URL from the keyword arguments passed to functions.
    *** Be sure to include this parser as a parent for any NSX subparsers ***
    """
    nsx_url_flag = argparse.ArgumentParser(add_help=False)
    nsx_url_flag.add_argument("--nsxm", nargs = '?', default = "proxy", const = "nsxm", help = "Used to specify NSX Manager instead of NSX proxy (Default).")

# ============================
# GLOBAL Parsers
# ============================
    """Parsers to be used as parent to pass glaf(s) for correct API URL, ORG_ID, or SDDC_ID"""
        
    csp_url_flag = argparse.ArgumentParser(add_help=False)
    csp_url_flag.add_argument("--csp_flag",help=argparse.SUPPRESS) # TOM What about config.ini?

    vmc_url_flag = argparse.ArgumentParser(add_help=False)
    vmc_url_flag.add_argument("--vmc_flag",help=argparse.SUPPRESS)

    vcdr_url_flag= argparse.ArgumentParser(add_help=False)
    vcdr_url_flag.add_argument("--vcdr_flag", help = argparse.SUPPRESS)

    vtc_config_flag= argparse.ArgumentParser(add_help=False)
    vtc_config_flag.add_argument("--vtc_flag", help = argparse.SUPPRESS)

    org_id_flag = argparse.ArgumentParser(add_help=False)
    org_id_flag.add_argument("--org_flag",help=argparse.SUPPRESS)

    sddc_id_parser_flag = argparse.ArgumentParser(add_help=False)
    sddc_id_parser_flag.add_argument("--sddc_flag",help=argparse.SUPPRESS)

# ============================
# PyVMC Config
# ============================

    # create the parser for the "config" command
    config_parser=subparsers.add_parser('config', formatter_class=MyFormatter, help='Commands related to the configuration of pyVMC.')
    # create a subparser for config sub-commands
    config_parser_subs = config_parser.add_subparsers(help='config sub-command help')

    config_show_parser = config_parser_subs.add_parser('build', help = "Show the current configuration of pyVMC.")
    config_show_parser.set_defaults(func = build_initial_config)

    config_show_parser = config_parser_subs.add_parser('show', help = "Show the current configuration of pyVMC.")
    config_show_parser.set_defaults(func = show_config)


# ============================
# CSP
# ============================

    # create the parser for the "csp" command
    csp_parser=subparsers.add_parser('csp', formatter_class=MyFormatter, help='Commands related to the Cloud Service Portal itself.')
    # create a subparser for csp sub-commands
    csp_parser_subs = csp_parser.add_subparsers(help='csp sub-command help')

# ============================
# CSP - Services
# ============================

    csp_service_parser = csp_parser_subs.add_parser('show-csp-services', parents=[auth_flag,csp_url_flag,org_id_flag], help='Show the entitled services in the VMware Cloud Service Console.')
    csp_service_parser.set_defaults(func = getServiceDefinitions)
    csp_service_role_parser = csp_parser_subs.add_parser('show-csp-service-roles', parents=[auth_flag,csp_url_flag, org_id_flag] , help='Show the entitled service roles in the VMware Cloud Service Console.')
    csp_service_role_parser.set_defaults(func = getCSPServiceRoles)
    # get_access_token_parser=csp_parser_subs.add_parser('get-access-token', parents=[auth_flag,csp_url_flag, nsx_url_flag], help = 'show your access token')

# ============================
# CSP - User and Group Management
# ============================
    add_users_to_csp_group_parser=csp_parser_subs.add_parser('add-users-to-csp-group', parents=[auth_flag,csp_url_flag, org_id_flag], help = 'CSP user to a group')
    add_users_to_csp_group_parser.add_argument('-g', '--group-id', required=True, help= "The ID of the group to search or modify.")
    add_users_to_csp_group_parser.add_argument('-e', '--email', nargs = '+',required=True, help= "Use to specify an email to search by, or a list of space-separated emails to add to a group.")
    add_users_to_csp_group_parser.set_defaults(func = addUsersToCSPGroup)

    show_csp_group_diff_parser=csp_parser_subs.add_parser('show-csp-group-diff', parents=[auth_flag,csp_url_flag, org_id_flag], help = 'this compares the roles in the specified group with every user in the org and prints out a user-by-user diff')
    show_csp_group_diff_parser.add_argument('-g', '--group-id', required=True, help= "The ID of the group to search or modify.")
    show_csp_group_diff_parser.add_argument('-f', '--filter', choices=['showall', 'skipmembers','skipowners'], required=True, help = "Filter out specific members of the group.")
    show_csp_group_diff_parser.set_defaults(func = getCSPGroupDiff)

    show_csp_group_members_parser=csp_parser_subs.add_parser('show-csp-group-members', parents=[auth_flag,csp_url_flag, org_id_flag], help = 'show CSP group members')
    show_csp_group_members_parser.add_argument('-g', '--group-id', required=True, help= "The ID of the group to search or modify.")
    show_csp_group_members_parser.set_defaults(func = getCSPGroupMembers)

    show_csp_groups_parser=csp_parser_subs.add_parser('show-csp-groups', parents=[auth_flag,csp_url_flag, org_id_flag], help = 'To show CSP groups which contain GROUP_SEARCH_TERM string')
    show_csp_groups_parser.add_argument('-s', '--search-term', help = "Text string to filter search.")
    show_csp_groups_parser.set_defaults(func = getCSPGroups)

    search_csp_org_users_parser=csp_parser_subs.add_parser('search-csp-org-users', parents=[auth_flag,csp_url_flag, org_id_flag], help = 'Search for users in the CSP or org.')
    search_csp_org_users_parser.add_argument('-s', '--search-term', required=True, help = "Text string to filter search.")
    search_csp_org_users_parser.set_defaults(func = searchCSPOrgUsers)

    find_csp_user_by_service_role_parser=csp_parser_subs.add_parser('find-csp-user-by-service-role', parents=[auth_flag,csp_url_flag, org_id_flag], help = 'Search for CSP users with a specific service role.  First use show-csp-service-roles to see entitled roles')
    find_csp_user_by_service_role_parser.add_argument('-r', '--service-role', required=True, help= "The service role to search by.")
    find_csp_user_by_service_role_parser.set_defaults(func = findCSPUserByServiceRole)

    show_org_users_parser=csp_parser_subs.add_parser('show-org-users', parents=[auth_flag,csp_url_flag, org_id_flag], help = 'Show all organization users')
    show_org_users_parser.set_defaults(func = showORGusers)

# ============================
# Cloud Flex Compute
# ============================

    # create the parser for the "flex-compute" command
    flexcomp_parser = subparsers.add_parser('flexcomp', formatter_class=MyFormatter, help='Commands related to the Cloud Flex Compute itself.')
    # create subparser for flexcomp sub-commands
    flexcomp_parser_sub = flexcomp_parser.add_subparsers(help='flexcomp sub-command help')

    flexcomp_activityStatus = flexcomp_parser_sub.add_parser('activity-status', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Get activity status of long running tasks')
    flexcomp_activityStatus.add_argument('activityId', help='Activity ID of the task.')
    flexcomp_activityStatus.set_defaults(func=showFlexcompActivityStatus)

# =================================
# Cloud Flex Compute - Compute
# =================================
    show_all_namespaces = flexcomp_parser_sub.add_parser('show-all-namespaces', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Show all present Cloud Flex Compute Name Spaces')
    show_all_namespaces.set_defaults(func=showFlexcompNamespaces)

    validate_network = flexcomp_parser_sub.add_parser('validate-network', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Validate network CIDR before creating Cloud Flex Compute Name Space')
    validate_network.add_argument('flexCompCIDR', help='Specify the IP address range for your VMware Cloud Flex Compute. Example: 10.2.0.0/16')
    validate_network.add_argument('segName', help='Workload Segment name')
    validate_network.add_argument('segCIDR', help='Specify the IP address range for your Workload Segment. Example: 10.2.x.0/24')
    validate_network.set_defaults(func=validateNetworkFlexComp)

    create_flexcomp_namespace = flexcomp_parser_sub.add_parser('create-flexcompute',parents=[auth_flag,vmc_url_flag,org_id_flag], help='Create new Cloud Flex Compute')
    create_flexcomp_namespace.add_argument('nsName', help='Name of Cloud Flex Compute')
    create_flexcomp_namespace.add_argument('nsDesc', help='Description for Cloud Flex Compute')
    create_flexcomp_namespace.add_argument('templateId', help='Resource size template id. Available values can be seen using `show-flex-comp-templates` option')
    create_flexcomp_namespace.add_argument('region', help='Cloud Flex Compute region name. Available regions can be seen using `show-flex-comp-regions` option')
    create_flexcomp_namespace.add_argument('flexCompCIDR',
                              help='Specify the IP address range for your VMware Cloud Flex Compute. Example: 10.2.0.0/16')
    create_flexcomp_namespace.add_argument('segName', help='Workload Segment name')
    create_flexcomp_namespace.add_argument('segCIDR',
                              help='Specify the IP address range for your Workload Segment. Example: 10.2.x.0/24')
    create_flexcomp_namespace.set_defaults(func=createFlexcompNamespace)

    delete_flexcomp_namespace = flexcomp_parser_sub.add_parser('delete-flexcomp', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Delete existing Cloud Flex Compute')
    delete_flexcomp_namespace.add_argument('nsId', help='Cloud Flex Compute ID. Available Cloud Flex Compute IDs can be seen using `show-all-namespaces` option')
    delete_flexcomp_namespace.set_defaults(func=deleteFlexcompNamespace)

# =================================
# Cloud Flex Compute - Profiles
# =================================
    show_flexcomp_region = flexcomp_parser_sub.add_parser('show-flex-comp-regions', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Show available Cloud Flex Compute regions')
    show_flexcomp_region.set_defaults(func=showFlexcompRegions)
    show_flexcomp_templates = flexcomp_parser_sub.add_parser('show-flex-comp-templates', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Show available Cloud Flex Compute resource templates to create Name Space')
    show_flexcomp_templates.set_defaults(func=showFlexcompTemplates)

# =================================
# Cloud Flex Compute - VMs
# =================================
    show_flexcomp_vms = flexcomp_parser_sub.add_parser('show-all-vms', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Show all VMs in Cloud Flex Compute instance')
    show_flexcomp_vms.set_defaults(func=showAllVMsFlexcomp)

    show_flexcomp_images = flexcomp_parser_sub.add_parser('show-all-images', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Show all images available to create VMs from')
    show_flexcomp_images.set_defaults(func=showAllImagesFlexcomp)

    flexcomp_createVm = flexcomp_parser_sub.add_parser('create-vm', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Create VM')
    flexcomp_createVm.add_argument('vmName', help='Virtual Machine Name')
    flexcomp_createVm.add_argument('vmNamespaceId', help='Namespace ID on which to create VM')
    flexcomp_createVm.add_argument('vmCPU', help='Number of CPUs for the VM. Min 1 CPU, Max 36 CPU. Make sure CPU number is less or equal to CPUs for Namespace')
    flexcomp_createVm.add_argument('vmMem', help='Memory in GB for the VM. Min 1 GB, Max 1 TiB. Make sure memory size is less or equal to memory for Namespace')
    flexcomp_createVm.add_argument('vmStorage', help='Storage for the VM. Min 1 MB, Max 61 TiB. Make sure storage size is less or equal to storage for Namespace')
    flexcomp_createVm.add_argument('networkSegName', help='Network Seg Name')
    # flexcomp_createVm.add_argument('networkSegCIDR', help='Network Seg CIDR')
    flexcomp_createVm.add_argument('guestOS', help='Current support for Linux Guest OS : UBUNTU_64, RHEL_6_64, RHEL_7_64, CENTOS_7_64')
    flexcomp_createVm.add_argument('imageId', help='ISO Image name from which VM will be created.')
    flexcomp_createVm.set_defaults(func=createVMFlexcomp)

    flexcomp_vmPowerOps = flexcomp_parser_sub.add_parser('power-operation', parents=[auth_flag,vmc_url_flag,org_id_flag], help='Perform Power Operations on VM')
    flexcomp_vmPowerOps.add_argument('vmId', help='VM ID for the VM on which power operation needs to be performed. Available VMs can be seen using `show-all-vms` option')
    flexcomp_vmPowerOps.add_argument('powerOperation', help='Available operations are: power_off, power_on, suspend, hard_stop, reset, guest_os_shutdown, guest_os_restart')
    flexcomp_vmPowerOps.set_defaults(func=vmPowerOperationsFlexcomp)

    flexcomp_vmDelete = flexcomp_parser_sub.add_parser('delete-vm', parents=[auth_flag,vmc_url_flag, org_id_flag], help='Delete VM. Make sure VM is in powerd OFF state.')
    flexcomp_vmDelete.add_argument('vmId',help='VM ID for the VM on which power operation needs to be performed. Available VMs can be seen using `show-all-vms` option')
    flexcomp_vmDelete.set_defaults(func=vmDeleteFlexcomp)

# ============================
# SDDC - AWS Account and VPC
# ============================

    # create the parser for the "sddc" command
    sddc_parser=subparsers.add_parser('sddc', formatter_class=MyFormatter, help='Commands related to the Software Defined Datacenter (SDDC) itself.')
    # create a subparser for csp sub-commands
    sddc_parser_subs = sddc_parser.add_subparsers(help='sddc sub-command help')

    show_compatible_subnets_parser=sddc_parser_subs.add_parser('show-compatible-subnets', parents=[auth_flag,vmc_url_flag,org_id_flag,sddc_id_parser_flag], help = 'show compatible native AWS subnets connected to the SDDC')
    show_compatible_subnets_parser.add_argument("LinkedAccount", help = "The Object ID of the linked Account") # positional arg 1
    show_compatible_subnets_parser.add_argument("Region", help = "The text of the region ID") # positional arg 2
    show_compatible_subnets_parser.set_defaults(func = getCompatibleSubnets)
    
    show_connected_accounts_parser=sddc_parser_subs.add_parser('show-connected-accounts', parents=[auth_flag,vmc_url_flag,org_id_flag, sddc_id_parser_flag], help = 'show native AWS accounts connected to the SDDC')
    show_connected_accounts_parser.set_defaults(func = getConnectedAccounts)

    set_sddc_connected_services_parser=sddc_parser_subs.add_parser('set-sddc-connected-services', parents=[auth_flag,nsx_url_flag], help = 'change whether to use S3 over the Internet(false) or via the ENI(true)')
    set_sddc_connected_services_parser.add_argument('ServiceName', choices=['s3'], help="Only s3 for now")
    set_sddc_connected_services_parser.add_argument('ENIorInternet', choices=['true','false'], help="Connect s3 to ENI (true) or Internet (false)")
    set_sddc_connected_services_parser.set_defaults(func = setSDDCConnectedServices)

    show_sddc_connected_vpc_parser=sddc_parser_subs.add_parser('show-sddc-connected-vpc', parents=[auth_flag,vmc_url_flag,sddc_id_parser_flag, nsx_url_flag], help = 'show the VPC connected to the SDDC')
    show_sddc_connected_vpc_parser.set_defaults(func = getSDDCConnectedVPC)
    
    show_shadow_account_parser=sddc_parser_subs.add_parser('show-shadow-account', parents=[auth_flag,vmc_url_flag,nsx_url_flag], help = 'show the Shadow AWS Account VMC is deployed in')
    show_shadow_account_parser.set_defaults(func = getSDDCShadowAccount) 

# ============================
# SDDC - SDDC
# ============================
    parent_sddc_parser = argparse.ArgumentParser(add_help=False)

    show_sddc_state_parser=sddc_parser_subs.add_parser('show-sddc-state', parents=[auth_flag,vmc_url_flag,org_id_flag,sddc_id_parser_flag], help = 'get a view of your selected SDDC')
    show_sddc_state_parser.set_defaults(func = getSDDCState) 
    show_sddc_hosts_parser=sddc_parser_subs.add_parser('show-sddc-hosts', parents=[auth_flag,vmc_url_flag,org_id_flag,sddc_id_parser_flag], help = 'display a list of the hosts in your SDDC')
    show_sddc_hosts_parser.set_defaults(func = getSDDChosts)

    show_sddcs_parser=sddc_parser_subs.add_parser('show-sddcs', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'display a list of your SDDCs')
    show_sddcs_parser.set_defaults(func = getSDDCS)
    show_vms_parser=sddc_parser_subs.add_parser('show-vms', parents=[auth_flag,nsx_url_flag], help = 'get a list of your VMs')
    show_vms_parser.set_defaults(func = getVMs)

  # Create-sddc
    create_sddc_parser=sddc_parser_subs.add_parser('create', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Create an SDDC')
    create_sddc_parser.add_argument('-n','--name', required = True, help= 'name for newly created SDDC')
    create_sddc_parser.add_argument('-aws','--aws_account_guid', required = True, help='GUID for linked/connected AWS account')
    create_sddc_parser.add_argument('-r','--region',required = True,  help='string literal for AWS region; see https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html#concepts-available-regions')
    create_sddc_parser.add_argument('-num','--number',type=int,required = True,  help="number of hosts in new region")
    # where to get the canonical list https://developer.vmware.com/apis/vmc/v1.1/data-structures/SddcConfig/
    create_sddc_parser.add_argument('-t','--host_type', choices=['i3.metal','i3en.metal','i4i.metal'], required = True, help="string literal for host type")
    create_sddc_parser.add_argument('-sid','--aws_subnet_id', required = True, help='subnet ID for the apropriate subnet for new SDDC in subnet format, eg subnet-xxxxxx')
    create_sddc_parser.add_argument('-mgt','--mgt_subnet', required = True, help='CIDR for SDDC management subnet.  Accepts only /16, /20, or /23')
    create_sddc_parser.add_argument('-s','--sddc_size', required = False, choices=['nsx_small','medium','large','nsx_large'], help='add size argument to help size vCenter and NSX Manager')
    create_sddc_parser.add_argument('-v','--validate-only', action='store_true',  help="(optional) Validate the input parameters but do not create the SDDC")
    create_sddc_parser.set_defaults(func = createSDDC)
    
    delete_sddc_parser=sddc_parser_subs.add_parser('delete', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Delete an SDDC')
    delete_sddc_parser.add_argument("SDDCtoDelete", help = "The object id of the sddc to delete")
    delete_sddc_parser.add_argument("--force",action='store_true', help="(optional) Force the deletion of an SDDC")
    delete_sddc_parser.set_defaults(func = deleteSDDC)

# ============================
# SDDC - SDDC Tasks
# ============================
    watch_task_parser=sddc_parser_subs.add_parser('watch-task', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Poll a tasks until completion') 
    watch_task_parser.set_defaults(func = watchSDDCTask )
    watch_task_parser.add_argument("taskID",help="GUID for task you want info on") 
    cancel_task_parser=sddc_parser_subs.add_parser('cancel-task', parents=[auth_flag,vmc_url_flag,org_id_flag,sddc_id_parser_flag], help = 'Cancel a task, if possible') 
    cancel_task_parser.add_argument("taskID", help="GUID for task you want to cancel")
    cancel_task_parser.set_defaults(func = cancelSDDCTask)

# ============================
# SDDC - TKG
# ============================
    parent_tkg_parser = argparse.ArgumentParser(add_help=False)

    # create the parser for the "tkg" command
    tkg_parser=subparsers.add_parser('tkg', formatter_class=MyFormatter, help='Commands related to the Tanzu Kubernetes Service (TKG).')
    # create a subparser for csp sub-commands
    tkg_parser_subs = tkg_parser.add_subparsers(help='sddc sub-command help')

    # create parsers for each of the inidividual subcommands
    enable_tkg_parser=tkg_parser_subs.add_parser('enable-tkg', parents=[auth_flag, vmc_url_flag, org_id_flag, sddc_id_parser_flag], help = 'Enable Tanzu Kubernetes Grid on an SDDC')
    enable_tkg_parser.add_argument('-e', '--egress-cidr', required=True, help='Address range reserved for SNATed outbound traffic from containers and guest clusters.')
    enable_tkg_parser.add_argument('-i', '--ingress-cidr', required=True, help='Address range allocated to receive inbound traffic through load balancers to containers.')
    enable_tkg_parser.add_argument('-n', '--namespace-cidr', required=True, help='Address range assigned to namespace segments.  Must be at least a /23.')
    enable_tkg_parser.add_argument('-s', '--service-cidr', required=True, help='Address range reserved for Tanzu supervisor services.')
    enable_tkg_parser.set_defaults(func=enable_tkg)

    disable_tkg_parser=tkg_parser_subs.add_parser('disable-tkg', parents=[auth_flag,vmc_url_flag, org_id_flag, sddc_id_parser_flag], help = 'Disable Tanzu Kubernetes Grid on an SDDC')
    disable_tkg_parser.set_defaults(func=disable_tkg)

# ============================
# NSX-T - Segments
# ============================

    """ Parent Parser for NSX Segment functions """
    parent_segment_parser = argparse.ArgumentParser(add_help=False)
    parent_segment_parser.add_argument("-n","--objectname", required=False, help= "The name or ID of the segment or T1.  May not include spaces or hypens.")
    parent_segment_parser.add_argument("-conn","--connectivity", choices=["ON", "OFF"], required=False, help= "Connectivity status for the segment.")
    parent_segment_parser.add_argument("-dhcpr","--dhcp-range", required=False, help= "If applicable, the DHCP range of IP addresses to be distributed.")
    parent_segment_parser.add_argument("-dn","--domain-name", required=False, help= "The domain name for the subnet - e.g. 'vmc.local'")
    parent_segment_parser.add_argument("-gw","--gateway", required=False, help= "The gateway and subnet of the network - e.g. '192.138.1.1/24'")
    parent_segment_parser.add_argument("-rt","--routing-type", choices=["ROUTED", "EXTENDED", "ROUTED_AND_EXTENDED", "DISCONNECTED"], type = str.upper, required=False, help= "Routing type - by default this is set to 'ROUTED'")
    parent_segment_parser.add_argument("-st","--segment-type", choices=["fixed","flexible"], default="flexible", required=False, help= "Determines if this this segment will be 'fixed' to the default CGW - by default this is 'flexible'")
    parent_segment_parser.add_argument("-t1id","--tier1-id", required=False, help= "If applicable, the ID of the Tier1 gateway the network should be connected to.")

    # create the parser for the "segment" command
    segment_parser = subparsers.add_parser('segment', help='Create, delete, update, and show Virtual Machine network segments.')
    # create a subparser for segment sub-commands
    segment_parser_subs = segment_parser.add_subparsers(help='segment sub-command help')

    # create individual parsers for each sub-command
    segment_create_parser = segment_parser_subs.add_parser("create", parents=[auth_flag,nsx_url_flag, parent_segment_parser], help = "Create a new virtual machine network segment.")
    segment_create_parser.set_defaults(func = new_segment)

    segment_delete_parser = segment_parser_subs.add_parser("delete", parents=[auth_flag,nsx_url_flag, parent_segment_parser], help = "Delete a virtual machine network segment.")
    segment_delete_parser.set_defaults(func = remove_segment)

    segment_show_parser = segment_parser_subs.add_parser("show", parents=[auth_flag,nsx_url_flag, parent_segment_parser], help = "Show the current virtual machine network segments.")
    segment_show_parser.set_defaults(func = getSDDCnetworks)

    segment_update_parser = segment_parser_subs.add_parser("update", parents=[auth_flag,nsx_url_flag, parent_segment_parser], help = "Update the configuration of a virtual machine network segment.")
    segment_update_parser.set_defaults(func = configure_segment)

    # vmnetgrp.add_argument("-xtid", "--ext-tunnel-id",required=False, help= "ID of the extended tunnel.")

# ============================
# NSX-T - VPN (SDDC and Tier-1)
# ============================
    parent_vpn_parser = argparse.ArgumentParser(add_help=False)

    # create the parser for the "vpn" command
    vpn_parser = subparsers.add_parser('vpn', help='Create, delete, update, and show virtual private network (VPN) settings.')
    # create a subparser for segment sub-commands
    vpn_parser_subs = vpn_parser.add_subparsers(help='vpn sub-command help')

    # create individual parsers for each sub-command
    new_ike_profile_parser = vpn_parser_subs.add_parser('new-ike-profile', parents=[auth_flag,nsx_url_flag, parent_vpn_parser], help='Create a new VPN IKE Profile')
    new_ike_profile_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_ike_profile_parser.add_argument('-i', '--ike-version', choices=['IKE_V1', 'IKE_V2', 'IKE_FLEX'], default='IKE_V2', required=True, type=str.upper, help='IKE version for this profile. Default is IKE-V2')
    new_ike_profile_parser.add_argument('-dh', '--dh-group', choices=['GROUP2', 'GROUP5', 'GROUP14', 'GROUP15', 'GROUP16', 'GROUP19', 'GROUP20', 'GROUP21'], default='GROUP14', nargs='+', required=True, type=str.upper, help='The Diffie-Hellman Group for this IKE Profile.  Multiple DH Groups can be selected per profile.  Default is DH14.')
    new_ike_profile_parser.add_argument('-a', '--digest-algo', choices=['SHA1', 'SHA2_256', 'SHA2_384', 'SHA2_512'], nargs='+', type=str.upper, help='IKE digest algorithm.Default is SHA2-256')
    new_ike_profile_parser.add_argument('-e', '--encrypt-algo', choices=['AES_128', 'AES_256', 'AES_GCM_128', 'AES_GCM_192', 'AES_GCM_256'], default='AES_256', required=True, nargs='+', type=str.upper, help='IKE encryption algorithm. Default is AES-256. If any GCM algorithm is chosen, IKE V2 is required.')
    new_ike_profile_parser.set_defaults(func=new_sddc_ipsec_vpn_ike_profile)

    new_ipsec_profile_parser = vpn_parser_subs.add_parser('new-ipsec-profile', parents=[auth_flag,nsx_url_flag, parent_vpn_parser], help='Create a new VPN IPSEC Tunnel Profile')
    new_ipsec_profile_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_ipsec_profile_parser.add_argument('-dh', '--dh-group', choices=['GROUP2', 'GROUP5', 'GROUP14', 'GROUP15', 'GROUP16', 'GROUP19', 'GROUP20', 'GROUP21'], default='GROUP14', nargs='+', required=True, type=str.upper, help='The Diffie-Hellman Group for this IKE Profile.  Multiple DH Groups can be selected per profile.  Default is DH14.')
    new_ipsec_profile_parser.add_argument('-e', '--encrypt-algo', choices=['AES_128', 'AES_256', 'AES_GCM_128', 'AES_GCM_192', 'AES_GCM_256', 'NO_ENCRYPTION_AUTH_AES_GMAC_128', 'NO_ENCRYPTION_AUTH_AES_GMAC_192', 'NO_ENCRYPTION_AUTH_AES_GMAC_256', 'NO_ENCRYPTION'], default='AES_256', required=True, nargs='+', type=str.upper, help='IPSEC Encryption Algorithm options. Default is AES-256')
    new_ipsec_profile_parser.add_argument('-a', '--digest-algo', choices=['SHA1', 'SHA2_256', 'SHA2_384', 'SHA2_512'], nargs='+', type=str.upper, help='IPSec Digest Algorithm.')
    new_ipsec_profile_parser.add_argument('-p', '--pfs-disable', action='store_false', help='Disable perfect forward secrecy')
    new_ipsec_profile_parser.set_defaults(func=new_sddc_ipsec_vpn_tunnel_profile)

    new_dpd_profile_parser = vpn_parser_subs.add_parser('new-dpd-profile', parents=[auth_flag,nsx_url_flag, parent_vpn_parser], help='Create a new IPSEC DPD profile')
    new_dpd_profile_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_dpd_profile_parser.add_argument('-m', '--probe-mode', choices=['PERIODIC', 'ON-DEMAND'], default='PERIODIC', type=str.upper, required=True, help='DPD Probe Mode is used to query the liveliness of the peer.')
    new_dpd_profile_parser.add_argument('-i', '--interval', type=int, help='DPD Probe interval defines an interval for DPD probes (in seconds).  Default for periodic is 60s and On-Demand is 10s.')
    new_dpd_profile_parser.add_argument('-d', '--disable', action='store_false', help='Disable dead peer detection')
    new_dpd_profile_parser.add_argument('-r', '--retry-count', type=int, help='Maximum number of DPD message retry attemptes')
    new_dpd_profile_parser.set_defaults(func=new_sddc_ipsec_vpn_dpd_profile)

    new_t1_vpn_service_parser = vpn_parser_subs.add_parser('new-t1-vpn-service', parents=[auth_flag,nsx_url_flag, parent_vpn_parser], help='Create a new Tier-1 gateway VPN service')
    new_t1_vpn_service_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_t1_vpn_service_parser.add_argument('-t1', '--tier1-gateway', required=True, help='Select which Tier-1 gateway this VPN service should be attached to')
    new_t1_vpn_service_parser.add_argument('-s', '--service-type', required=True, choices=['ipsec', 'l2vpn'], help='Select whether this service is for an IPSec VPN or L2VPN')
    new_t1_vpn_service_parser.set_defaults(func=new_t1_vpn_service)

    new_local_endpoint_parser = vpn_parser_subs.add_parser('new-local-endpoint', parents=[auth_flag,nsx_url_flag, parent_vpn_parser], help='Create a new Tier-1 VPN local endpoint')
    new_local_endpoint_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_local_endpoint_parser.add_argument('-t', '--tier1-gateway', required=True, help='Select which Tier-1 gateway this Local Endpoint is associated with')
    new_local_endpoint_parser.add_argument('-s', '--vpn-service', required=True, help='Select which VPN service this Local Endpoint will be associated with')
    new_local_endpoint_parser.add_argument('-l', '--local-address', required=True, help='Define the local IPv4 address for the Local Endpoint')
    new_local_endpoint_parser.set_defaults(func=new_t1_local_endpoint)

    new_t1_ipsec_session_parser = vpn_parser_subs.add_parser('new-t1-ipsec-session', parents=[auth_flag,nsx_url_flag, parent_vpn_parser], help='Create a new Tier-1 gateway VPN session')
    new_t1_ipsec_session_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_t1_ipsec_session_parser.add_argument('-v', '--vpn-type', choices=['route-based', 'policy-based'], required=True, help='Define whether this will be a route-based (BGP) VPN or a policy-based (static) VPN. If a route-based VPN, you must also define "-b" and "-s".')
    new_t1_ipsec_session_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='Define which Tier-1 Gateway this ')
    new_t1_ipsec_session_parser.add_argument('-vs', '--vpn-service', required=True, help='Define the VPN service to which this session should be attached')
    new_t1_ipsec_session_parser.add_argument('-d', '--dpd-profile', required=True, help='Provide the name of the DPD profile to use with this IPSEC VPN')
    new_t1_ipsec_session_parser.add_argument('-i', '--ike-profile', required=True, help='Provide the name of the IKE profile to use with this IPSEC VPN')
    new_t1_ipsec_session_parser.add_argument('-t', '--tunnel-profile', required=True, help='Provide the IPSEC Tunnel Profile to use with this IPSEC VPN')
    new_t1_ipsec_session_parser.add_argument('-l', '--local-endpoint', required=True, help='Provide the name of the Local Endpoint to use with this IPSEC VPN')
    new_t1_ipsec_session_parser.add_argument('-r', '--remote-address', required=True, help='Provide the IPv4 address for the remote site')
    new_t1_ipsec_session_parser.add_argument('-p', '--psk', required=True, help='Define the pre-shared key for the IPSEC VPN session')
    new_t1_ipsec_session_parser.add_argument('-b', '--bgp-ip-address', nargs='+', help='Define the BGP IPV4 interface. Route-based VPN only')
    new_t1_ipsec_session_parser.add_argument('-s', '--bgp-subnet-prefix', help='Define the BGP subnet prefix length. Route-based VPN only')
    new_t1_ipsec_session_parser.add_argument('-dest', '--destination-addr', nargs='+', help='Define the destination subnets for the VPN.  Must be in IPV4 CIDR format.  Multiple entries supported with spaces inbetween.  Policy-based VPN only')
    new_t1_ipsec_session_parser.add_argument('-src', '--source-addr', nargs='+', help='Define the source subnets for the VPN.  Must be in IPV4 CIDR format.  Multiple entries supported with spaces inbetween.  Policy-based VPN only')
    new_t1_ipsec_session_parser.set_defaults(func=new_t1_ipsec_session)

    new_t1_l2vpn_session_parser = vpn_parser_subs.add_parser('new-t1-l2vpn-session', parents=[nsx_url_flag, parent_vpn_parser], help='Create a new Tier-1 gateay L2VPN session')
    new_t1_l2vpn_session_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_t1_l2vpn_session_parser.add_argument('-vs', '--vpn-service', required=True, help='Define the IPSec VPN Service')
    new_t1_l2vpn_session_parser.add_argument('-ls', '--l2vpn-service', required=True, help='Define the L2VPN Service')
    new_t1_l2vpn_session_parser.add_argument('-le', '--local-endpoint', required=True, help='Define the local endpoint for the L2VPN')
    new_t1_l2vpn_session_parser.add_argument('-r', '--remote-address', required=True, help='Provide the IPv4 address of the remote site')
    new_t1_l2vpn_session_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='The Tier-1 Gateway that this L2VPN is attached to')
    new_t1_l2vpn_session_parser.add_argument('-p', '--psk', required=True, help='The pre-shared key for the L2VPN session')
    new_t1_l2vpn_session_parser.add_argument('-t', '--tunnel-bgp-address', nargs='+', required=True, help='The tunnel interface for the L2VPN.  Entry must be a valid IPv4 address')
    new_t1_l2vpn_session_parser.add_argument('-s', '--tunnel-bgp-subnet', required=True, help='The BGP tunnel subnet for the L2VPN session.  Entry must be a valid CIDR mask')
    new_t1_l2vpn_session_parser.set_defaults(func=new_t1_l2vpn_session)

    new_sddc_ipsec_vpn_parser = vpn_parser_subs.add_parser('new-sddc-ipsec-vpn', parents=[nsx_url_flag, parent_vpn_parser], help='Create a new IPSEC VPN tunnel for the SDDC')
    new_sddc_ipsec_vpn_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_sddc_ipsec_vpn_parser.add_argument('-v', '--vpn-type', choices=['route-based', 'policy-based'], required=True, help='Define whether this will be a route-based (BGP) VPN or a policy-based (static) VPN. If a route-based VPN, you must also define "-b" and "-s".')
    new_sddc_ipsec_vpn_parser.add_argument('-r', '--remote-address', required=True, help='Provide the IPv4 address of the remote site')
    new_sddc_ipsec_vpn_parser.add_argument('-d', '--dpd-profile', required=True, help='Provide the name of the DPD profile to be used for this VPN tunnel')
    new_sddc_ipsec_vpn_parser.add_argument('-i', '--ike-profile', required=True, help='Provide the name of the IKE profile to be used for this VPN tunnel')
    new_sddc_ipsec_vpn_parser.add_argument('-t', '--tunnel-profile', required=True, help='Provide the name of the Tunnel profile to be used for this VPN tunnel')
    new_sddc_ipsec_vpn_parser.add_argument('-p', '--psk', required=True, help='Provide the pre-shared key for the IPSec VPN session')
    new_sddc_ipsec_vpn_parser.add_argument('-b', '--bgp-ip-address', nargs='+', help='Define the BGP IPV4 interface. Route-based VPN only')
    new_sddc_ipsec_vpn_parser.add_argument('-s', '--bgp-subnet-prefix', help='Define the BGP subnet prefix length. Route-based VPN only')
    new_sddc_ipsec_vpn_parser.add_argument('-dest', '--destination-addr', nargs='+', help='Define the destination subnets for the VPN.  Must be in IPV4 CIDR format.  Multiple entries supported with spaces inbetween.  Policy-based VPN only')
    new_sddc_ipsec_vpn_parser.add_argument('-src', '--source-addr', nargs='+', help='Define the source subnets for the VPN.  Must be in IPV4 CIDR format.  Multiple entries supported with spaces inbetween.  Policy-based VPN only')
    new_sddc_ipsec_vpn_parser.set_defaults(func=new_sddc_ipsec_vpn)

    new_sddc_l2vpn_parser = vpn_parser_subs.add_parser('new-sddc-l2vpn', parents=[nsx_url_flag], help='create a new L2VPN for the SDDC')
    new_sddc_l2vpn_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    new_sddc_l2vpn_parser.add_argument('-r', '--remote-address', required=True, help='Provide the IPv4 address of the local site')
    new_sddc_l2vpn_parser.add_argument('-e', '--endpoint', choices=['Public-IP', 'Private-IP'], required=True, help='Choose between the Public IP endpoint and the Private IP endpoint')
    new_sddc_l2vpn_parser.set_defaults(func=new_sddc_l2vpn)

    remove_sddc_ipsec_vpn_parser = vpn_parser_subs.add_parser('remove-sddc-ipsec-vpn', parents=[nsx_url_flag], help='remove a SDDC IPSec VPN')
    remove_sddc_ipsec_vpn_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    remove_sddc_ipsec_vpn_parser.set_defaults(func=remove_sddc_ipsec_vpn)

    remove_sddc_l2vpn_parser = vpn_parser_subs.add_parser('remove-sddc-l2vpn', parents=[nsx_url_flag], help='remove a SDDC L2VPN')
    remove_sddc_l2vpn_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    remove_sddc_l2vpn_parser.set_defaults(func=remove_sddc_l2vpn)

    remove_tier1_vpn_parser = vpn_parser_subs.add_parser('remove-tier1-ipsec-vpn', parents=[nsx_url_flag], help='remove a Tier-1 IPSec VPN')
    remove_tier1_vpn_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    remove_tier1_vpn_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='The name of the Tier-1 gateway that the VPN is attached to')
    remove_tier1_vpn_parser.add_argument('-vs', '--vpn-service', required=True, help='The name of the VPN service the VPN is asscotiated with')
    remove_tier1_vpn_parser.set_defaults(func=remove_tier1_ipsec_vpn)

    remove_tier1_l2vpn_parser = vpn_parser_subs.add_parser('remove-tier1-l2vpn', parents=[nsx_url_flag], help='remove a Tier-1 L2VPN')
    remove_tier1_l2vpn_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    remove_tier1_l2vpn_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='The name of the Tier-1 gateway')
    remove_tier1_l2vpn_parser.add_argument('-vs', '--vpn-service', required=True, help='The name of the L2VPN service')
    remove_tier1_l2vpn_parser.set_defaults(func=remove_tier1_l2vpn)

    remove_tier1_vpn_local_endpoint_parser = vpn_parser_subs.add_parser('remove-t1-vpn-local-endpoint', parents=[nsx_url_flag], help='remove a Tier-1 Local Endpoint')
    remove_tier1_vpn_local_endpoint_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    remove_tier1_vpn_local_endpoint_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='The name of the Tier-1 gateway')
    remove_tier1_vpn_local_endpoint_parser.add_argument('-vs', '--vpn-service', required=True, help='The name of the IPSec service')
    remove_tier1_vpn_local_endpoint_parser.set_defaults(func=remove_tier1_vpn_local_endpoint)

    remove_tier1_vpn_service_parser = vpn_parser_subs.add_parser('remove-t1-vpn-service', parents=[nsx_url_flag], help='Remove a Tier-1 VPN Service')
    remove_tier1_vpn_service_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    remove_tier1_vpn_service_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='The name of the Tier-1 gateway')
    remove_tier1_vpn_service_parser.add_argument('-vt', '--vpn-type', choices=['ipsec', 'l2vpn'], type=str.lower, required=True, help='Chose the VPN service type, ipsec or l2vpn')
    remove_tier1_vpn_service_parser.set_defaults(func=remove_tier1_vpn_service)

    remove_vpn_profile_parser = vpn_parser_subs.add_parser('remove-vpn-profile', parents=[nsx_url_flag], help='remove a VPN IKE profile')
    remove_vpn_profile_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    remove_vpn_profile_parser.add_argument('-p', '--profile-type', choices=['ike', 'ipsec', 'dpd'], type=str.lower, required=True, help="Chose which type of profile you would like to remove.")
    remove_vpn_profile_parser.set_defaults(func=remove_vpn_profile)

    show_sddc_vpn_parser = vpn_parser_subs.add_parser('show-sddc-vpn', parents=[nsx_url_flag], help='show the SDDC VPNs')
    show_sddc_vpn_parser.set_defaults(func=show_sddc_ipsec_vpn)

    show_sddc_vpn_endpoint = vpn_parser_subs.add_parser('show-vpn-endpoints', parents=[nsx_url_flag], help='Show the SDDC VPN endpoints')
    show_sddc_vpn_endpoint.set_defaults(func=show_sddc_vpn_endpoints)

    show_sddc_l2vpn_parser = vpn_parser_subs.add_parser('show-sddc-l2vpn', parents=[nsx_url_flag], help='show the SDDC L2VPN')
    show_sddc_l2vpn_parser.set_defaults(func=show_sddc_l2vpn)

    show_vpn_ike_profile_parser = vpn_parser_subs.add_parser('show-vpn-ike-profiles', parents=[nsx_url_flag], help='show the VPN IKE profiles')
    show_vpn_ike_profile_parser.set_defaults(func=show_vpn_ike_profile)

    show_vpn_ipsec_profile_parser = vpn_parser_subs.add_parser('show-vpn-ipsec-profiles', parents=[nsx_url_flag], help='Show the VPN IPSec Tunnel Profiles')
    show_vpn_ipsec_profile_parser.set_defaults(func=show_sddc_ipsec_profile)

    show_vpn_dpd_profile_parser = vpn_parser_subs.add_parser('show-vpn-dpd-profiles', parents=[nsx_url_flag], help='Show the VPN DPD Profiles')
    show_vpn_dpd_profile_parser.set_defaults(func=show_sddc_dpd_profile)

    show_t1_vpn_services = vpn_parser_subs.add_parser('show-tier1-vpn-services', parents=[nsx_url_flag], help='Show Tier-1 VPN Services')
    show_t1_vpn_services.set_defaults(func=show_tier1_vpn_services)

    show_t1_vpn_local_endpoints = vpn_parser_subs.add_parser('show-tier1-vpn-local-endpoints', parents=[nsx_url_flag], help='Show Tier-1 Local Endpoints')
    show_t1_vpn_local_endpoints.set_defaults(func=show_tier1_vpn_le)

    show_t1_ipsec_vpn_parser = vpn_parser_subs.add_parser('show-tier1-vpn', parents=[nsx_url_flag], help='Show Tier-1 IPSec VPN sessions')
    show_t1_ipsec_vpn_parser.set_defaults(func=show_tier1_ipsec_vpn)

    show_t1_ipsec_vpn_details_parser = vpn_parser_subs.add_parser('show-tier1-vpn-details', parents=[nsx_url_flag], help='Show IPSec VPN details for a provided Tier1 VPN name')
    show_t1_ipsec_vpn_details_parser.add_argument('-n', '--display-name', required=True, help='The display name of the VPN object being configured')
    show_t1_ipsec_vpn_details_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='The name of the Tier-1 gateway')
    show_t1_ipsec_vpn_details_parser.add_argument('-vs', '--vpn-service', required=True, help='The name of the IPSec VPN service')
    show_t1_ipsec_vpn_details_parser.set_defaults(func=show_tier1_vpn_details)

    show_tier1_l2vpn_parser = vpn_parser_subs.add_parser('show-tier1-l2vpn', parents=[nsx_url_flag], help='Show Tier-1 L2VPN sessions')
    show_tier1_l2vpn_parser.set_defaults(func=show_tier1_l2vpn)

    show_tier1_l2vpn_details_parser = vpn_parser_subs.add_parser('show-tier1-l2vpn-details', parents=[nsx_url_flag], help='Show Tier-1 L2VPN Session Details')
    show_tier1_l2vpn_details_parser.add_argument('-n', '--display-name', required=True, help='The display name of the L2VPN object')
    show_tier1_l2vpn_details_parser.add_argument('-t1g', '--tier1-gateway', required=True, help='The name of the Tier-1 gateway the L2VPN is attached to')
    show_tier1_l2vpn_details_parser.add_argument('-vs', '--vpn-service', required=True, help='The name of the L2VPN service in use by the L2VPN session')
    show_tier1_l2vpn_details_parser.set_defaults(func=show_tier1_l2vpn_details)


# ============================
# NSX-T - Route-Based VPN Prefix Lists, Neighbors
# ============================

    # create the parser for the "rbvpn-prefix-list" command
    rbvpn_prefixlist_parser=vpn_parser_subs.add_parser('rbvpn-prefix-list', formatter_class=MyFormatter, help='Create and configure route-based VPN prefix lists.')
    # create a subparser for rbvpn-prefix-list sub-commands
    rbvpn_prefixlist_parser_subs = rbvpn_prefixlist_parser.add_subparsers(help='rbvpn-prefix-list sub-command help')

    # create individual parsers for each sub-command
    rbvpn_prefixlist_attach_parser = rbvpn_prefixlist_parser_subs.add_parser('attach', parents=[auth_flag,nsx_url_flag], formatter_class=MyFormatter, help = "Attach an existing prefix list to a BGP neighbor.")
    rbvpn_prefixlist_attach_parser.add_argument("-plid", "--prefix-list-id", help = "The ID of prefix list")
    rbvpn_prefixlist_attach_parser.add_argument("-nid", "--neighbor-id", required = True, help = "The ID of the neighbor to attach to.  Use 'pyVMC.py rbvpn-neighbors show' for a list of BGP neighbors.")
    rbvpn_prefixlist_attach_parser.add_argument("-rf", "--route-filter", choices = ["in","out"], type= str.lower, help = "Use to specify either in_route_filter or out_route_filter.")
    rbvpn_prefixlist_attach_parser.add_argument("-i", "--interactive", nargs = '?', default = False, const = True, help = "Used to specify interactive mode.  If not specified, pyVMC assumes scripted mode.")
    rbvpn_prefixlist_attach_parser.set_defaults(func = attachT0BGPprefixlist)

    rbvpn_prefixlist_create_parser = rbvpn_prefixlist_parser_subs.add_parser('create', parents=[auth_flag,nsx_url_flag], help = "Create a new prefix list for a route-based VPN.  NOTE: Interactive command - no arguments required.")
    rbvpn_prefixlist_create_parser.set_defaults(func = newBGPprefixlist)

    rbvpn_prefixlist_delete_parser = rbvpn_prefixlist_parser_subs.add_parser('delete', parents=[auth_flag,nsx_url_flag], help = "Delete a prefix list for a route-based VPN.")
    rbvpn_prefixlist_delete_parser.add_argument("-plid", "--prefix-list-id", required = True, help = "The ID of prefix list")
    rbvpn_prefixlist_delete_parser.set_defaults(func = delRBVPNprefixlist)

    rbvpn_prefixlist_detach_parser = rbvpn_prefixlist_parser_subs.add_parser('detach', parents=[auth_flag,nsx_url_flag], help = "Detach all prefix lists from a BGP neighbor.")
    rbvpn_prefixlist_detach_parser.add_argument("-nid", "--neighbor-id", required = True, help = "The ID of the neighbor from which to detach ALL prefix lists.  Use 'pyVMC.py rbvpn-neighbors show' for a list of BGP neighbors.")
    rbvpn_prefixlist_detach_parser.set_defaults(func = detachT0BGPprefixlists)

    rbvpn_prefixlist_export_parser = rbvpn_prefixlist_parser_subs.add_parser('export', parents=[auth_flag,nsx_url_flag], help = "Export an existing route-based VPN prefix list to a JSON file.")
    rbvpn_prefixlist_export_parser.add_argument("-plid", "--prefix-list-id", required = True, help = "The ID of prefix list")
    rbvpn_prefixlist_export_parser.set_defaults(func = exportRBVPNprefixlist)

    rbvpn_prefixlist_import_parser = rbvpn_prefixlist_parser_subs.add_parser('import', parents=[auth_flag,nsx_url_flag], help = "Import a JSON file as a route-based VPN prefix list (will overwrite an existing list of the same name).")
    rbvpn_prefixlist_import_parser.add_argument("-fn", "--filename", required = True, help = "The name of the file to import as a route-based VPN prefix list.  This must match the format of the json/sample-rbvpn-prefix-list.json file.")
    rbvpn_prefixlist_import_parser.add_argument("-plid", "--prefix-list-id", required = True, help = "The ID of prefix list")
    rbvpn_prefixlist_import_parser.set_defaults(func = importRBVPNprefixlist)

    rbvpn_prefixlist_show_parser = rbvpn_prefixlist_parser_subs.add_parser('show', parents=[auth_flag,nsx_url_flag], help = "Show list of available prefix lists for a route-based VPN.")
    rbvpn_prefixlist_show_parser.set_defaults(func = getSDDCT0PrefixLists)

    rbvpn_neighbors_parser=vpn_parser_subs.add_parser('rbvpn-neighbors' , help='Show and configure BGP Neighbors for route-based VPN.')
    rbvpn_neighbors_parser_subs = rbvpn_neighbors_parser.add_subparsers(help='rbvpn-neighbors sub-command help')

    rbvpn_neighbors_show_parser = rbvpn_neighbors_parser_subs.add_parser('show', parents=[auth_flag,nsx_url_flag], help = "Show current BGP neighbors for route-based VPNs..")
    rbvpn_neighbors_show_parser.set_defaults(func = getSDDCT0BGPneighbors)

# ============================
# NSX-T - NAT
# ============================
    parent_nat_parser = argparse.ArgumentParser(add_help=False)

    # create the parser for the "nat" command
    nat_parser_main=subparsers.add_parser('nat', help='Show and update Network Address Translation (NAT) rules.')
    # create a subparser for gwfw sub-commands
    nat_parser_subs = nat_parser_main.add_subparsers(help='nat sub-command help')

    # create individual parsers for each sub-command
    new_nat_rule_parser=nat_parser_subs.add_parser('new-nat-rule', parents=[auth_flag,nsx_url_flag], help = 'To create a new NAT rule')
    new_nat_rule_parser.add_argument('-n', '--objectname', required = True, help = "The name / ID of the NAT rule to create.")
    new_nat_rule_parser.add_argument('-a','--action', choices=["DNAT", "REFLEXIVE"], type = str.upper, nargs = '?', default = "REFLEXIVE", help = '''
    Destination NAT(DNAT) - translates the destination IP address of inbound packets so that packets are delivered to a target address into another network. DNAT is only supported when the logical router is running in active-standby mode.
    Reflexive NAT(REFLEXIVE - default) - all inbound traffic is translated, regardless of port.
    ''')
    new_nat_rule_parser.add_argument('-t1id','--tier1_id', nargs = '?', default = 'cgw', help = 'The ID of the Tier1 gateway to which to apply the NAT rule.  If not specified, default = "cgw"')   
    new_nat_rule_parser.add_argument('-pub','--public_ip', required = True, help = "The IP address or network on the 'external' network. For REFLEXIVE rules this will be used as the 'TRANSLATED' address.  For DNAT rules this will be used as the 'DESTINATION' address.")
    new_nat_rule_parser.add_argument('-priv','--private_ip', required = True, help = "The IP address or network on the 'internal' network. For REFLEXIVE rules this will be used as the 'SOURCE' address.  For DNAT rules this will be used as the 'TRANSLATED' address.")
    new_nat_rule_parser.add_argument('-svc','--service', help = "Represents the service on which the NAT rule will be applied. Use './pyVMC.py inventory show-services' for a list of available services.")
    new_nat_rule_parser.add_argument('-tp','--translated_port', help = "Single port number or range. Examples- Single port '8080', Range of ports '8090-8095'.  If there is a service configured in NAT rule, the translated_port will be realized on NSX Manager as the destination_port")
    new_nat_rule_parser.add_argument('-l','--logging', action = 'store_true', help = "Use to enable logging - default is False.")
    new_nat_rule_parser.add_argument('-d','--disabled', action = 'store_false', help = "Use to disable the rule - default is enabled.")
    new_nat_rule_parser.set_defaults(func = new_nat_rule)

    remove_nat_rule_parser=nat_parser_subs.add_parser('remove-nat-rule', parents=[auth_flag,nsx_url_flag], help = 'remove a NAT rule')
    remove_nat_rule_parser.add_argument('-n', '--objectname', required = True, help = "The name / ID of the NAT rule to delete.")
    remove_nat_rule_parser.add_argument('-t1id','--tier1_id', nargs = '?', default = 'cgw', help = 'The ID of the Tier1 gateway for the NAT rule.  If not specified, default = "cgw"')   
    remove_nat_rule_parser.set_defaults(func = delete_nat_rule)

    show_nat_parser=nat_parser_subs.add_parser('show-nat', parents=[auth_flag,nsx_url_flag], help = 'show the configured NAT rules')
    show_nat_parser.add_argument('-t1id','--tier1_id', nargs = '?', default = 'cgw', help = 'The ID of the Tier1 gateway to which to apply the NAT rule.  If not specified, default = "cgw"')
    show_nat_parser.set_defaults(func = get_nat_rules)

    show_nat_stats=nat_parser_subs.add_parser('show-nat-stats', parents=[auth_flag,nsx_url_flag], help = 'Show the statistics for a given NAT rule.')
    show_nat_stats.add_argument('-n', '--objectname', required = True, help = "The name / ID of the rule to show statistics for.")
    show_nat_stats.add_argument('-t1id','--tier1_id', nargs = '?', default = 'cgw', help = 'The ID of the Tier1 gateway to which to apply the NAT rule.  If not specified, default = "cgw"')
    show_nat_stats.set_defaults(func = get_nat_stats)

# ============================
# NSX-T - T1
# ============================

    # create the parser for the "t1" command
    t1_parser = subparsers.add_parser('t1', help='Create, delete, update, and show secondary T1 gateways.')
    # create a subparser for t1 sub-commands
    t1_parser_subs = t1_parser.add_subparsers(help='t1 sub-command help')

    # create individual parsers for each sub-command
    t1_create_parser = t1_parser_subs.add_parser("create", parents=[auth_flag,nsx_url_flag], help = "Create a new, secondary T1 gateway.")
    t1_create_parser.add_argument('-n', '--tier1-id', required=True, help='The name for the new Tier-1 gateway')
    t1_create_parser.add_argument('-t', '--tier1-type', required=True, choices=['ROUTED', 'ISOLATED', 'NATTED'], type= str.upper, help='The type of Tier-1 Gateway to create.  Choices are routed, isolated or natted.')
    t1_create_parser.set_defaults(func = t1_create)

    t1_delete_parser = t1_parser_subs.add_parser("delete", parents=[auth_flag,nsx_url_flag], help = "Delete a secondary T1 gateway.")
    t1_delete_parser.add_argument("-n","--tier1-id", required=True, help= "The name of the Tier1 gateway to remove.")
    t1_delete_parser.set_defaults(func = t1_remove)

    t1_update_parser = t1_parser_subs.add_parser("update", parents=[auth_flag,nsx_url_flag], help = "Update the configuration of a secondary T1 gateway.")
    t1_update_parser.add_argument("-n","--tier1-id", required=True, help= "The ID or name of the Tier1 gateway.")
    t1_update_parser.add_argument("-t", "--t1type", choices=["ROUTED", "ISOLATED", "NATTED"], type= str.upper, required=True, help= "Type of Tier1 router to create.")
    t1_update_parser.set_defaults(func = t1_configure)


# ============================
# VTC - VMware Transit Connect
# ============================

    #create a parent parser for VTC commands (several commands share parameters for AWS Account ID)
    # parent_vtc_parser = argparse.ArgumentParser(add_help=False)
    # parent_vtc_parser.add_argument('-aid', '--aws_account_id', required=True, help = "The ID of the AWS Account that owns the resource (DXGE / VPC, etc) you wish to configure.")

    # create the parser for the "vtc" command
    vtc_parser=subparsers.add_parser('vtc', formatter_class=MyFormatter, help='Commands related to VMware Transit Connect (VTC).')
    # create a subparser for csp sub-commands
    vtc_parser_subs = vtc_parser.add_subparsers(help='vtc sub-command help')

    get_task_status_parser = vtc_parser_subs.add_parser('get-task-status', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Get status of the current task.')
    get_task_status_parser.add_argument('-tid','--task_id', required=True, help="The ID of the task for which you would like the status.")
    get_task_status_parser.add_argument('-v','--verbose', action='store_false', help="Additional information printed during task.")
    get_task_status_parser.set_defaults(func = get_task_status)
# ============================
# VTC - AWS Operations
# ============================

    connect_aws_parser=vtc_parser_subs.add_parser('connect-aws', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Connect an vTGW to an AWS account')
    connect_aws_parser.add_argument('-aid', '--aws_account_id', required=True, help = "The ID of the AWS Account that owns the resource (DXGE / VPC, etc) you wish to configure.")
    connect_aws_parser.add_argument('-rid', '--region_id', required = True, help= "The AWS region the VPC is deployed in.  Examples - 'us-east-1', 'us-west-2'")
    connect_aws_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to attach to AWS.  Use 'get-group-info' for a list of SDDC Groups with IDs.")
    connect_aws_parser.set_defaults(func = connect_aws_account)

    disconnect_aws_parser=vtc_parser_subs.add_parser('disconnect-aws', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Disconnect a vTGW from an AWS account')
    disconnect_aws_parser.add_argument('-aid', '--aws_account_id', required=True, help = "The ID of the AWS Account that owns the resource (DXGE / VPC, etc) you wish to configure.")
    disconnect_aws_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to detach from AWS.  Use 'get-deployments' for a list of SDDC Groups with IDs.")
    disconnect_aws_parser.set_defaults(func = disconnect_aws_account)

# ============================
# VTC - DXGW Operations
# ============================

    attach_dxgw_parser=vtc_parser_subs.add_parser('attach-dxgw', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Attach a Direct Connect Gateway to a vTGW')
    attach_dxgw_parser.add_argument('-aid', '--aws_account_id', required=True, help = "The ID of the AWS Account that owns the resource (DXGE / VPC, etc) you wish to configure.")
    attach_dxgw_parser.add_argument('-did', '--dxgw_id',  required = True, help= "The AWS ID of the DXGW you wish to attach.")
    attach_dxgw_parser.add_argument('-rid', '--region_id', required = True, help= "The AWS region the DXGW is deployed in.  Examples - 'us-east-1', 'us-west-2'")
    attach_dxgw_parser.add_argument('-pl','--prefix_list', nargs='+', required = True, help= "A space-separated list of networks (e.g. 192.168.1.0/24) the SDDC advertises to DXGW and to on-prem.")
    attach_dxgw_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to attach to the Direct Connect Gateway.  Use 'get-deployments' for a list of SDDC Groups with IDs.")
    attach_dxgw_parser.set_defaults(func = attach_dxgw)

    detach_dxgw_parser=vtc_parser_subs.add_parser('detach-dxgw', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Detach a Direct Connect Gateway from a vTGW')
    detach_dxgw_parser.add_argument('-did', '--dxgw_id',  required = True, help= "The AWS ID of the DXGW you wish to detach.")
    detach_dxgw_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to detach from the Direct Connect Gateway.  Use 'get-deployments' for a list of SDDC Groups with IDs.")
    detach_dxgw_parser.set_defaults(func = detach_dxgw)

# ============================
# VTC - SDDC Operations
# ============================

    get_sddc_info_parser=vtc_parser_subs.add_parser('get-deployments', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Display a list of all SDDCs')
    get_sddc_info_parser.set_defaults(func = get_deployments)

    get_nsx_info_parser=vtc_parser_subs.add_parser('get-nsx-info', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Display NSX credentials and URLs')
    get_nsx_info_parser.add_argument('-d', '--deployment_id', required = True, help="The deployment ID of the SDDC you wish to get information for.  Use 'get-deployments' for a list and their IDs.")
    get_nsx_info_parser.set_defaults(func = get_nsx_info)

    attach_sddc_parser=vtc_parser_subs.add_parser('attach-sddc', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Attach an SDDC to a vTGW')
    attach_sddc_parser.add_argument('-sid', '--sddc_id', required=True, help = "The ID of the SDDC to attach to the group.  Use 'get-deployments' for a list of SDDCs with IDs.")
    attach_sddc_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to attach to.  Use 'get-group-info' for a list of SDDCs Groups with IDs.")
    attach_sddc_parser.set_defaults(func = attach_sddc)

    detach_sddc_parser=vtc_parser_subs.add_parser('detach-sddc', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Detach an SDDC from a vTGW')
    detach_sddc_parser.add_argument('-sid', '--sddc_id', required=True, help = "The ID of the SDDC to attach to the group.  Use 'get-deployments' for a list of SDDCs with IDs.")
    detach_sddc_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to detach from.  Use 'get-group-info' for a list of SDDCs Groups with IDs.")
    detach_sddc_parser.set_defaults(func = detach_sddc)

# ============================
# VTC - SDDC-Group Operations
# ============================

    create_sddc_group_parser=vtc_parser_subs.add_parser('create-sddc-group', parents = [auth_flag, vmc_url_flag,org_id_flag,sddc_id_parser_flag], help = 'Create an SDDC group')
    create_sddc_group_parser.add_argument("-n","--name", required=True, help= "The Name for the SDDC Group")
    create_sddc_group_parser.add_argument("-desc","--description", help= "The Description for the SDDC Group. please make sure to enclose this in quotes if your description has spaces in it")
    create_sddc_group_parser.add_argument("-d","--deployment_groups", nargs='*', default=[], help="Pass in the deployment IDs to be added to the cluster. Use 0-n times.")
    create_sddc_group_parser.add_argument("-nowait","--dont-wait", action='store_true',required=False, help= "Don't wait on the result. Show the task ID")
    create_sddc_group_parser.add_argument("-v","--verbose", action='store_true', required=False, help= "Show verbose output")
    create_sddc_group_parser.set_defaults(func = create_sddc_group)

    delete_sddc_group_parser=vtc_parser_subs.add_parser('delete-sddc-group', parents = [auth_flag, vmc_url_flag,org_id_flag], help = 'Delete an SDDC group')
    delete_sddc_group_parser.add_argument("-gid", "--sddc_group_id",help="ID for the SDDC group to delete. Use 'get-group-info' to view a list of SDDC Groups and their IDs.")
    delete_sddc_group_parser.set_defaults(func = delete_sddc_group)
    
    sddc_group_info_parser=vtc_parser_subs.add_parser('get-group-info', parents = [auth_flag, vmc_url_flag,org_id_flag], help = 'Display details for an SDDC group')
    sddc_group_info_parser.set_defaults(func = get_sddc_groups)


# ============================
# VTC - VPC Operations
# ============================

    attach_vpc_parser=vtc_parser_subs.add_parser('attach-vpc', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Attach a VPC to a vTGW')
    attach_vpc_parser.add_argument('-aid', '--aws_account_id', required=True, help = "The ID of the AWS Account that owns the resource (DXGE / VPC, etc) you wish to configure.")
    attach_vpc_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to attach to.  Use 'get-group-info' for a list of SDDCs Groups with IDs.")
    attach_vpc_parser.set_defaults(func = attach_vpc)

    detach_vpc_parser=vtc_parser_subs.add_parser('detach-vpc', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Detach VPC from a vTGW')
    detach_vpc_parser.add_argument('-aid', '--aws_account_id', required=True, help = "The ID of the AWS Account that owns the resource (DXGE / VPC, etc) you wish to configure.")
    detach_vpc_parser.add_argument('-gid', '--sddc_group_id', required=True, help = "The ID of the SDDC Group to attach to.  Use 'get-group-info' for a list of SDDCs Groups with IDs.")
    detach_vpc_parser.set_defaults(func = detach_vpc)

    vpc_prefixes_parser=vtc_parser_subs.add_parser('vpc-prefixes', parents=[auth_flag,vmc_url_flag,org_id_flag], help = 'Add or remove static routes to your vTGW.')
    vpc_prefixes_parser.add_argument('-aid', '--aws_account_id', required=True, help = "The ID of the AWS Account that owns the resource (DXGE / VPC, etc) you wish to configure.")
    vpc_prefixes_parser.add_argument("-gid", "--sddc_group_id", required = True, help="ID for the SDDC group to add prefixes to. Use 'get-group-info' to view a list of SDDC groups and their IDs.")
    vpc_prefixes_parser.set_defaults(func = add_vpc_prefixes)


# ============================
# VTC - TGW Operations
# ============================

    # attach_tgw_parser=vtc_parser_subs.add_parser('attach-tgw', parents=[auth_flag, vmc_flag, org_id_flag], help='Attach external TGW to vTGW')
    # attach_tgw_parser.add_argument('-t', '--tgw_id', required=True, help='The transit gateway ID the vTC will be peered with')
    # attach_tgw_parser.add_argument('-a', '--aws_id', required=True, help='The AWS Account ID that owns the transit gateway')
    # attach_tgw_parser.add_argument('-s', '--source_region', required=True, help='The AWS region the vTGW is located')
    # attach_tgw_parser.add_argument('-d', '--dest_region', required=True, help='The AWS region where the customer TGW is located')
    # attach_tgw_parser.add_argument('-c', '--cidr', required=True, nargs=+, help='CIDR ranges that are permitted to communicate over the attachment.  Enter one of more complete CIDR range')
    # attach_tgw_parser.set_defaults(func=attach_tgw)


# ============================
# NSX-T - Firewall - Gateway
# ============================
    # create the parser for the "gwfw" command
    gwfw_parser_main=subparsers.add_parser('gwfw', help='Show and update policies and rules associated with NSX Gateway Firewall (mgw, cgw, etc.).')
    # create a subparser for gwfw sub-commands
    gwfw_parser_subs = gwfw_parser_main.add_subparsers(help='gwfw sub-command help')

    # create individual parsers for each sub-command

    new_cgw_rule_parser=gwfw_parser_subs.add_parser('new-cgw-rule', parents=[auth_flag,nsx_url_flag], formatter_class=argparse.RawTextHelpFormatter, help = "Create a new CGW security rule.  When specifying source or destination groups, note you may specify multiple simply by listing them, separated by spaces.")
    new_cgw_rule_parser.add_argument("-name", "--display_name", required= True, help = "The name of the rule")
    new_cgw_rule_parser.add_argument("--services", required= True, nargs = '+', help = "The service(s) to configure for the firewall rule.  You may specify multiple simply by listing them, separated by spaces.")
    new_cgw_rule_parser.add_argument("--action", choices= ["ALLOW", "DROP", "REJECT"], type= str.upper, required = True, help = "Choose the action to define for the rule.")
    new_cgw_rule_parser.add_argument("--sequence", default= "0", required = False, help = "The sequence number for rule processing. (Optional)")
    new_cgw_rule_parser.add_argument("--scope", choices = ["all", "public", "direct-connect", "cross-vpc", "vpn"], nargs='+', required= True,  help = "The interface(s) in the SDDC to apply the rule to. You may select more than one by simply adding them separated by spaces.")
    new_cgw_rule_parser.add_argument("--source", required= True, nargs = '+', help = '''
    The source group(s) for the Compute Gateway firewall rule.  When specifying source groups, note you may specify multiple simply by listing them, separated by spaces.
    This value may be one or more of the (case sensitive) predefined groups on the VMC Tier 0:
        connected_vpc
        directConnect_prefixes
        s3_prefixes
        deployment_group_dgw_prefixes
        deployment_group_tgw_prefixes
        deployment_group_vpc_prefixes
        deployment_group_sddc_prefixes
        
    ... or a custom defined group.  If you choose to use custom groups, be sure to specify the correct group ID.
    Use './pyVMC.py inventory show-group cgw' or to display currently configured groups for the Compute Gateway.
    '''
    )
    new_cgw_rule_parser.add_argument("--dest", required= True, nargs = '+', help = '''
    The destination group(s) for the Compute Gateway firewall rule.  When specifying destination groups, note you may specify multiple simply by listing them, separated by spaces.
    This value may be one or more of the (case sensitive) predefined groups on the VMC Tier 0:
        connected_vpc
        directConnect_prefixes
        s3_prefixes
        deployment_group_dgw_prefixes
        deployment_group_tgw_prefixes
        deployment_group_vpc_prefixes
        deployment_group_sddc_prefixes
        
    ... or a custom defined group.  If you choose to use custom groups, be sure to specify the correct group ID.
    Use './pyVMC.py inventory show-group cgw' to display currently configured groups for the Compute Gateway.
    '''
    )
    new_cgw_rule_parser.set_defaults(func = newSDDCCGWRule)

    new_mgw_rule_parser=gwfw_parser_subs.add_parser('new-mgw-rule', parents=[auth_flag,nsx_url_flag], help = 'Create a new MGW security rule.')
    new_mgw_rule_parser.add_argument("-name", "--display_name", required= True, help = "The name of the rule")
    new_mgw_rule_parser.add_argument("--services", required= True, nargs = '+', help = "The service(s) to configure for the firewall rule.  You may specify multiple simply by listing them, separated by spaces.")
    new_mgw_rule_parser.add_argument("--action", choices= ["ALLOW", "DROP", "REJECT"], type= str.upper, required = True, help = "Choose the action to define for the rule.")
    new_mgw_rule_parser.add_argument("--sequence", default= "0", required = False, help = "The sequence number for rule processing. (Optional)")
    new_mgw_rule_parser.add_argument("--source", required= True, nargs = '+', help = '''
    The source group(s) for the Management Gateway firewall rule.  When specifying source groups, note you may specify multiple simply by listing them, separated by spaces.
    This value may be one or more of the (case sensitive) predefined "Management" groups for the SDDC:
        ESXI
        HCX
        VCENTER
        NSX-MANAGER
    ... or a custom defined group.  If you choose to use custom groups, be sure to specify the correct group ID.
    Use './pyVMC.py inventory show-group mgw' to display currently configured groups for the Management Gateway.
    '''
    )
    new_mgw_rule_parser.add_argument("--dest", required= True, nargs = '+', help = '''
    The destination group(s) for the Management Gateway firewall rule.  When specifying destination groups, note you may ONLY ONE (case sensitive) predefined Management Group, as follows:
        ESXI
        HCX
        VCENTER
        NSX-MANAGER
    Based on your SDDC configuration and services, there may be additional groups.  Use './pyVMC.py inventory show-group cgw' to display currently configured groups for the Compute Gateway.
    '''
    )
    new_mgw_rule_parser.set_defaults(func = newSDDCMGWRule)

    remove_cgw_rule_parser=gwfw_parser_subs.add_parser('remove-cgw-rule', parents=[auth_flag,nsx_url_flag], help = 'delete a CGW security rule')
    remove_cgw_rule_parser.add_argument("rule_id", help = "The ID of the rule you wish to delete.  Use './pyVMC.py gwfw show-cgw-rule for a list.")
    remove_cgw_rule_parser.set_defaults(func = removeSDDCCGWRule)

    remove_mgw_rule_parser=gwfw_parser_subs.add_parser('remove-mgw-rule', parents=[auth_flag,nsx_url_flag], help = 'delete a MGW security rule')
    remove_mgw_rule_parser.add_argument("rule_id", help = "The ID of the rule you wish to delete.  Use './pyVMC.py gwfw show-mgw-rule for a list.")
    remove_mgw_rule_parser.set_defaults(func = removeSDDCMGWRule)

    show_cgw_rule_parser=gwfw_parser_subs.add_parser('show-cgw-rule', parents=[auth_flag,nsx_url_flag], help = 'show the CGW security rules')
    show_cgw_rule_parser.set_defaults(func = getSDDCCGWRule)

    show_mgw_rule_parser=gwfw_parser_subs.add_parser('show-mgw-rule', parents=[auth_flag,nsx_url_flag], help = 'show the MGW security rules')
    show_mgw_rule_parser.set_defaults(func= getSDDCMGWRule)

# ============================
# NSX-T - Firewall - Distributed
# ============================
    parent_dfw_parser = argparse.ArgumentParser(add_help=False)

    # create the parser for the "dfw" command
    dfw_parser_main=subparsers.add_parser('dfw', formatter_class=MyFormatter, help='Show and update policies and rules associated with NSX Distributed Firewall.')
    # create a subparser for gwfw sub-commands
    dfw_parser_subs = dfw_parser_main.add_subparsers(help='dfw sub-command help')

    # create individual parsers for each sub-command
    new_dfw_rule_parser=dfw_parser_subs.add_parser('new-dfw-rule', parents=[auth_flag,nsx_url_flag], help = 'create a new DFW security rule')
    new_dfw_rule_parser.add_argument("display_name", help = "The name of the rule")
    new_dfw_rule_parser.add_argument("--services", required= True, nargs = '+', help = "The service(s) to configure for the firewall rule.  You may specify multiple simply by listing them, separated by spaces.")
    new_dfw_rule_parser.add_argument("--action", choices= ["ALLOW", "DROP", "REJECT"], type= str.upper, required = True, help = "Choose the action to define for the rule.")
    new_dfw_rule_parser.add_argument("--sequence", default= "0", required = False, help = "The sequence number for rule processing.")
    new_dfw_rule_parser.add_argument("--section_id", required = True, help = "The section to addd the new rule to.  Use './pyVMC.py dfw show-dfw-section' for a list.")
    new_dfw_rule_parser.add_argument("--source", required= True, nargs = '+', help = '''
    The source group(s) for the DFW rule.  When specifying source groups, note you may specify multiple simply by listing them, separated by spaces.
    This value may be one or more of the (case sensitive) predefined groups on the VMC Tier 0:
        connected_vpc
        directConnect_prefixes
        s3_prefixes
        deployment_group_dgw_prefixes
        deployment_group_tgw_prefixes
        deployment_group_vpc_prefixes
        deployment_group_sddc_prefixes
        
    ... or a custom defined group.  If you choose to use custom groups, be sure to specify the correct group ID.
    Use './pyVMC.py inventory show-group cgw' or to display currently configured groups for the Compute Gateway.
    '''
    )
    new_dfw_rule_parser.add_argument("--dest", required= True, nargs = '+', help = '''
    The destination group(s) for the DFW rule.  When specifying destination groups, note you may specify multiple simply by listing them, separated by spaces.
    This value may be one or more of the (case sensitive) predefined groups on the VMC Tier 0:
        connected_vpc
        directConnect_prefixes
        s3_prefixes
        deployment_group_dgw_prefixes
        deployment_group_tgw_prefixes
        deployment_group_vpc_prefixes
        deployment_group_sddc_prefixes
        
    ... or a custom defined group.  If you choose to use custom groups, be sure to specify the correct group ID.
    Use './pyVMC.py inventory show-group cgw' to display currently configured groups for the Compute Gateway.
    '''
    )
    new_dfw_rule_parser.set_defaults(func = newSDDCDFWRule)

    new_dfw_section_parser=dfw_parser_subs.add_parser('new-dfw-section', parents=[auth_flag,nsx_url_flag], help = 'create a new DFW section')
    new_dfw_section_parser.add_argument("display_name", help = "The name of the section you wish to create.")
    new_dfw_section_parser.add_argument("--category", choices= ["Ethernet","Emergency", "Infrastructure", "Environment","Application"], required= False, help ='''
    Policy framework provides five pre-defined categories for classifying a security policy. They are "Ethernet","Emergency", "Infrastructure", "Environment" and "Application". 
    There is a pre-determined order in which the policy framework manages the priority of these security policies. Ethernet category is for supporting layer 2 firewall rules.
    The other four categories are applicable for layer 3 rules. Amongst them, the Emergency category has the highest priority followed by Infrastructure, Environment and then Application rules. 
    Administrator can choose to categorize a security policy into the above categories or can choose to leave it empty. If empty it will have the least precedence w.r.t the above four categories.
    '''
    )
    new_dfw_section_parser.set_defaults(func = newSDDCDFWSection)

    remove_dfw_rule_parser=dfw_parser_subs.add_parser('remove-dfw-rule', parents=[auth_flag,nsx_url_flag], help = 'delete a DFW rule')
    remove_dfw_rule_parser.add_argument('section_id', help = "The section ID containing the rule you wish to delete.  Use './pyVMC.py dfw show-dfw-section' for a list.")
    remove_dfw_rule_parser.add_argument('rule_id', help = "The ID of the rule you wish to delete.  Use './pyVMC.py dfw show-dfw-section-rules' for a list.")
    remove_dfw_rule_parser.set_defaults(func = removeSDDCDFWRule)

    remove_dfw_section_parser=dfw_parser_subs.add_parser('remove-dfw-section', parents=[auth_flag,nsx_url_flag], help = 'delete a DFW section')
    remove_dfw_section_parser.add_argument('section_id', help = "The name of the section you wish to remove.  Use './pyVMC.py dfw show-dfw-section' for a list.")
    remove_dfw_section_parser.set_defaults(func = removeSDDCDFWSection)

    show_dfw_section_parser=dfw_parser_subs.add_parser('show-dfw-section', parents=[auth_flag,nsx_url_flag], help = 'show the DFW sections')
    show_dfw_section_parser.set_defaults(func = getSDDCDFWSection)

    show_dfw_section_rules_parser=dfw_parser_subs.add_parser('show-dfw-section-rules', parents=[auth_flag,nsx_url_flag], help = 'show the DFW security rules within a section')
    show_dfw_section_rules_parser.add_argument('section_id', help = "The name of the section you wish to retrieve.  Use './pyVMC.py dfw show-dfw-section' for a list.")
    show_dfw_section_rules_parser.set_defaults(func = getSDDCDFWRule)


# ============================
# NSX-T - Advanced Firewall
# ============================
 
    # create the parser for the "nsxaf" command
    nsxaf_parser=subparsers.add_parser('nsxaf' , formatter_class=MyFormatter, help='Commands related to the NSX Advanced Firewall - e.g. IDS.')
    # create a subparser for nsxaf sub-commands
    nsxaf_parser_subs = nsxaf_parser.add_subparsers(help='nsxaf sub-command help')

    show_ids_cluster_status_parser=nsxaf_parser_subs.add_parser('show-ids-cluster-status', parents=[auth_flag,nsx_url_flag], help = 'Show IDS status for each cluster in the SDDC')
    show_ids_cluster_status_parser.set_defaults(func = getNsxIdsEnabledClusters)
    
    enable_cluster_ids_parser=nsxaf_parser_subs.add_parser('enable-cluster-ids', parents=[auth_flag,nsx_url_flag], help = 'Enable IDS on cluster')
    enable_cluster_ids_parser.add_argument('cluster_id', help = "The ID of the cluster to enable with Advanced Firewall capabilities.")
    enable_cluster_ids_parser.set_defaults(func = enableNsxIdsCluster)
    
    disable_cluster_ids_parser=nsxaf_parser_subs.add_parser('disable-cluster-ids', parents=[auth_flag,nsx_url_flag], help = 'Disable IDS on cluster')
    disable_cluster_ids_parser.add_argument('cluster_id', help = "The ID of the cluster to enable with Advanced Firewall capabilities.")
    disable_cluster_ids_parser.set_defaults(func = disableNsxIdsCluster)
    
    enable_all_cluster_ids_parser=nsxaf_parser_subs.add_parser('enable-all-cluster-ids', parents=[auth_flag,nsx_url_flag], help = 'Enable IDS on all clusters')
    enable_all_cluster_ids_parser.set_defaults(func = enableNsxIdsAll)
    
    disable_all_cluster_ids_parser=nsxaf_parser_subs.add_parser('disable-all-cluster-ids', parents=[auth_flag,nsx_url_flag], help = 'Disable IDS on all clusters')
    disable_all_cluster_ids_parser.set_defaults(func = disableNsxIdsAll)
    
    enable_ids_auto_update_parser=nsxaf_parser_subs.add_parser('enable-ids-auto-update', parents=[auth_flag,nsx_url_flag], help = 'Enable IDS signature auto update')
    enable_ids_auto_update_parser.set_defaults(func = enableNsxIdsAutoUpdate)
    
    ids_update_signatures_parser=nsxaf_parser_subs.add_parser('ids-update-signatures', parents=[auth_flag,nsx_url_flag], help = 'Force update of IDS signatures')
    ids_update_signatures_parser.set_defaults(func = NsxIdsUpdateSignatures)
    
    show_ids_signature_versions_parser=nsxaf_parser_subs.add_parser('show-ids-signature-versions', parents=[auth_flag,nsx_url_flag], help = 'Show downloaded signature versions')
    show_ids_signature_versions_parser.set_defaults(func = getNsxIdsSigVersions)
    
    show_ids_profiles_parser=nsxaf_parser_subs.add_parser('show-ids-profiles', parents=[auth_flag,nsx_url_flag], help = 'Show all IDS profiles')
    show_ids_profiles_parser.set_defaults(func = getIdsProfiles)
    
    search_product_affected_parser=nsxaf_parser_subs.add_parser('search-product-affected', parents=[auth_flag,nsx_url_flag], help = 'Search through the active IDS signature for specific product affected. Useful when building an IDS Profile')
    search_product_affected_parser.set_defaults(func = search_ids_signatures_product_affected)
    
    create_ids_profile_parser=nsxaf_parser_subs.add_parser('create-ids-profile', parents=[auth_flag,nsx_url_flag], help = 'Create an IDS profile with either Product Affected, CVSS or both.')
    create_ids_profile_parser.add_argument("objectname", help = "The name of the profile to create.")
    create_ids_profile_parser.add_argument("-pa", "--product_affected", required=False, nargs='+', help="This is the product affected for the IDS Profile.  To determine the product affected syntax, use the 'search-product-affected' function.")
    create_ids_profile_parser.add_argument("--cvss", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], required=False, nargs='+', help="Choose a CVSS category to limit your IDS profile")
    create_ids_profile_parser.set_defaults(func = create_ids_profile)

    delete_ids_profile_parser=nsxaf_parser_subs.add_parser('delete-ids-profile', parents=[auth_flag,nsx_url_flag], help = 'Delete the specified IDS profile.')
    delete_ids_profile_parser.add_argument("objectname", help = "The name of the profile to delete.")
    delete_ids_profile_parser.set_defaults(func = delete_ids_profile)

    show_ids_policies_parser=nsxaf_parser_subs.add_parser('show-ids-policies', parents=[auth_flag,nsx_url_flag], help = 'List all IDS policies')
    show_ids_policies_parser.set_defaults(func = listIdsPolicies)

    create_ids_policy_parser=nsxaf_parser_subs.add_parser('create-ids-policy', parents=[auth_flag,nsx_url_flag], help = 'Create an IDS policy')
    create_ids_policy_parser.add_argument("objectname", help = "The name of the policy to create.")
    create_ids_policy_parser.set_defaults(func = create_ids_policy)

    delete_ids_policy_parser=nsxaf_parser_subs.add_parser('delete-ids-policy', parents=[auth_flag,nsx_url_flag], help = 'Delete the specified IDS policy.')
    delete_ids_policy_parser.add_argument("objectname", help = "The name of the policy to delete.")
    delete_ids_policy_parser.set_defaults(func = delete_ids_policy)

    show_ids_rules_parser=nsxaf_parser_subs.add_parser('show-ids-rules', parents=[auth_flag,nsx_url_flag], help = 'List all IDS rules')
    show_ids_rules_parser.set_defaults(func = get_ids_rules)

    create_ids_rule_parser=nsxaf_parser_subs.add_parser('create-ids-rule', parents=[auth_flag,nsx_url_flag], help = 'Create an IDS rule using previously created IDS profile and inventory groups')
    create_ids_rule_parser.add_argument("objectname", help = "The name of the rule to create.")
    create_ids_rule_parser.add_argument('ids_profile', help='The IDS Profile to evaluate against. Required argument.')
    create_ids_rule_parser.add_argument('ids_policy', help='The IDS Policy this rule will be created under. Required argument.')
    create_ids_rule_parser.add_argument("-act", "--action", required=False, choices=['DETECT', 'DETECT_PREVENT'], type = str.upper, default='DETECT', help="Choose whether this rule will just detect the intrusion or prevent the instrusion")
    create_ids_rule_parser.add_argument("-sg", "--source-group", required=False, default='ANY', nargs='*', help='Source inventory group; default is ANY, however source and destination may not both be ANY')
    create_ids_rule_parser.add_argument("-dg", "--dest-group", required=False, default='ANY', nargs='*', help='Destination inventory group; default is ANY, however source and destination may not both be ANY')
    create_ids_rule_parser.add_argument('-scp', '--scope', required=False, default='ANY', nargs='*', help='Determines where the IDS rule is applied.  Default is to apply across the entire DFW, but can be specific to a Inventory Group')
    create_ids_rule_parser.add_argument('-srv', '--services', required=False, default='ANY', nargs='*', help='Services this IDS rules is applied against.  Default is ANY.')
    create_ids_rule_parser.set_defaults(func = create_ids_rule)

    delete_ids_rule_parser=nsxaf_parser_subs.add_parser('delete-ids-rule', parents=[auth_flag,nsx_url_flag], help = 'Delete the specified IDS rule.')
    delete_ids_rule_parser.add_argument("objectname", help = "The name of the rule to delete.")
    delete_ids_rule_parser.add_argument('ids_policy', help='The IDS Policy this rule exists under. Required argument.')
    delete_ids_rule_parser.set_defaults(func = delete_ids_rule)


# ============================
# NSX-T - Inventory
# ============================
    # create the parser for the "inventory" command
    inventory_parser_main=subparsers.add_parser('inventory', help='Show and update objects in the NSX Inventory (groups, services, etc).')
    # create a subparser for gwfw sub-commands
    inventory_parser_subs = inventory_parser_main.add_subparsers(help='inventory sub-command help')

# ============================
# NSX-T - Inventory Groups
# ============================

    new_inv_group_parser=inventory_parser_subs.add_parser('new-inv-group', parents=[auth_flag,nsx_url_flag], help = 'create a new group')
    new_inv_group_parser.add_argument("gateway", choices= ["cgw", "mgw"], help= "The gateway domain for which the group will be defined.")
    new_inv_group_parser.add_argument("objectname", help= "The name of the inventory group to create. Use 'pyVMC.py inventory show-group' for a complete list.")
    new_inv_group_parser.add_argument("--type", choices=["ip-based", "member-based", "criteria-based", "group-based"], required = True, help = '''
    The type of membership to assign to the group: ip-based, member-based, criteria-based, or group-based.
    Note that in the current version, criteria-based membership is limited to VM attributes - "Name", "Tag", "OSName", "ComputerName."
    Also please note you may not use Tag-based criteria with "NOTEQUALS."
    '''
    )
    new_inv_group_parser.add_argument("--members", nargs = '+', help = '''
    A list of the members you would like added to the group.
    This may be a list of IP addresses, groups by ID, or virtual machines by NSX External ID.
    Use './pyVMC.py search-nsx VirtualMachine' for a table of virtual machines to choose from.
    ''')
    new_inv_group_parser.add_argument("--key", choices= ["Name", "Tag", "OSName", "ComputerName"], help = "Criteria filter for adding virtual machines.")
    new_inv_group_parser.add_argument("--operator", choices = ["EQUALS", "NOTEQUALS", "CONTAINS", "STARTSWITH", "ENDSWITH"], type = str.upper, help = "Operator used for criteria filters.")
    new_inv_group_parser.add_argument("--filter_value", help = "String containing the value to filter on for criteria-based membership.")
    new_inv_group_parser.set_defaults(func = new_inv_group)

    remove_inv_group_parser=inventory_parser_subs.add_parser('remove-inv-group', parents=[auth_flag,nsx_url_flag], help = 'remove a group')
    remove_inv_group_parser.add_argument("gateway", choices= ["cgw", "mgw"], help= "The gateway domain for which the group is defined.")
    remove_inv_group_parser.add_argument("objectname", help= "The name of the inventory group to delete. Use 'pyVMC.py inventory show-group' for a complete list.")
    remove_inv_group_parser.set_defaults(func = remove_inv_group)

    show_inv_group_parser=inventory_parser_subs.add_parser('show-inv-group', parents=[auth_flag,nsx_url_flag], help = 'show existing groups')
    show_inv_group_parser.add_argument("gateway", choices = ["cgw", "mgw", "both"], nargs = "?", default = "both", help = "Show the inventory groups associated with the MGW or CGW gateways.")
    show_inv_group_parser.add_argument("-n", "--objectname", help= "The name of the inventory group to retrieve details for. Use 'pyVMC.py inventory show-group' for a complete list.")
    show_inv_group_parser.set_defaults(func = get_inv_groups)

    show_inv_group_association_parser=inventory_parser_subs.add_parser('show-inv-group-association', parents=[auth_flag,nsx_url_flag], help = 'Show security rules used by a group')
    show_inv_group_association_parser.add_argument("gateway", choices = ["cgw", "mgw"], help = "Show the inventory groups associated with the MGW or CGW gateways.")
    show_inv_group_association_parser.add_argument("objectname", help= "The name of the inventory group to retrieve details for. Use 'pyVMC.py inventory show-group' for a complete list.")
    show_inv_group_association_parser.set_defaults(func = get_inv_group_assoc)

# ============================
# NSX-T - Inventory Services
# ============================

    # create individual parsers for each sub-command
    new_service_parser=inventory_parser_subs.add_parser('new-service', parents=[auth_flag,nsx_url_flag], help = 'create a new service')
    new_service_parser.add_argument("objectname", help = "The name of the inventory service to create.")
    new_service_parser.add_argument("-i", "--interactive", action='store_true', help = "Use to interactively define service entries and ports.  If not used, command expects additional arguments for service entries and ports.")
    new_service_parser.add_argument("-src", "--source_ports", nargs = '*', help = "Space separated list of source ports, or a range.. i.e. 22 25 26-27.")
    new_service_parser.add_argument("-dest", "--dest_ports",  nargs = '*', help = "Space separated list of source ports, or a range.. i.e. 22 25 26-27.")
    new_service_parser.add_argument("-l4p", "--l4_protocol", help = "Expected protocol (i.e. 'TCP', 'UDP', etc.")
    new_service_parser.set_defaults(func = newSDDCService)

    import_service_parser=inventory_parser_subs.add_parser('import-service', parents = [auth_flag,nsx_url_flag], help = 'Common 3rd party services that can be added to or removed from the services list of your SDDC. Default is to add, optional flag to delete')
    import_service_parser.add_argument("-l", "--list-providers", action = "store_true", help = "Display a list available providers for import - all other arguments are ignored if you use this argument")
    import_service_parser.add_argument("-p", "--provider-name", required=False, help = "Use the named provider - providers are JSON files located in imports folder. Default is to add services, optional flag to delete")
    import_service_parser.add_argument("-t", "--test-only", action = "store_true", help = "Displays a list of the provider's services - does not modify the SDDC configuration")
    import_service_parser.add_argument("-d", "--delete-mode", action = "store_true", help = "Changes to delete mode - the services in the provider's list will be deleted from the SDDC")
    import_service_parser.set_defaults(func = import_service)

    remove_service_parser=inventory_parser_subs.add_parser('remove-service', parents=[auth_flag,nsx_url_flag], help = 'remove a service')
    remove_service_parser.add_argument("objectname", help = "The ID of the inventory service to delete.  Use './pyVMC.py inventory show-services' for a list.")
    remove_service_parser.set_defaults(func = removeSDDCService)

    show_services_parser=inventory_parser_subs.add_parser('show-services', parents=[auth_flag,nsx_url_flag], help = 'show services')
    show_services_parser.add_argument("-n", "--objectname", help = "The ID of the inventory service to find, shows just the service entries for that one service.")
    show_services_parser.set_defaults(func = getSDDCService)    

# ============================
# NSX-T - System
# ============================
    # create the parser for the "system" command
    system_parser_main=subparsers.add_parser('system', help='Show and update configuration data associated with the NSX-T System (DNS, public IP, etc).')
    # create a subparser for gwfw sub-commands
    system_parser_subs = system_parser_main.add_subparsers(help='system sub-command help')    

# ============================
# NSX-T - DNS
# ============================

    # create parent parsers for DNS commands
    parent_dns_parser = argparse.ArgumentParser(add_help=False)
    parent_dns_parser.add_argument("-t1-scope", "--tier1-scope", choices=["CGW","MGW"], help= "Specify either CGW or MGW as the tier 1 gateway to apply to.")

    # create individual parsers for each sub-command
    show_dns_svc_parser=system_parser_subs.add_parser("show-dns-services", parents=[auth_flag,nsx_url_flag, parent_dns_parser], help="Show currently configured DNS services")
    show_dns_svc_parser.set_defaults(func=getSDDCDNS_Services)   # exra logic necessary to call correct function
    show_dns_zones_parser = system_parser_subs.add_parser('show-dns-zones', parents=[auth_flag,nsx_url_flag ,parent_dns_parser], help = "Show currently configured DNS zone services.")
    show_dns_zones_parser.set_defaults(func=getSDDCDNS_Zones)


# ============================
# NSX-T - Public IP Addressing
# ============================

    # create individual parsers for each sub-command
    new_sddc_public_ip_parser=system_parser_subs.add_parser('new-sddc-public-ip', parents=[auth_flag,nsx_url_flag], help = 'request a new public IP')
    new_sddc_public_ip_parser.add_argument("ip_id", help = "The name / description of the public IP address; spaces are not allowed.")
    new_sddc_public_ip_parser.set_defaults(func = newSDDCPublicIP)

    remove_sddc_public_ip_parser=system_parser_subs.add_parser('remove-sddc-public-ip', parents=[auth_flag,nsx_url_flag], help = 'remove an existing public IP')
    remove_sddc_public_ip_parser.add_argument("ip_id", help = "The name / description of the public IP address; spaces are not allowed.")
    remove_sddc_public_ip_parser.set_defaults(func = deleteSDDCPublicIP)

    set_sddc_public_ip_parser=system_parser_subs.add_parser('set-sddc-public-ip', parents=[auth_flag,nsx_url_flag], help = 'update the description of an existing public IP')
    set_sddc_public_ip_parser.add_argument("ip_id", help = "The current ID of the public IP address to update.  Use './pyVMC.py system show-sddc-public-ip to see a list.")
    set_sddc_public_ip_parser.add_argument("notes", help = "The NEW name / description of the public IP address to update; spaces are not allowed.")
    set_sddc_public_ip_parser.set_defaults(func = setSDDCPublicIP)

    show_sddc_public_ip_parser=system_parser_subs.add_parser('show-sddc-public-ip', parents=[auth_flag,nsx_url_flag], help = 'show the public IPs')
    show_sddc_public_ip_parser.set_defaults(func = getSDDCPublicIP)

# ============================
# NSX-T - MTU
# ============================

    # create the parser for the "mtu" command
    mtu_parser_main=system_parser_subs.add_parser('mtu', help='Show and update configuration data associated with Maximum Transmission Unit value for the Intranet Interface.')
    # create a subparser for bgp sub-commands
    mtu_parser_subs = mtu_parser_main.add_subparsers(help='mtu sub-command help')

    # create individual parsers for each sub-command
    mtu_show_parser = mtu_parser_subs.add_parser("show", parents=[auth_flag,nsx_url_flag], help = "Show the currently configured value for MTU on the Intranet Interface.")
    mtu_show_parser.set_defaults(func = getSDDCMTU)

    mtu_update_parser = mtu_parser_subs.add_parser("update", parents=[auth_flag,nsx_url_flag], help = "Update the configuration value for the MTU on the Intranet Interface.")
    mtu_update_parser.add_argument("mtu", help = "new MTU value for the Direct Connect / Intranet Interface.")
    mtu_update_parser.set_defaults(func = setSDDCMTU)

# ============================
# NSX-T - ASN
# ============================

    # create the parser for the "asn" command
    asn_parser_main=system_parser_subs.add_parser('asn', help='Show and update configuration data associated with Autonomous System Number value for the Intranet Interface.')
    # create a subparser for asn sub-commands
    asn_parser_subs = asn_parser_main.add_subparsers(help='asn sub-command help')

    # create individual parsers for each sub-command
    asn_show_parser = asn_parser_subs.add_parser("show", parents=[auth_flag,nsx_url_flag], help = "Show the currently configured value for ASN on the Intranet Interface.")
    asn_show_parser.set_defaults(func = getSDDCBGPAS)

    asn_update_parser = asn_parser_subs.add_parser("update", parents=[auth_flag,nsx_url_flag], help = "Update the configuration value for the ASN on the Intranet Interface.")
    asn_update_parser.add_argument("-asn", help = "new ASN value for the Direct Connect / Intranet Interface.")
    asn_update_parser.set_defaults(func = setSDDCBGPAS)

# ============================
# NSX-T - Route Preference - DX or VPN
# ============================

    # create the parser for the "dx-admin-cost" command
    dx_admin_cost=system_parser_subs.add_parser('dx-admin-cost', help='Use to view currently configured routing preference / admin cost - VPN or DX.')
    # create a subparser for asn sub-commands
    dx_admin_cost_parser_subs = dx_admin_cost.add_subparsers(help='admin cost sub-command help')

    # create individual parsers for each sub-command
    dx_admin_cost_show = dx_admin_cost_parser_subs.add_parser("show", parents=[auth_flag,nsx_url_flag], help = "Show currently configured routing preference / admin cost - VPN or DX.")
    dx_admin_cost_show.set_defaults(func = getSDDCBGPVPN)


# ============================
# NSX-T - Interfaces, Egress counters
# ============================

    show_egress_interface_counters_parser=system_parser_subs.add_parser('show-egress-interface-counters', parents=[auth_flag,nsx_url_flag], help = 'show current Internet interface egress counters')
    show_egress_interface_counters_parser.set_defaults(func = getSDDCEgressInterfaceCtrs)

# ============================
# NSX-T - Show Routes
# ============================

    show_routes_parser= system_parser_subs.add_parser('show-routes', parents=[auth_flag,nsx_url_flag, org_id_flag, vmc_url_flag], help = 'Show SDDC routes')
    show_routes_parser.add_argument('route-type', choices = ['t0', 'bgp', 'static', 'tgw'], type = str.lower, help = " Select the type of route information to display - t0 (all), bgp (learned and advertised), static, tgw (Trasit Gateway configured).")
    show_routes_parser.add_argument('-gid', '--sddc_group_id', help = "The ID of the SDDC for the route table.  Use 'get-group-info' for a list of SDDCs Groups with IDs.")
    show_routes_parser.add_argument('--search-name', help = "Optionally, enter the name of the SDDC group you wish to view the route table for.")
    show_routes_parser.set_defaults(func = getSDDCroutes)


# ============================
# NSX-T - Search
# ============================
    """ Subparser for NSX Search functions """
    search_nsx_parser = subparsers.add_parser('search-nsx', parents=[auth_flag,nsx_url_flag],formatter_class=MyFormatter, help='Search the NSX Manager inventory.')
    search_nsx_parser.add_argument("object_type", choices=["BgpNeighborConfig","BgpRoutingConfig","Group","IdsSignature","PrefixList","RouteBasedIPSecVPNSession","Segment","Service","StaticRoute","Tier0","Tier1","VirtualMachine","VirtualNetworkInterface"], help="The type of object to search for.")
    search_nsx_parser.add_argument("-oid","--object_id", required=False, help="The name of the object you are searching for.")
    search_nsx_parser.set_defaults(func=search_nsx)

# ============================
# VCDR
# ============================

    # create the parser for the "vcdr" command
    vcdr_parser = subparsers.add_parser('vcdr', help='Create, delete, update, and show information about VMware Cloud Disaster Recovery.')
    # create a subparser for vcdr sub-commands
    vcdr_parser_subs = vcdr_parser.add_subparsers(help='vcdr sub-command help')

    # create sub-parser for Scale-out File System sub-command
    vcdr_scfs_parser = vcdr_parser_subs.add_parser("scfs", help = "VCDR cloud file system - use '-h' for help.")
    vcdr_scfs_parser_subs = vcdr_scfs_parser.add_subparsers(help='vcdr scfs sub-command help')

    # create individual parsers for each SCFS sub-sub-command(s)
    vcdr_scfs_show_parser = vcdr_scfs_parser_subs.add_parser("show", parents=[auth_flag,vcdr_url_flag], help = "Show information about the VCDR Scale-out file System(s).")
    vcdr_scfs_show_parser.add_argument("-cfsid","--cloud_fs_id", required=False, help= "ID of the Cloud File System")
    vcdr_scfs_show_parser.set_defaults(func = getVCDRCloudFS)

    # create sub-parser for Protection Group sub-command
    vcdr_pg_parser = vcdr_parser_subs.add_parser("pg", help = "VCDR Protection Groups - use '-h' for help.")
    vcdr_pg_parser_subs = vcdr_pg_parser.add_subparsers(help='vcdr pg sub-command help')

    # create individual parsers for each PG sub-sub-command(s)
    vcdr_pg_show_parser = vcdr_pg_parser_subs.add_parser("show", parents=[auth_flag,vcdr_url_flag], help = "Show information about the VCDR Protection Group(s).")
    vcdr_pg_show_parser.add_argument("-cfsid","--cloud_fs_id", required=True, help= "ID of the Cloud File System")
    vcdr_pg_show_parser.add_argument("-pgid", "--protection_group_id", required=False, help = "ID of the protection group")
    vcdr_pg_show_parser.set_defaults(func = getVCDRPG)

    # create sub-parser for Snapshots sub-command
    vcdr_snaps_parser = vcdr_parser_subs.add_parser("snaps", help = "VCDR Snapshots - use '-h' for help.")
    vcdr_snaps_parser_subs = vcdr_snaps_parser.add_subparsers(help='vcdr snaps sub-command help')

    # create individual parsers for each Snapshot sub-sub-command(s)
    vcdr_snaps_show_parser = vcdr_snaps_parser_subs.add_parser("show", parents=[auth_flag,vcdr_url_flag], help = "Show information about the VCDR Snapshot(s).")
    vcdr_snaps_show_parser.add_argument("-cfsid","--cloud_fs_id", required=True, help= "ID of the Cloud File System")
    vcdr_snaps_show_parser.add_argument("-pgid", "--protection_group_id", required=True, help = "ID of the protection group")
    vcdr_snaps_show_parser.add_argument("-snapid", "--protection_group_snap_id", required=False, help = "ID of the protection group snapshot")
    vcdr_snaps_show_parser.set_defaults(func = getVCDRPGSnaps)

    # create sub-parser for Recovery SDDC sub-command
    vcdr_rsddc_parser = vcdr_parser_subs.add_parser("rsddc", help = "VCDR Recovery SDDC - use '-h' for help.")
    vcdr_rsddc_parser_subs = vcdr_rsddc_parser.add_subparsers(help='vcdr rsddc sub-command help')

    # create individual parsers for each Recovery SDDC sub-sub-command(s)
    vcdr_rsddc_show_parser = vcdr_rsddc_parser_subs.add_parser("show", parents=[auth_flag,vcdr_url_flag], help = "Show information about the VCDR Recovery SDDC(s).")
    vcdr_rsddc_show_parser.add_argument("-rsddcid", "--recovery_sddc_id", required=False, help = "ID of the recovery SDDC")
    vcdr_rsddc_show_parser.set_defaults(func = getVCDRSDDCs)

    # create sub-parser for Protected Site sub-command
    vcdr_psite_parser = vcdr_parser_subs.add_parser("psite", help = "VCDR Protected Site - use '-h' for help.")
    vcdr_psite_parser_subs = vcdr_psite_parser.add_subparsers(help='vcdr psite sub-command help')

    # create individual parsers for each Protected Site sub-sub-command(s)
    vcdr_psite_show_parser = vcdr_psite_parser_subs.add_parser("show", parents=[auth_flag,vcdr_url_flag], help = "Show information about the VCDR Protected Site(s).")
    vcdr_psite_show_parser.add_argument("-cfsid","--cloud_fs_id", required=True, help= "ID of the Cloud File System")
    vcdr_psite_show_parser.add_argument("-siteid", "--site_id", required=False, help = "ID of the protected site")
    vcdr_psite_show_parser.set_defaults(func = getVCDRSites)

    # create sub-parser for protected VM sub-command
    vcdr_vms_parser = vcdr_parser_subs.add_parser("vms", help = "VCDR cloud file system - use '-h' for help.")
    vcdr_vms_parser_subs = vcdr_vms_parser.add_subparsers(help='vcdr scfs sub-command help')

    # create individual parsers for each Protected VM sub-sub-command(s)
    vcdr_vms_show_parser = vcdr_vms_parser_subs.add_parser("show", parents=[auth_flag,vcdr_url_flag], help = "Show information about the VCDR protected VM(s).")
    vcdr_vms_show_parser.add_argument("-cfsid","--cloud_fs_id", required=True, help= "ID of the Cloud File System")
    vcdr_vms_show_parser.set_defaults(func = getVCDRVM)

# ============================
# Call function to retreieve parameters in config.ini
# ============================
    config_params = read_config()

# ============================
# Parsing arguments and calling function(s)
# ============================
    # Parse the arguments.
    args = ap.parse_args()

    # If no arguments given, or no subcommands given with a function defined, return help:
    if 'func' not in args:
        ap.print_help(sys.stderr)
        sys.exit(0)
    else:
        pass
    # Build dictionary to pass to later functions
    params = vars(args)

    # Depending on params in config.ini use OAuth or Refresh Token for auth
    auth_params = {}
    sessiontoken = ''
    try:
        auth_method = args.oauth
        match auth_method:
            case "oauth":
                auth_params = {'auth_method':auth_method, 'strCSPProdURL':config_params['strCSPProdURL'], 'oauth_clientSecret':config_params['clientSecret'], 'oauth_clientId':config_params['clientId']}
                sessiontoken = getAccessToken(**auth_params)
            case "refresh_token":
                auth_params = {'auth_method':auth_method, 'strCSPProdURL':config_params['strCSPProdURL'], 'myKey':config_params['Refresh_Token']}
                sessiontoken = getAccessToken(**auth_params)
    except:
        auth_params = {'auth_method':"refresh_token", 'strCSPProdURL':config_params['strCSPProdURL'], 'myKey':config_params['Refresh_Token']}
        sessiontoken = getAccessToken(**auth_params)

    if sessiontoken == None:
        sys.exit(1)
        
    # Update the dictionary with the session token
    params.update({"sessiontoken": sessiontoken})
    
    # If flags are present for VMC, add the appropriate URL to the parameters payload. Command line arguments overload
    try:
        args.vmc_flag
        params.update({"strProdURL": config_params['strProdURL']})
    except:
        pass

    # If flags are present for CSP, add the appropriate URL to the parameters payload.
    try:
        args.csp_flag
        params.update({"strCSPProdURL": config_params['strCSPProdURL']})
    except:
        pass

    # If flags are present for VCDR, add the appropriate URL to the parameters payload.
    try:
        args.vcdr_flag
        params.update({"strVCDRProdURL": config_params['strVCDRProdURL']})
    except:
        pass

    # If flags are present for ORG_ID, add the ORG_ID to the parameters payload.
    try:
        args.org_flag
        params.update({"ORG_ID":config_params['ORG_ID']})
    except:
        pass

 # If flags are present for SDDC_ID, add the SDDC_ID to the parameters payload.
    try:
        args.sddc_flag
        params.update({"SDDC_ID": config_params['SDDC_ID']})
    except:
        pass

    # If flags are present for NSX Proxy or NSX Manager, add the appropriate URL to the parameters payload.
    try:
        params.get('nsxm')
        params['proxy'] = params.pop('nsxm')
        if params['proxy'] == "proxy":
            sddc_info = get_sddc_info_json(config_params['strProdURL'], config_params['ORG_ID'], sessiontoken, config_params['SDDC_ID'])
            if sddc_info == None:
                sys.exit(1)
            proxy_url = sddc_info['resource_config']['nsx_api_public_endpoint_url']
            params.update({"proxy": proxy_url})
        else:
            sddc_info = get_sddc_info_json(config_params['strProdURL'], config_params['ORG_ID'], sessiontoken, config_params['SDDC_ID'])
            nsxm_url = sddc_info['resource_config']['nsx_mgr_url']
            params.update({"proxy": nsxm_url})
    except Exception as inst:
        pass

    # Call the appropriate function with the dictionary containing the arguments.
    args.func(**params)
    sys.exit(0)


if __name__ == "__main__":
    main()