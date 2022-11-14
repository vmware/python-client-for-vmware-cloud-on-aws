# What's New - November 14, 2022
In this latest release, all commands have been refactored to use a command / sub-command syntax.  This provides for greater ease of use, as commands can be grouped by category.  Furthermore, a comprehensive argument framework has been implemented (argparse) which allows for passing parameters via the command line for better support for scripting. 

For example, in previous versions BGP prefix filters for your route-based VPN could only be created interactively at the command line.  Now, however, prefix lists can be imported as JSON files to make it a lot easier to update your T0 route table via script for specific use cases - e.g. disaster recovery.

### New Features:
 - all commands refactored to use argument parsing with python argparse module
 - moving forward, all commands will be updated (over time) to use standardized create / update / delete verbs (CrUD) where applicable 

### New Commands / options:
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

### Known Issuesß:
