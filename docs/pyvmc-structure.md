# Overview
Over time, PyVMC has grown it its capabilites, in the number of commands it supports and ultimately in its complexity.  Functionality has been separated amongst several files to make navigating and updating the code easier - however this may make understanding how the project is put together a bit more challenging to understand.

## The Files

As mentione above, the functionality of the project is split up into multiple files....

![pyvmc structure](images/pyvmc_refactor.png)

Everything begins with...

**pyVMC.py**
pyVMC.py is the file where _main_ is defined, where the commands and arguments are defined for controlling user input, and where the 'business logic'/ functions are housed for handling user input and ultimately returning a result back to the screen.

A great deal of work has gone into incorporating python argparse into the project for defining and handling commands and arguments in the CLI - so the first thing you should do before adding / updating a command or function for the project is think through how the user your new functionality:
- Are you simply adding new functionality to a command that already exists?  
- Are you instead adding a new command for an existing feature? 
- Are you adding new commands for an entirely new API?

The answers to the questions above will ultimately help determine if you are adding a new category of commands ("super-command"), a new sub-command under a super-command that already exists, or just a new option for an existing subcommand.

See the image below for a graphical representation of how argparse is being used to strucure commands in a hierarchical fashion.

![argparse structure](images/argparse_structure.png)

**API modules**
The functions that actually make calls to the API endpoint(s) are housed in separate files, aligned to the specific API:
- pyvmc_csp.py: functions that make calls to the CSP URL - https://console.cloud.vmware.com
- pyvmc_vmc.py: functions that make calls to the VMC service API - https://vmc.vmware.com
- pyvmc_nsx.py: functions that make calls to the NSX API via the reverse proxy to directly to the NSX manager  (this URL is unique to each customer and is determined via a query to the service)
- pyvmc_vcdr.py: fuctions that make calls to the VCDR Orchestrator API (this URL is unique to each customer and must be manually updated in the config.ini file)

## Error Handling