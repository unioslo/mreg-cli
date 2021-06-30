# MREG CLI [![Build Status](https://github.com/unioslo/mreg-cli/actions/workflows/test.yml/badge.svg)](https://github.com/unioslo/mreg-cli/actions/workflows/test.yml)
Command Line Interface for Mreg

- [Usage](#usage)
    - [host](#host)
        - [A/AAAA](#a/aaaa)
        - [CNAME](#cname)
        - [HINFO](#hinfo)
        - [LOC](#loc)
        - [NAPTR](#naptr)
        - [PTR](#ptr)
        - [SRV](#srv)
        - [SSHFP](#sshfp)
        - [TTL](#ttl)
        - [TXT](#txt)
        - [DHCP](#dhcp)
    - [subnet](#subnet)
    - [zone](#zone)
    - [history](#history)
    - [other](#other)
- [Devhelp](#devhelp)
    - [client.py](#client.py)
    - [commands.py](#commands.py)
    - [util.py](#util.py)
    - [history.py](#history.py)
    - [config.py](#config.py)
    - [log.py](#log.py)

## Usage
There is currently no form of authentication in the CLI. Force can be used by anyone.

Logging uses the OS user name when recording logs.  
The log file can be change in _cli.conf_.

Server IP and port can also be specified in _cli.conf_.

### host
Force are required when adding a host with an ip in a subnet not controlled by MREG or in a frozen subnet.
``` 
   host add <name> <ip/net> <contact> [-hinfo <hinfo>] [-comment <comment>]
       Add a new host with the given name, ip or subnet and contact. hinfo and comment
       are optional.
```

Force are required when removing a host with multiple A/AAAA records or if it has a NAPTR, PTR or SRV record.
```
   host remove <name|ip>
       Remove host. If <name> is an alias the cname host is removed.
       
```

```
       
   host info <name|ip>
       Print information about host. If <name> is an alias the cname hosts info is shown.
       
   host rename <old-name> <new-name>
       Rename host. If <old-name> is an alias then the alias is renamed.
    
   host set_comment <name> <comment>
       Set comment for host. If <name> is an alias the cname host is updated.
       
   host set_contact <name> <contact>
       Set contact for host. If <name> is an alias the cname host is updated.

```

#### A/AAAA
The API doesn't differentiate between ipv4 and ipv6, so A/AAAA are only different on the client side.  
Require force if the host already has A/AAAA record(s), or if the ip is in a subnet not controlled by MREG.
```
   host a_add <name> <ip|subnet>
       Add an A record to host. If <name> is an alias the cname host is used.
       
   host a_change <name> <old-ip> <new-ip-or-subnet>
       Change A record. If <name> is an alias the cname host is used.
       
   host a_remove <name> <ip>
       Remove A record from host. If <name> is an alias the cname host is used.
       
   host a_show <name>
       Show hosts ipaddresses. If <name> is an alias the cname host is used.
       
   host aaaa_add <name> <ipv6>
       Add an AAAA record to host. If <name> is an alias the cname host is used.
       
   host aaaa_change <name> <old-ipv6> <new-ipv6>
       Change AAAA record. If <name> is an alias the cname host is used.
       
   host aaaa_remove <name> <ipv6>
       Remove AAAA record from host. If <name> is an alias the cname host is used.
       
   host aaaa_show <name>
       Show hosts ipaddresses. If <name> is an alias the cname host is used.
```

#### CNAME
``` 
   host cname_add <existing-name> <new-alias>
       Add a CNAME record to host. If <existing-name> is an alias the cname host is used as
       target for <new-alias>.
       
   host cname_remove <name> <alias-to-delete>
       Remove CNAME record.
       
   host cname_show <name>
       Show CNAME records for host. If <name> is an alias the cname hosts aliases are shown.
```

#### HINFO
``` 
   host hinfo_remove <name>
       Remove hinfo for host. If <name> is an alias the cname host is updated.
       
   host hinfo_set <name> <hinfo>
       Set hinfo for host. If <name> is an alias the cname host is updated.
       
   host hinfo_show <name>
       Show hinfo for host. If <name> is an alias the cname hosts hinfo is shown.
```

#### LOC
All LOC commands require force.
``` 
   host loc_remove <name>
       Remove location from host. If <name> is an alias the cname host is updated.
       
   host loc_set <name> <loc>
       Set location of host. If <name> is an alias the cname host is updated.
       
   host loc_show <name>
       Show location of host. If <name> is an alias the cname hosts LOC is shown.
```

#### NAPTR
``` 
   host naptr_add <name> <preference> <order> <flagg> <service> <regexp> <replacement>
       Add a NAPTR record to host.
       
   host naptr_remove <name> <replacement>
       Remove NAPTR record.
       
   host naptr_show <name>
       Show all NAPTR records for host.
```

#### PTR
``` 
   host ptr_change <ipv4|ipv6> <old-name> <new-name>
       Move PTR record from <old-name> to <new-name>.
       
   host ptr_remove <ipv4|ipv6> <name>
       Remove PTR record from host.
       
   host ptr_set <ipv4|ipv6> <name>
       Create a PTR record for host.
       
   host ptr_show <ipv4|ipv6>
       Show PTR record matching given ip (empty input shows all PTR records).
```

#### SRV
Require force if a host with <target-name> doesn't exist.
``` 
   host srv_add <service-name> <pri> <weight> <port> <target-name>
       Add SRV record.
       
   host srv_remove <service-name>
       Remove SRV record.
       
   host srv_show <service-name>
       Show SRV records for the service.
```

#### SSHFP
```
   host sshfp_add <name> <algorithm> <hash_type> <fingerprint>
       Add SSHFP record for the host.

   host sshfp_remove <name> <fingerprint>
       Remove SSHFP record with a given fingerprint from the host.
       A missing fingerprint removes all SSHFP records for the host.

   host sshfp_show <name>
       Show SSHFP records for the host.
```

#### TTL
``` 
   host ttl_remove <name>
       Remove explicit TTL for host. If <name> is an alias the alias host is updated.
       
   host ttl_set <name> <ttl>
       Set ttl for host. Valid values are 300 <= TTL <= 68400 or "default". If <name> is an
       alias the alias host is updated.
       
   host ttl_show <name>
       Show ttl for host. If <name> is an alias the alias hosts TTL is shown.
```

#### TXT
``` 
   host txt_add <name> <text>
       Add a txt record to host. <text> must be enclosed in double quotes if it contains more
       than one word.
       
   host txt_remove <name> <text>
       Remove TXT record for host matching <text>.
       
   host txt_show <name>
       Show all TXT records for host.
```

#### DHCP
``` 
   dhcp assoc <name|ip> <mac-addr>
       Associate MAC address with host. If host got multiple A/AAAA records an IP must be
       given instead of name.
       
   dhcp disassoc <name|ip>
       Disassociate MAC address with host/ip. If host got multiple A/AAAA records an IP must be
       given instead of name
```

### subnet
``` 
   subnet create <subnet> <description> <vlan> <dns_delegated> <category> <location> <frozen>
       Create a new subnet
       
   subnet import <file>
       Import subnet data from <file>.
       
   subnet info <subnet>
       Display subnet info
       
   subnet list_unused_addresses <subnet>
       Lists all the unused addresses for a subnet
       
   subnet list_used_addresses <subnet>
       Lists all the used addresses for a subnet
       
   subnet remove <subnet>
       Remove subnet
       
   subnet set_category <subnet> <category_tag>
       Set category tag for subnet
       
   subnet set_description <subnet> <description>
       Set description for subnet
       
   subnet set_dns_delegated <subnet>
       Set that DNS-administration is being handled elsewhere.
       
   subnet set_frozen <subnet>
       Freeze a subnet.
       
   subnet set_location <subnet> <location_tag>
       Set location tag for subnet
       
   subnet set_reserved <subnet> <number>
       Set number of reserved hosts.
       
   subnet set_vlan <subnet> <vlan>
       Set VLAN for subnet
       
   subnet unset_dns_delegated <subnet>
       Set that DNS-administration is not being handled elsewhere.
       
   subnet unset_frozen <subnet>
       Unfreeze a subnet.
```

### zone
``` 
   zone create <zone-name> (<nameservers>)
       Create new zone.
       
   zone delete <zone-name>
       Delete a zone
       
   zone set_ns <zone-name> (<nameservers>)
       Update nameservers for an existing zone.
       
   zone set_soa <zone-name> (<primary_ns> <email> <serialno> <refresh> <retry> <expire> <ttl>)
       Updated the SOA of a zone.
```

### history
History is stored on a per-session basis, so when the program is terminated the history is gone.  
The history is a recording Read commands from a file. If --exit is supplied then it'll stop executing on error.of all API calls for each user action. `history print` shows for each
record if it can be redone/undone.  
GET calls are never undone or redone.  
The most common reason for an action not being undo-able is foreign keys being invalid after a delete.
``` 
   history print
       Print the history.
       
   history redo <history-number>
       Redo some history event given by <history-number> (GET requests are not redone)
       
   history undo <history-number>
       Undo some history event given by <history-number> (GET requests cannot be undone)
```

### other
The CLI also provides these miscellaneous functions:

List available commands without a argument, or display detailed help for a command or for a specific option of a command.
```
help
help <cmd>
<cmd> help <option>
```

`shell <cmd>`: Run a bash command.

`source <file-name> [--exit]`: Read commands from a file. If --exit is supplied then it'll stop executing on error.

## Devhelp

##### client.py
Implementation of the client shell, using the python standard library module `cmd`.
When creating a new command the only change needed here is to add the methods:
```python
    def do_<command-name>(self, args):
        self.command_do(args, <command-object>)

    def complete_<command-name>(self, text, line, begidx, endidx):
        return self.command_complete(text, line, begidx, endidx, <command-object>)

    def help_<command-name>(self):
        self.command_help(<command-object>)
```

##### commands.py
Implementation of the commands. `CommandBase` is the base class which uses inspection 
to generate documentation and execute commands.  
When creating a new command create a class which inherits `CommandBase` and add 
methods starting with `opt_` to add options to the command:
```python
class <command-class>(CommandBase):
    """
    Doc string for the command. Displayed as help string when typing "help <command>"
    """

    def opt_<command-option>(self, args):
        """
        Doc string for command option. Displayed as help string when typing "<command> help <option>"
        """
        pass
```

##### util.py
Contains most of the helper functions for the project.

##### history.py
Implementation of (basic) history recording. History recordings must be explicitly called
from the code of command implementations. History is not saved to file.

##### config.py
Contains `cli_config(config_file, required_fields)`  which reads a simple key=value config
file and returns a dict. Raises an exception if any of the required_fields are missing.

##### log.py
Contains functions for handling logging. The log entries are on the format: 
```
2018-01-01 15:01:02 username [ERROR] host add: message
```

The log functions are:

`cli_info(msg, print_msg=False)` - log a [OK] message. Doesn't print to stdout by default.  
`cli_warning(msg, print_msg=True)` - log a [WARNING] message and raise an exception, the default
exception is CliWarning. Print to stdout by default.  
`cli_error(msg, print_msg=True)` - log a [ERROR] message and raise an exception, the default
exception is CliError. Print to stdout by default.
