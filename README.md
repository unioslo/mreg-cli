# MREG CLI [![Build Status](https://github.com/unioslo/mreg-cli/actions/workflows/test.yml/badge.svg)](https://github.com/unioslo/mreg-cli/actions/workflows/test.yml)

`mreg-cli` is a command line interface for the MREG API.

- [MREG CLI](#mreg-cli-)
  - [Setup](#setup)
  - [General usage](#general-usage)
    - [Filtering](#filtering)
    - [Forcing commands](#forcing-commands)
  - [Command set](#command-set)
    - [Host](#host)
      - [A/AAAA](#aaaaa)
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
    - [other](#other)

## Setup

Options can be set in ~/.config/mreg-cli.conf. A typical config file looks like this:

```ini
[mreg]
url=https://mreg.example.com:8000
user=mreg-user
```

An example config file can be found in [data/mreg-cli.conf](data/mreg-cli.conf).

<details>
<summary>Config options</summary>

### URL

The URL of the MREG server. This is the only required option.

```ini
[mreg]
url=https://mreg.example.com:8000
```

The URL can also be specified as a command line argument:

```bash
mreg-cli --url "https://mreg.example.com:8000"
```

### User

The username to use when connecting to the MREG server. This is optional, and if not specified, the CLI will try to use the current user's username.

```ini
[mreg]
user=mreg-user
```

The user can also be specified as a command line argument:

```bash
mreg-cli --user "mreg-user"
```

### Domain

Default domain to use for hostnames. This is optional, and if not specified, the CLI will use `uio.no` as the default domain.

```ini
[mreg]
domain=uio.no
```

The domain can also be specified as a command line argument:

```bash
mreg-cli --domain "uio.no"
```

### Prompt

The prompt text can be configured with a custom format string. The available variables are:

- `{user}`: Username of active user
- `{proto}`: Protocol part of the server URL
- `{host}`: Name part of the server URL
- `{port}`: Port part of the server URL (if any)
- `{domain}`: Domain name. Defaults to `uio.no` if not specified.

By default the prompt is set to `{user}@{host}`, which is equivalent to the following config:

```ini
[mreg]
prompt={user}@{host}
```

Which results in a prompt like this:

```cli
admin@mreg.example.com>
```

#### Command line

A custom prompt string can be specified as a command line argument as well:

```bash
mreg-cli --prompt "<string>"
```

#### Disabling the prompt prefix text

The prompt text can be disabled by setting it to no value in the config file or by using the `--prompt` flag with an empty string.

```ini
[mreg]
prompt=
```

```bash
mreg-cli --prompt ""
```

Which results in the following prompt:

```cli
>
```

### Log file

The location of the log file. The default location is `$XDG_DATA_DIRS/mreg-cli/mreg-cli.log`, which is typically `~/.local/share/mreg-cli/mreg-cli.log`.

```ini
[mreg]
logfile=/var/log/mreg-cli.log
```

The log file can also be specified as a command line argument:

```bash
mreg-cli --logfile "/var/log/mreg-cli.log"
```

### Timeout

The timeout for HTTP requests to the MREG server. The default is 20 seconds.

```ini
[mreg]
timeout=20
```

### Cache

Enable/disable caching of API results. Cache is always cleared on every write request (POST, PUT, PATCH, DELETE).

```ini
[mreg]
cache=true
```

### Cache TTL

Time-to-live for cached API results, in seconds. Defaults to 300 seconds (5 minutes).

```ini
[mreg]
cache_ttl=300
```

### Category tags

List of valid category tags for networks. Used by `network create`.

```ini
[mreg]
category_tags=default,production,development,test
```

### Location tags

List of valid location tags for networks. Used by `network create`.

```ini
[mreg]
location_tags=default,oslo,bergen,stavanger
```

</details>

## General usage

Commands in `mreg-cli` take on the form of a fairly standard command line interface:

```sh
host add myhost.example.com 192.168.1.1 me@example.con -hinfo Linux -comment "My host"
```

Here we are using the `host add` command to add a new host. The command takes a number of arguments, which are positional. The arguments in this case is a name and an ip address, followed by a contact and some optional arguments. The optional arguments are specified with a flag, followed by the value. The optional arguments can be specified in any order, but the positional arguments must be specified in the order they are defined in the command.

### Filtering

`mreg-cli` support output filtering via the operators `|` and `|!`. The `|` operator is used to filter the output to only show the lines matching the text  specified after the operator. Using `|!` will show the lines _not_ matching the text specified after the operator. The filter text is a standard python regular expression. Some examples:

```sh
mreg> host info one.example.com
Name:         one.example.com
Contact:      me@example.com
A_Records     IP                           MAC
              192.168.1.2                  aa:bb:cc:dd:ee:ff
TTL:          (Default)
TXT:          v=spf1 -all
mreg> host info one.example.com | example
Name:         one.example.com
Contact:      me@example.com
mreg> host info one.example.com | me.*com
Contact:      me@example.com
mreg> host info one.example.com |! me.*com
Name:         one.example.com
A_Records     IP                           MAC
              192.168.1.2                  aa:bb:cc:dd:ee:ff
TTL:          (Default)
TXT:          v=spf1 -all
```

### Forcing commands

A number of commands take a `-force` flag. This flag is typically required when the operation will fail internal validation. However, please note that `-force` is emphatically not a "I know what I'm doing" flag. It is a "I know what I'm doing and I'm willing to take responsibility for the consequences" flag. If you're not sure what you're doing, don't use `-force`.

As an example, you may add a host to a network unknown to mreg, or a frozen network. You may want to assiciate a mac address to a host or an IP that already has a mac address associated with it. All of these examples will cause a validation failure, but you may bypass this failure by using `-force`. This is fine if you for example are certain the new mac address is supposed to replace the old one, but if you mistakenly associate a mac address to the wrong host, you may cause the host to be unreachable on the network. `-force` exists to alert you that you are doing something that may have unintended consequences, and you should be sure you know what you are doing before using it.

## Command set

### Host

```cli
   host add <name> <ip/net> <contact> [-hinfo <hinfo>] [-comment <comment>]
       Add a new host with the given name, ip or subnet and contact. hinfo and comment
       are optional.
```

!!!note
    Force is required when adding a host with an ip in a subnet not controlled by MREG or in a frozen subnet.

```cli
   host remove <name|ip>
       Remove host. If <name> is an alias the cname host is removed.
       
```

```cli
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

```cli
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

```cli
   host cname_add <existing-name> <new-alias>
       Add a CNAME record to host. If <existing-name> is an alias the cname host is used as
       target for <new-alias>.
       
   host cname_remove <name> <alias-to-delete>
       Remove CNAME record.
       
   host cname_show <name>
       Show CNAME records for host. If <name> is an alias the cname hosts aliases are shown.
```

#### HINFO

```cli
   host hinfo_remove <name>
       Remove hinfo for host. If <name> is an alias the cname host is updated.
       
   host hinfo_set <name> <hinfo>
       Set hinfo for host. If <name> is an alias the cname host is updated.
       
   host hinfo_show <name>
       Show hinfo for host. If <name> is an alias the cname hosts hinfo is shown.
```

#### LOC

All LOC commands require force.

```cli
   host loc_remove <name>
       Remove location from host. If <name> is an alias the cname host is updated.
       
   host loc_set <name> <loc>
       Set location of host. If <name> is an alias the cname host is updated.
       
   host loc_show <name>
       Show location of host. If <name> is an alias the cname hosts LOC is shown.
```

#### NAPTR

```cli
   host naptr_add <name> <preference> <order> <flagg> <service> <regexp> <replacement>
       Add a NAPTR record to host.
       
   host naptr_remove <name> <replacement>
       Remove NAPTR record.
       
   host naptr_show <name>
       Show all NAPTR records for host.
```

#### PTR

```cli
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

Require force if a host with `target-name` doesn't exist.

```cli
   host srv_add <service-name> <pri> <weight> <port> <target-name>
       Add SRV record.
       
   host srv_remove <service-name>
       Remove SRV record.
       
   host srv_show <service-name>
       Show SRV records for the service.
```

#### SSHFP

```cli
   host sshfp_add <name> <algorithm> <hash_type> <fingerprint>
       Add SSHFP record for the host.

   host sshfp_remove <name> <fingerprint>
       Remove SSHFP record with a given fingerprint from the host.
       A missing fingerprint removes all SSHFP records for the host.

   host sshfp_show <name>
       Show SSHFP records for the host.
```

#### TTL

```cli
   host ttl_remove <name>
       Remove explicit TTL for host. If <name> is an alias the alias host is updated.
       
   host ttl_set <name> <ttl>
       Set ttl for host. Valid values are 300 <= TTL <= 68400 or "default". If <name> is an
       alias the alias host is updated.
       
   host ttl_show <name>
       Show ttl for host. If <name> is an alias the alias hosts TTL is shown.
```

#### TXT

```cli
   host txt_add <name> <text>
       Add a txt record to host. <text> must be enclosed in double quotes if it contains more
       than one word.
       
   host txt_remove <name> <text>
       Remove TXT record for host matching <text>.
       
   host txt_show <name>
       Show all TXT records for host.
```

#### DHCP

```cli
   dhcp assoc <name|ip> <mac-addr>
       Associate MAC address with host. If host got multiple A/AAAA records an IP must be
       given instead of name.
       
   dhcp disassoc <name|ip>
       Disassociate MAC address with host/ip. If host got multiple A/AAAA records an IP must be
       given instead of name
```

### subnet

```cli
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

```cli
   zone create <zone-name> (<nameservers>)
       Create new zone.
       
   zone delete <zone-name>
       Delete a zone
       
   zone set_ns <zone-name> (<nameservers>)
       Update nameservers for an existing zone.
       
   zone set_soa <zone-name> (<primary_ns> <email> <serialno> <refresh> <retry> <expire> <ttl>)
       Updated the SOA of a zone.
```

### other

The CLI also provides these miscellaneous functions:

List available commands without a argument, or display detailed help for a command or for a specific option of a command.

```cli
help
help <cmd>
<cmd> help <option>
```

`shell <cmd>`: Run a bash command.

`source <file-name> [--exit]`: Read commands from a file. If --exit is supplied then it'll stop executing on error.
