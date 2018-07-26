import traceback
import inspect
import re
import types
import typing
import requests
import ipaddress

from util import *
from config import *
from history import history
from log import *

try:
    conf = cli_config(required_fields=("server_ip", "server_port"))
except Exception as e:
    print("commands.py: cli_config:", e)
    traceback.print_exc()
    sys.exit(1)


################################################################################
#                                                                              #
#   Base class of CLI commands                                                 #
#                                                                              #
################################################################################

class CommandBase():
    """
    Base class of all commands for the mreg client. It provide functions which uses inspection to
    generate documentation and cli-info.

    To add a new option to the command create a opt_<option-name> method which takes a list of
    arguments as input.
    """

    def __init__(self):
        pass

    @staticmethod
    def _is_option(value):
        """Identify an option method"""
        if isinstance(value, types.MethodType):
            if re.match("^opt_.*$", value.__name__):
                return True
        return False

    def _option_methods(self) -> typing.List[typing.Tuple[str, typing.Callable]]:
        """Return all option methods of self"""
        # getmembers returns a list of tuples with: (<method name>, <method object>)
        return inspect.getmembers(self, predicate=self._is_option)

    def help(self) -> str:
        """Generate a help message of the command (self) and all its options"""
        help_str = "{}\n\nOptions:\n".format(inspect.getdoc(self))
        for method in self._option_methods():
            assert isinstance(method[1], types.MethodType)
            for line in inspect.getdoc(method[1]).splitlines(keepends=False):
                help_str += "   {}\n".format(line)
        return help_str

    def options(self) -> typing.List[str]:
        """Returns all options of this command, identified by function prefix "opt_\" (they are
        returned without opt_ prefix)
        """
        options = []
        for method in self._option_methods():
            options.append(method[0].split('_', maxsplit=1)[1])
        return options

    def opt_help(self, opt: str) -> None:
        """
        help <option>
            Return the documentation for the option.
        """
        for method in self._option_methods():
            if method[0] == "opt_" + opt:
                assert isinstance(method[1], types.MethodType)
                print(inspect.getdoc(method[1]))
                return
        print("No documentation of \"{}\"".format(opt))

    def method(self, opt: str) -> typing.Callable:
        """Returns the actual option method from a user-friendly option name."""
        for method in self._option_methods():
            if method[0] == "opt_" + opt:
                assert isinstance(method[1], types.MethodType)
                return method[1]
        cli_error("unknown option: {}".format(opt))


################################################################################
#                                                                              #
#   Command classes                                                            #
#                                                                              #
################################################################################


class History(CommandBase):
    """
    Redo/undo actions or show history.
        history <option> [<history-number>]
    """

    def opt_print(self, args: typing.List[str]):
        """
        print
            Print the history.
        """
        history.print()

    def opt_redo(self, args: typing.List[str]):
        """
        redo <history-number>
            Redo some history event given by <history-number> (GET requests are not redone)
        """
        try:
            history.redo(int(args[0]))
        except ValueError as e:
            cli_warning("invalid input: {}".format(e))

    def opt_undo(self, args: typing.List[str]):
        """
        undo <history-number>
            Undo some history event given by <history-number> (GET requests cannot be undone)
        """
        try:
            history.undo(int(args[0]))
        except ValueError as e:
            cli_warning("invalid input: {}".format(e))


# noinspection PyMethodMayBeStatic,PyMethodMayBeStatic
class Host(CommandBase):
    """
    Create, delete or edit host.
        host <option> <argument(s)>
    """

    def opt_info(self, args: typing.List[str]) -> None:
        """
        info <name|ip>
            Print information about host. If <name> is an alias the cname hosts info is shown.
        """
        if len(args) < 1:
            name_or_ip = input("Enter name or ip> ")
        else:
            name_or_ip = args[0]

        # Get host info or raise exception
        info = host_info_by_name_or_ip(name_or_ip)

        # Pretty print all host info
        print_host_name(info["name"])
        print_contact(info["contact"])
        if info["comment"]:
            print_comment(info["comment"])
        print_ipaddresses(info["ipaddress"])
        print_ttl(info["ttl"])
        if info["hinfo"]:
            print_hinfo(hinfo_id_to_strings(info["hinfo"]))
        if info["loc"]:
            print_loc(info["loc"])
        for cname in aliases_of_host(info["name"]):
            print_cname(cname, info["name"])
        for txt in info["txt"]:
            print_txt(txt["txt"])
        for ptr in info["ptr_override"]:
            print_ptr(ptr["ipaddress"], info["name"])
        cli_info("printed host info for {}".format(info["name"]))

    def opt_remove(self, args: typing.List[str]) -> None:
        """
        remove <name|ip>
            Remove host. If <name> is an alias the cname host is removed.
        """
        if len(args) < 1:
            name_or_ip = input("Enter name or ip> ")
        else:
            name_or_ip = args[0]

        # Get host info or raise exception
        info = host_info_by_name_or_ip(name_or_ip)

        warn_msg = ""
        # Require force if host has any aliases. Delete the aliases if force.
        aliases = aliases_of_host(info["name"])
        if len(aliases):
            if "y" not in args:
                warn_msg += "{} aliases. ".format(len(aliases))
            else:
                for alias in aliases:
                    url = "http://{}:{}/hosts/{}".format(
                        conf["server_ip"],
                        conf["server_port"],
                        alias,
                    )
                    # Cannot undo delete because of hosts CNAME record
                    history.record_delete(url, old_data=dict(), undoable=False)
                    delete(url)
                    cli_info("deleted alias host {} when removing {}".format(alias, info["name"]))

        # Require force if host has multiple A/AAAA records
        if len(info["ipaddress"]) > 1 and "y" not in args:
            warn_msg += "{} ipaddresses. ".format(len(info["ipaddress"]))

        # Require force if host has any NAPTR records. Delete the NAPTR records if force
        url = "http://{}:{}/naptrs/?hostid={}".format(
            conf["server_ip"],
            conf["server_port"],
            info["hostid"],
        )
        history.record_get(url)
        naptrs = get(url).json()
        if len(naptrs) > 0:
            if "y" not in args:
                warn_msg += "{} NAPTR records. ".format(len(naptrs))
            else:
                for ptr in naptrs:
                    url = "http://{}:{}/naptrs/{}".format(
                        conf["server_ip"],
                        conf["server_port"],
                        ptr["naptrid"],
                    )
                    history.record_delete(url, ptr)
                    delete(url)
                    cli_info("deleted NAPTR record {} when removing {}".format(
                        ptr["replacement"],
                        info["name"],
                    ))

        # Require force if host has any SRV records. Delete the SRV records if force
        url = "http://{}:{}/srvs/?target={}".format(
            conf["server_ip"],
            conf["server_port"],
            info["name"],
        )
        history.record_get(url)
        srvs = get(url).json()
        if len(srvs) > 0:
            if "y" not in args:
                warn_msg += "{} SRV records. ".format(len(srvs))
            else:
                for srv in srvs:
                    url = "http://{}:{}/srvs/{}".format(
                        conf["server_ip"],
                        conf["server_port"],
                        srv["srvid"],
                    )
                    history.record_delete(url, srv)
                    delete(url)
                    cli_info("deleted SRV record {} when removing {}".format(
                        srv["service"],
                        info["name"],
                    ))

        # Require force if host has any PTR records. Delete the PTR records if force
        if len(info["ptr_override"]) > 0:
            if "y" not in args:
                warn_msg += "{} PTR records. ".format(len(info["ptr_override"]))
            else:
                for ptr in info["ptr_override"]:
                    url = "http://{}:{}/ptroverrides/{}".format(
                        conf["server_ip"],
                        conf["server_port"],
                        ptr["id"],
                    )
                    history.record_delete(url, ptr, redoable=False, undoable=False)
                    delete(url)
                    cli_info("deleted PTR record {} when removing {}".format(
                        ptr["ipaddress"],
                        info["name"],
                    ))

        # To be able to undo the delete the ipaddress field of the 'old_data' has to be an ipaddress
        # string
        if len(info["ipaddress"]) > 0:
            info["ipaddress"] = info["ipaddress"][0]["ipaddress"]

        # Warn user and raise exception if any force requirements was found
        if warn_msg:
            cli_warning("{} has: {}Must force".format(info["name"], warn_msg))

        # Delete host
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_delete(url, old_data=info)
        delete(url)
        cli_info("removed {}".format(info["name"]), print_msg=True)

    def opt_add(self, args: typing.List[str]) -> None:
        """
        add <name> <ip/net> <contact> [-hinfo <hinfo>] [-comment <comment>]
            Add a new host with the given name, ip or subnet and contact. hinfo and comment
            are optional.
        """
        # NOTE: PTR record not created
        # NOTE: an A-record forward-zone not controlled by MREG aren't handled

        # Get arguments interactively, if missing required, with HINFO help
        hi_list = hinfo_list()
        if len(args) < 3:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip_or_net = input("Enter subnet or ip> ") if len(args) < 2 else args[1]
            contact = input("Enter contact> ")
            hinfo = input("Enter hinfo (optional)> ")
            while hinfo == "?":
                print_hinfo_list(hi_list)
                hinfo = input("Enter hinfo (optional)> ")
            comment = input("Enter comment (optional)> ")
        else:
            name = args[0]
            ip_or_net = args[1]
            contact = args[2]
            hinfo = "" if "-hinfo" not in args else args[args.index("-hinfo") + 1]
            comment = "" if "-comment" not in args else args[args.index("-comment") + 1]

        # Verify hinfo id
        if hinfo:
            hinfo = int(hinfo)
            if not 0 < hinfo <= len(hi_list):
                cli_warning("invalid hinfo ({}) when trying to add {}".format(hinfo, name))

        # Handle arbitrary ip from subnet if received a subnet w/o mask
        subnet = dict()
        if re.match(r"^.*/$", ip_or_net):
            subnet = get_subnet(ip_or_net[:-1])
            ip = available_ips_from_subnet(subnet).pop()

        # Handle arbitrary ip from subnet if received a subnet w/mask
        elif is_valid_subnet(ip_or_net):
            subnet = get_subnet(ip_or_net)
            ip = available_ips_from_subnet(subnet).pop()

        # Require force if given valid ip in subnet not controlled by MREG
        elif is_valid_ip(ip_or_net) and not ip_in_mreg_net(ip_or_net):
            if "y" not in args:
                cli_warning("{} isn't in a subnet controlled by MREG, must force".format(ip_or_net))
            else:
                ip = ip_or_net

        # Or else check that the address given isn't reserved
        else:
            subnet = get_subnet(ip_or_net)
            network_object = ipaddress.ip_network(subnet['range'])
            addresses = list(network_object.hosts())
            reserved_addresses = set([str(ip) for ip in addresses[:subnet['reserved']]])
            if ip_or_net in reserved_addresses and 'y' not in args:
                cli_warning("Address is reserved. Requires force")
            if ip_or_net == network_object.network_address.exploded:
                cli_warning("Can't overwrite the network address of the subnet")
            if ip_or_net == network_object.broadcast_address.exploded:
                cli_warning("Can't overwrite the broadcast address of the subnet")
            ip = ip_or_net

        # Require force if subnet is frozen
        if 'y' not in args and subnet['frozen']:
            cli_warning("Subnet {} is frozen. Requires force".format(subnet['range']))

        # Contact sanity check
        if not is_valid_email(contact):
            cli_warning("invalid mail address ({}) when trying to add {}".format(contact, name))

        # Fail if given host exists on either short or long form
        try:
            name = resolve_input_name(name)
        except HostNotFoundWarning:
            pass
        else:
            cli_warning("host {} already exists".format(name))

        # Always use long form host name. Require force if FQDN not in MREG zone
        if is_longform(name):
            if not host_in_mreg_zone(name) and "y" not in args:
                cli_warning("{} isn't in a zone controlled by MREG, must force".format(name))
        else:
            name = to_longform(name)

        # Create the new host with an ip address
        url = "http://{}:{}/hosts/".format(conf["server_ip"], conf["server_port"])
        data = {
            "name": name,
            "ipaddress": ip,
            "contact": contact,
            "hinfo": hinfo or None,
            "comment": comment or None,
        }
        history.record_post(url, resource_name=name, new_data=data)
        post(url, **data)
        cli_info("created host {}".format(name), print_msg=True)

    def opt_set_contact(self, args: typing.List[str]) -> None:
        """
        set_contact <name> <contact>
            Set contact for host. If <name> is an alias the cname host is updated.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            contact = input("Enter contact> ")
        else:
            name = args[0]
            contact = args[1]

        # Contact sanity check
        if not is_valid_email(contact):
            cli_warning("invalid mail address {} (target host: {})".format(contact, name))

        # Get host info or raise exception
        info = host_info_by_name(name)
        old_data = {"contact": info["contact"]}
        new_data = {"contact": contact}

        # Update contact information
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, contact=contact)
        cli_info("Updated contact of {} to {}".format(info["name"], contact), print_msg=True)

    def opt_set_comment(self, args: typing.List[str]) -> None:
        """
        set_comment <name> <comment>
            Set comment for host. If <name> is an alias the cname host is updated.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            comment = input("Enter comment> ")
        else:
            name = args[0]
            comment = " ".join(args[1:])

        # Get host info or raise exception
        info = host_info_by_name(name)
        old_data = {"comment": info["comment"] or ""}
        new_data = {"comment": comment}

        # Update comment
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, comment=comment)
        cli_info("updated comment of {} to \"{}\"".format(info["name"], comment), print_msg=True)

    def opt_rename(self, args: typing.List[str]) -> None:
        """
        rename <old-name> <new-name>
            Rename host. If <old-name> is an alias then the alias is renamed.
        """
        if len(args) < 2:
            old_name = input("Enter old name> ") if len(args) < 1 else args[0]
            new_name = input("Enter new name> ")
        else:
            old_name = args[0]
            new_name = args[1]

        # Get longform name if input on shortform or raise exception if host not found
        old_name = resolve_input_name(old_name)

        # Fail if given host exists on either short or long form
        try:
            new_name = resolve_input_name(new_name)
        except HostNotFoundWarning:
            pass
        else:
            if "y" not in args:
                cli_warning("host {} already exists".format(new_name))

        # Always use long form host name. Require force if host not in MREG zone
        if is_longform(new_name):
            if not host_in_mreg_zone(new_name) and "y" not in args:
                cli_warning("{} isn't in a zone controlled by MREG, must force".format(new_name))
        else:
            new_name = to_longform(new_name)
        old_data = {"name": old_name}
        new_data = {"name": new_name}

        # Rename host
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], old_name)
        # Cannot redo/undo now since it changes name
        history.record_patch(url, new_data, old_data, redoable=False, undoable=False)
        patch(url, name=new_name)

        # Update all cname records pointing to <old-name>
        url = "http://{}:{}/cnames/?cname={}".format(
            conf["server_ip"],
            conf["server_port"],
            old_name,
        )
        history.record_get(url)
        cnames = get(url).json()
        for cname in cnames:
            url = "http://{}:{}/cnames/{}".format(
                conf["server_ip"],
                conf["server_port"],
                cname["id"],
            )
            old_data = {"cname": old_name}
            new_data = {"cname": new_name}
            history.record_patch(url, new_data, old_data)
            patch(url, cname=new_name)
        if len(cnames):
            cli_info("updated {} CNAME record(s) when renaming {} to {}".format(
                len(cnames),
                old_name,
                new_name,
            ))

        # Update all srv records pointing to <old-name>
        url = "http://{}:{}/srvs/?target={}".format(
            conf["server_ip"],
            conf["server_port"],
            old_name,
        )
        history.record_get(url)
        srvs = get(url).json()
        for srv in srvs:
            url = "http://{}:{}/srvs/{}".format(
                conf["server_ip"],
                conf["server_port"],
                srv["srvid"],
            )
            old_data = {"target": old_name}
            new_data = {"target": new_name}
            history.record_patch(url, new_data, old_data)
            patch(url, target=new_name)
        if len(srvs):
            cli_info("updated {} SRV record(s) when renaming {} to {}".format(
                len(srvs),
                old_name,
                new_name,
            ))
        cli_info("renamed {} to {}".format(old_name, new_name), print_msg=True)

    def opt_a_add(self, args: typing.List[str]) -> None:
        """
        a_add <name> <ip|subnet>
            Add an A record to host. If <name> is an alias the cname host is used.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip_or_net = input("Enter ip/subnet> ")
        else:
            name = args[0]
            ip_or_net = args[1]

        # Get host info for or raise exception
        info = host_info_by_name(name)

        # Require force if host has multiple A/AAAA records
        if len(info["ipaddress"]) and "y" not in args:
            cli_warning("{} already has A/AAAA record(s), must force".format(info["name"]))

        # Handle arbitrary ip from subnet if received a subnet w/o mask
        if re.match(r"^.*/$", ip_or_net):
            subnet = get_subnet(ip_or_net[:-1])
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            ip = available_ips_from_subnet(subnet).pop()

        # Handle arbitrary ip from subnet if received a subnet w/mask
        elif is_valid_subnet(ip_or_net):
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            ip = available_ips_from_subnet(subnet).pop()

        # Require force if given valid ip in subnet not controlled by MREG
        elif is_valid_ip(ip_or_net) and not ip_in_mreg_net(ip_or_net):
            if "y" not in args:
                cli_warning("{} isn't in a subnet controlled by MREG, must force".format(ip_or_net))
            else:
                ip = ip_or_net

        # Or else check that the address given isn't reserved
        else:
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            network_object = ipaddress.ip_network(subnet['range'])
            addresses = list(network_object.hosts())
            reserved_addresses = set([str(ip) for ip in addresses[:subnet['reserved']]])
            if ip_or_net in reserved_addresses and 'y' not in args:
                cli_warning("Address is reserved. Requires force")
            if ip_or_net == network_object.network_address.exploded:
                cli_warning("Can't overwrite the network address of the subnet")
            if ip_or_net == network_object.broadcast_address.exploded:
                cli_warning("Can't overwrite the broadcast address of the subnet")
            ip = ip_or_net

        # Fail if input isn't ipv4
        if is_valid_ipv6(ip):
            cli_warning("got ipv6 address, want ipv4.")
        if not is_valid_ipv4(ip):
            cli_warning("not valid ipv4 address: {}".format(ip))

        data = {
            "hostid": info["hostid"],
            "ipaddress": ip,
        }

        # Add A record
        url = "http://{}:{}/ipaddresses/".format(conf["server_ip"], conf["server_port"])
        history.record_post(url, ip, data)
        post(url, **data)
        cli_info("added ip {} to {}".format(ip, info["name"]), print_msg=True)

    def opt_a_remove(self, args: typing.List[str]) -> None:
        """
        a_remove <name> <ip>
            Remove A record from host. If <name> is an alias the cname host is used.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip = input("Enter ip> ")
        else:
            name = args[0]
            ip = args[1]

        # Ip sanity check
        if not is_valid_ipv4(ip):
            cli_warning("not a valid ipv4: \"{}\"".format(ip))

        # Check that ip belongs to host
        info = host_info_by_name(name)
        found = False
        for rec in info["ipaddress"]:
            if rec["ipaddress"] == ip:
                found = True
                break
        if not found:
            cli_warning("{} is not owned by {}".format(ip, info["name"]))

        old_data = {
            "hostid": info["hostid"],
            "ipaddress": ip,
        }

        # Remove ip
        url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"], conf["server_port"], ip)
        history.record_delete(url, old_data)
        delete(url)
        cli_info("removed ip {} from {}".format(ip, info["name"]), print_msg=True)

    def opt_a_change(self, args: typing.List[str]) -> None:
        """
        a_change <name> <old-ip> <new-ip-or-subnet>
            Change A record. If <name> is an alias the cname host is used.
        """
        if len(args) < 3:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            old_ip = input("Enter old ip> ") if len(args) < 2 else args[1]
            ip_or_net = input("Enter new ip/subnet> ")
        else:
            name = args[0]
            old_ip = args[1]
            ip_or_net = args[2]

        # Ip and subnet sanity checks
        if not is_valid_ipv4(old_ip):
            cli_warning("invalid ipv4 \"{}\" (target host {})".format(old_ip, name))
        elif not is_valid_ipv4(ip_or_net) and not is_valid_subnet(ip_or_net):
            cli_warning("invalid ipv4 nor subnet \"{}\" (target host {})".format(ip_or_net, name))

        # Check that ip belongs to host
        info = host_info_by_name(name)
        found = False
        for rec in info["ipaddress"]:
            if rec["ipaddress"] == old_ip:
                found = True
                break
        if not found:
            cli_warning("{} is not owned by {}".format(old_ip, info["name"]))

        # Handle arbitrary ip from subnet if received a subnet w/o mask
        if re.match(r"^.*/$", ip_or_net):
            subnet = get_subnet(ip_or_net[:-1])
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            ip = available_ips_from_subnet(subnet).pop()

        # Handle arbitrary ip from subnet if received a subnet w/mask
        elif is_valid_subnet(ip_or_net):
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            ip = available_ips_from_subnet(subnet).pop()

        # Require force if given valid ip in subnet not controlled by MREG
        elif is_valid_ip(ip_or_net) and not ip_in_mreg_net(ip_or_net):
            if "y" not in args:
                cli_warning("{} isn't in a subnet controlled by MREG, must force".format(ip_or_net))
            else:
                ip = ip_or_net

        # Or else check that the address given isn't reserved
        else:
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            network_object = ipaddress.ip_network(subnet['range'])
            addresses = list(network_object.hosts())
            reserved_addresses = set([str(ip) for ip in addresses[:subnet['reserved']]])
            if ip_or_net in reserved_addresses and 'y' not in args:
                cli_warning("Address is reserved. Requires force")
            if ip_or_net == network_object.network_address.exploded:
                cli_warning("Can't overwrite the network address of the subnet")
            if ip_or_net == network_object.broadcast_address.exploded:
                cli_warning("Can't overwrite the broadcast address of the subnet")
            ip = ip_or_net

        # Fail if input isn't ipv4
        if is_valid_ipv6(ip):
            cli_warning("got ipv6 address, want ipv4.")
        if not is_valid_ipv4(ip):
            cli_warning("not valid ipv4 address: {}".format(ip))

        old_data = {"ipaddress": old_ip}
        new_data = {"ipaddress": ip}

        # Update A record ip address
        url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"], conf["server_port"], old_ip)
        history.record_patch(url, new_data, old_data, redoable=False, undoable=False)
        patch(url, ipaddress=ip)
        cli_info("updated ip {} to {} for {}".format(old_ip, ip, info["name"]), print_msg=True)

    def opt_a_show(self, args: typing.List[str]) -> None:
        """
        a_show <name>
            Show hosts ipaddresses. If <name> is an alias the cname host is used.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_ipaddresses(info["ipaddress"])
        cli_info("showed ip addresses for {}".format(info["name"]))

    def opt_aaaa_add(self, args: typing.List[str]) -> None:
        """
        aaaa_add <name> <ipv6>
            Add an AAAA record to host. If <name> is an alias the cname host is used.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip_or_net = input("Enter ipv6> ")
        else:
            name = args[0]
            ip_or_net = args[1]

        # Get host info or raise exception
        info = host_info_by_name(name)

        if len(info["ipaddress"]) and "y" not in args:
            cli_warning("{} already has A/AAAA record(s), must force".format(info["name"]))

        # Handle arbitrary ip from subnet if received a subnet w/o mask
        if re.match(r"^.*/$", ip_or_net):
            subnet = get_subnet(ip_or_net[:-1])
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            ip = available_ips_from_subnet(subnet).pop()

        # Handle arbitrary ip from subnet if received a subnet w/mask
        elif is_valid_subnet(ip_or_net):
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            ip = available_ips_from_subnet(subnet).pop()

        # Require force if given valid ip in subnet not controlled by MREG
        elif is_valid_ip(ip_or_net) and not ip_in_mreg_net(ip_or_net):
            if "y" not in args:
                cli_warning("{} isn't in a subnet controlled by MREG, must force".format(ip_or_net))
            else:
                ip = ip_or_net

        # Or else check that the address given isn't reserved
        else:
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            network_object = ipaddress.ip_network(subnet['range'])
            addresses = list(network_object.hosts())
            reserved_addresses = set([str(ip) for ip in addresses[:subnet['reserved']]])
            if ip_or_net in reserved_addresses and 'y' not in args:
                cli_warning("Address is reserved. Requires force")
            if ip_or_net == network_object.network_address.exploded:
                cli_warning("Can't overwrite the network address of the subnet")
            if ip_or_net == network_object.broadcast_address.exploded:
                cli_warning("Can't overwrite the broadcast address of the subnet")
            ip = ip_or_net

        # Fail if input isn't ipv6
        if is_valid_ipv4(ip):
            cli_warning("got ipv4 address, want ipv6.")
        if not is_valid_ipv6(ip):
            cli_warning("not valid ipv6 address: {}".format(ip))

        data = {
            "hostid": info["hostid"],
            "ipaddress": ip,
        }

        # Create AAAA records
        url = "http://{}:{}/ipaddresses/".format(conf["server_ip"], conf["server_port"])
        history.record_post(url, ip, data)
        post(url, **data)
        cli_info("added ip {} to {}".format(ip, info["name"]), print_msg=True)

    def opt_aaaa_remove(self, args: typing.List[str]) -> None:
        """
        aaaa_remove <name> <ipv6>
            Remove AAAA record from host. If <name> is an alias the cname host is used.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip = input("Enter ipv6> ")
        else:
            name = args[0]
            ip = args[1]

        # Get host info or raise exception
        info = host_info_by_name(name)

        # Ipv6 sanity check
        if not is_valid_ipv6(ip):
            cli_warning("not a valid ipv6 \"{}\" (target host {})".format(ip, info["name"]))

        # Check that ip belongs to host
        found = False
        for rec in info["ipaddress"]:
            if rec["ipaddress"] == ip:
                found = True
                break
        if not found:
            cli_warning("{} is not owned by {}".format(ip, info["name"]))

        old_data = {
            "hostid": info["hostid"],
            "ipaddress": ip,
        }

        # Delete AAAA record
        url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"], conf["server_port"], ip)
        history.record_delete(url, old_data)
        delete(url)
        cli_info("removed {} from {}".format(ip, info["name"]), print_msg=True)

    def opt_aaaa_change(self, args: typing.List[str]) -> None:
        """
        aaaa_change <name> <old-ipv6> <new-ipv6>
            Change AAAA record. If <name> is an alias the cname host is used.
        """
        if len(args) < 3:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            old_ip = input("Enter old ipv6> ") if len(args) < 2 else args[1]
            ip_or_net = input("Enter new ipv6> ")
        else:
            name = args[0]
            old_ip = args[1]
            ip_or_net = args[2]

        # Get host info or raise exception
        info = host_info_by_name(name)

        # Handle arbitrary ip from subnet if received a subnet w/o mask
        if re.match(r"^.*/$", ip_or_net):
            subnet = get_subnet(ip_or_net[:-1])
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            new_ip = available_ips_from_subnet(subnet).pop()

        # Handle arbitrary ip from subnet if received a subnet w/mask
        elif is_valid_subnet(ip_or_net):
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            new_ip = available_ips_from_subnet(subnet).pop()

        # Require force if given valid ip in subnet not controlled by MREG
        elif is_valid_ip(ip_or_net) and not ip_in_mreg_net(ip_or_net):
            if "y" not in args:
                cli_warning("{} isn't in a subnet controlled by MREG, must force".format(ip_or_net))
            else:
                new_ip = ip_or_net

        # Or else check that the address given isn't reserved
        else:
            subnet = get_subnet(ip_or_net)
            if subnet["frozen"] and "y" not in args:
                cli_warning("subnet {} is frozen, must force".format(subnet["range"]))
            network_object = ipaddress.ip_network(subnet['range'])
            addresses = list(network_object.hosts())
            reserved_addresses = set([str(ip) for ip in addresses[:subnet['reserved']]])
            if ip_or_net in reserved_addresses and 'y' not in args:
                cli_warning("Address is reserved. Requires force")
            if ip_or_net == network_object.network_address.exploded:
                cli_warning("Can't overwrite the network address of the subnet")
            if ip_or_net == network_object.broadcast_address.exploded:
                cli_warning("Can't overwrite the broadcast address of the subnet")
            new_ip = ip_or_net

        # Fail if input isn't ipv6
        if not is_valid_ipv6(old_ip):
            cli_warning("not a valid ipv6 \"{}\" (target host {})".format(old_ip, info["name"]))
        elif is_valid_ipv4(new_ip):
            cli_warning("got ipv4 address, want ipv6.")
        elif not is_valid_ipv6(new_ip):
            cli_warning("not a valid ipv6 \"{}\" (target host {})".format(new_ip, info["name"]))

        # Check that ip belongs to host
        found = False
        for rec in info["ipaddress"]:
            if rec["ipaddress"] == old_ip:
                found = True
                break
        if not found:
            cli_warning("\"{}\" is not owned by {}".format(old_ip, info["name"]))

        old_data = {"ipaddress": old_ip}
        new_data = {"ipaddress": new_ip}

        # Update AAAA records ip address
        url = "http://{}:{}/ipaddresses/{}".format(conf["server_ip"], conf["server_port"], old_ip)
        # Cannot redo/undo since recourse name changes
        history.record_patch(url, new_data, old_data, redoable=False, undoable=False)
        patch(url, ipaddress=new_ip)
        cli_info("changed ip {} to {} for {}".format(old_ip, new_ip, info["name"]), print_msg=True)

    def opt_aaaa_show(self, args: typing.List[str]) -> None:
        """
        aaaa_show <name>
            Show hosts ipaddresses. If <name> is an alias the cname host is used.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_ipaddresses(info["ipaddress"])
        cli_info("showed aaaa records for {}".format(info["name"]))

    def opt_ttl_set(self, args: typing.List[str]) -> None:
        """
        ttl_set <name> <ttl>
            Set ttl for host. Valid values are 300 <= TTL <= 68400 or "default". If <name> is an
            alias the alias host is updated.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ttl = input("Enter ttl> ")
        else:
            name = args[0]
            ttl = args[1]

        # Get host info or raise exception
        info = host_info_by_name(name, follow_cnames=False)

        # TTL sanity check
        if not is_valid_ttl(ttl):
            cli_warning("invalid TTL value: {} (target host {})".format(ttl, info["name"]))

        old_data = {"ttl": info["ttl"] or -1}
        new_data = {"ttl": ttl if ttl != "default" else -1}

        # Update TTL
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, **new_data)
        cli_info("updated TTL for {}".format(info["name"]), print_msg=True)

    def opt_ttl_remove(self, args: typing.List[str]) -> None:
        """
        ttl_remove <name>
            Remove explicit TTL for host. If <name> is an alias the alias host is updated.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        old_data = {"ttl": info["ttl"]}
        new_data = {"ttl": -1}

        # Remove TTL value
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, ttl=-1)
        cli_info("removed TTL for {}".format(info["name"]), print_msg=True)

    def opt_ttl_show(self, args: typing.List[str]) -> None:
        """
        ttl_show <name>
            Show ttl for host. If <name> is an alias the alias hosts TTL is shown.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_ttl(info["ttl"])
        cli_info("showed TTL for {}".format(info["name"]))

    def opt_cname_add(self, args: typing.List[str]) -> None:
        """
        cname_add <existing-name> <new-alias>
            Add a CNAME record to host. If <existing-name> is an alias the cname host is used as
            target for <new-alias>.
        """
        if len(args) < 2:
            name = input("Enter name> ") if len(args) < 1 else args[0]
            alias = input("Enter alias> ")
        else:
            name = args[0]
            alias = args[1]

        # Get host info or raise exception
        info = host_info_by_name(name)

        # If alias name already exists the host cannot have any records
        try:
            alias_info = host_info_by_name(alias)
        except HostNotFoundWarning:
            alias_info = None
        else:
            if alias_info["hinfo"] or \
                    alias_info["loc"] or \
                    alias_info["cname"] or \
                    alias_info["ipaddress"] or \
                    alias_info["txt"] or\
                    alias_info["ptr_override"]:
                cli_warning("host {} already exists and has record(s)".format(alias_info["name"]))

        # Create cname host if it doesn't exist
        if not alias_info:
            alias = alias if is_longform(alias) else to_longform(alias)
            data = {
                "name": alias,
                "contact": info["contact"],
            }
            url = "http://{}:{}/hosts/".format(conf["server_ip"], conf["server_port"])
            history.record_post(url, alias, data)
            post(url, **data)
            alias_info = host_info_by_name(alias)

        # Create CNAME record
        url = "http://{}:{}/cnames/".format(conf["server_ip"], conf["server_port"])
        history.record_post(url, "", dict(), redoable=False, undoable=False)
        post(url, hostid=alias_info["hostid"], cname=info["name"])
        cli_info("Added cname alias {} for {}".format(alias_info["name"], info["name"]),
                 print_msg=True)

    def opt_cname_remove(self, args: typing.List[str]) -> None:
        """
        cname_remove <name> <alias-to-delete>
            Remove CNAME record.
        """
        if len(args) < 2:
            name = input("Enter name> ") if len(args) < 1 else args[0]
            alias = input("Enter alias> ")
        else:
            name = args[0]
            alias = args[1]

        # Get longform of input name, raise exception if host doesn't exist
        host_name = resolve_input_name(name)

        # Get host info or raise exception
        alias_info = host_info_by_name(alias, follow_cnames=False)

        # Check that cname host is an alias for host
        cnames = alias_info["cname"]
        if len(cnames) < 1:
            cli_warning("\"{}\" doesn't have any CNAME records.".format(alias_info["name"]))
        if cnames[0]["cname"] != host_name:
            cli_warning("\"{}\" is not an alias for \"{}\"".format(alias_info["name"], host_name))

        # Delete CNAME host
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"],
                                             alias_info["name"])
        history.record_delete(url, dict(), undoable=False)
        delete(url)
        cli_info("Removed cname alias {} for {}".format(alias_info["name"], host_name),
                 print_msg=True)

    def opt_cname_show(self, args: typing.List[str]) -> None:
        """
        cname_show <name>
            Show CNAME records for host. If <name> is an alias the cname hosts aliases are shown.
        """
        name = input("Enter name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        for alias in aliases_of_host(info["name"]):
            print_cname(alias, info["name"])
        cli_info("showed cname aliases for {}".format(info["name"]))

    def opt_loc_set(self, args: typing.List[str]) -> None:
        """
        loc_set <name> <loc>
            Set location of host. If <name> is an alias the cname host is updated.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            loc = input("Enter loc> ")
        else:
            name = args[0]
            loc = " ".join(args[1:])

        # LOC always require force
        if "y" not in args:
            cli_warning("require force to set location")

        # Get host info or raise exception
        info = host_info_by_name(name)

        # LOC sanity check
        if not is_valid_loc(loc):
            cli_warning("invalid LOC \"{}\" (target host {})".format(loc, info["name"]))

        old_data = {"loc": info["loc"] or ""}
        new_data = {"loc": loc}

        # Update LOC
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, loc=loc)
        cli_info("updated LOC to {} for {}".format(loc, info["name"]), print_msg=True)

    def opt_loc_remove(self, args: typing.List[str]) -> None:
        """
        loc_remove <name>
            Remove location from host. If <name> is an alias the cname host is updated.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]

        # LOC always require force
        if "y" not in args:
            cli_warning("require force to remove location")

        # Get host info or raise exception
        info = host_info_by_name(name)

        old_data = {"loc": info["loc"]}
        new_data = {"loc": ""}

        # Set LOC to null value
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, loc="")
        cli_info("removed LOC for {}".format(info["name"]), print_msg=True)

    def opt_loc_show(self, args: typing.List[str]) -> None:
        """
        loc_show <name>
            Show location of host. If <name> is an alias the cname hosts LOC is shown.
        """
        name = input("Enter name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_loc(info["loc"])
        cli_info("showed LOC for {}".format(info["name"]))

    def opt_hinfo_set(self, args: typing.List[str]) -> None:
        """
        hinfo_set <name> <hinfo>
            Set hinfo for host. If <name> is an alias the cname host is updated.
        """
        hi_list = hinfo_list()
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            hinfo = input("Enter hinfo> ")
            while hinfo == "?":
                print_hinfo_list(hi_list)
                hinfo = input("Enter hinfo> ")
        else:
            name = args[0]
            hinfo = args[1]

        # Hinfo sanity check
        hinfo = int(hinfo)
        if not 0 < hinfo <= len(hi_list):
            cli_warning("invalid hinfo.")

        # Get host info or raise exception
        info = host_info_by_name(name)
        old_data = {"hinfo": info["hinfo"] or -1}
        new_data = {"hinfo": hinfo}

        # Update hinfo
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, hinfo=hinfo)
        cli_info("updated hinfo to {} for {}".format(hinfo, info["name"]), print_msg=True)

    def opt_hinfo_remove(self, args: typing.List[str]) -> None:
        """
        hinfo_remove <name>
            Remove hinfo for host. If <name> is an alias the cname host is updated.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]

        # Get host info or raise exception
        info = host_info_by_name(name)

        old_data = {"hinfo": info["hinfo"]}
        new_data = {"hinfo": -1}

        # Set hinfo to null value
        url = "http://{}:{}/hosts/{}".format(conf["server_ip"], conf["server_port"], info["name"])
        history.record_patch(url, new_data, old_data)
        patch(url, hinfo=-1)
        cli_info("removed hinfo for {}".format(info["name"]), print_msg=True)

    def opt_hinfo_show(self, args: typing.List[str]) -> None:
        """
        hinfo_show <name>
            Show hinfo for host. If <name> is an alias the cname hosts hinfo is shown.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        if info["hinfo"]:
            print_hinfo(hinfo_id_to_strings(info["hinfo"]))
        cli_info("showed hinfo for {}".format(info["name"]))

    def opt_srv_add(self, args: typing.List[str]) -> None:
        """
        srv_add <service-name> <pri> <weight> <port> <target-name>
            Add SRV record.
        """
        if len(args) < 5:
            sname = input("Enter service name> ") if len(args) < 1 else args[0]
            pri = input("Enter priority> ") if len(args) < 2 else args[1]
            weight = input("Enter weight> ") if len(args) < 3 else args[2]
            port = input("Enter port> ") if len(args) < 4 else args[3]
            name = input("Enter target name> ")
        else:
            sname = args[0]
            pri = args[1]
            weight = args[2]
            port = args[3]
            name = args[4]

        # Require force if target host doesn't exist
        try:
            host_name = resolve_input_name(name)
        except HostNotFoundWarning:
            if "y" not in args:
                cli_warning("{} doesn't exist. Must force".format(name))
            host_name = name

        # Require force if target host not in MREG zone
        if not host_in_mreg_zone(host_name) and "y" not in args:
            cli_warning("{} isn't in a MREG controlled zone, must force".format(host_name))

        # Always use longform for service name
        sname = sname if is_longform(sname) else to_longform(sname, trailing_dot=True)

        # Check if a SRV record with identical service exists
        url = "http://{}:{}/srvs/?service={}".format(conf["server_ip"], conf["server_port"], sname)
        history.record_get(url)
        srvs = get(url).json()
        if len(srvs) > 0:
            entry_exists = True
        else:
            entry_exists = False

        data = {
            "service": sname,
            "priority": pri,
            "weight": weight,
            "port": port,
            "target": host_name,
        }

        # Create new SRV record
        url = "http://{}:{}/srvs/".format(conf["server_ip"], conf["server_port"])
        history.record_post(url, "", data, undoable=False)
        post(url, **data)
        if entry_exists:
            cli_info("Added SRV record {} with target {} to existing entry."
                     .format(sname, host_name), print_msg=True)
        else:
            cli_info("Added SRV record {} with target {}".format(sname, host_name), print_msg=True)

    def opt_srv_remove(self, args: typing.List[str]) -> None:
        """
        srv_remove <service-name>
            Remove SRV record.
        """
        sname = input("Enter service name> ") if len(args) < 1 else args[0]
        sname = sname if is_longform(sname) else to_longform(sname, trailing_dot=True)

        # Check if service exist
        url = "http://{}:{}/srvs/?service={}".format(conf["server_ip"], conf["server_port"], sname)
        history.record_get(url)
        srvs = get(url).json()
        if len(srvs) == 0:
            cli_warning("not service named {}".format(sname))
        elif len(srvs) > 1 and "y" not in args:
            cli_warning("multiple services named {}, must force".format(sname))

        # Remove all SRV records with that service
        for srv in srvs:
            assert isinstance(srv, dict)
            url = "http://{}:{}/srvs/{}".format(
                conf["server_ip"],
                conf["server_port"],
                srv["srvid"],
            )
            history.record_delete(url, srv, redoable=False)
            delete(url)
            cli_info("removed SRV record {} with target {}".format(srv["service"], srv["target"]),
                     print_msg=True)

    def opt_srv_show(self, args: typing.List[str]) -> None:
        """
        srv_show <service-name>
            Show SRV show. An empty input showes all existing SRV records
        """
        sname = input("Enter service name> ") if len(args) < 1 else args[0]

        # Get all matching SRV records
        url = "http://{}:{}/srvs/?service__contains={}".format(
            conf["server_ip"],
            conf["server_port"],
            sname,
        )
        history.record_get(url)
        srvs = get(url).json()
        if len(srvs) < 1:
            cli_warning("no service matching {}".format(sname))
        padding = 0

        # Print records
        for srv in srvs:
            if len(srv["service"]) > padding:
                padding = len(srv["service"])
        prev_name = ""
        for srv in sorted(srvs, key=lambda k: k["service"]):
            if prev_name == srv["service"]:
                srv["service"] = ""
            else:
                prev_name = srv["service"]
            print_srv(srv, padding)
        cli_info("showed entries for SRV {}".format(sname))

    def opt_txt_add(self, args: typing.List[str]) -> None:
        """
        txt_add <name> <text>
            Add a txt record to host. <text> must be enclosed in double quotes if it contains more
            than one word.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            text = input("Enter text> ")
        else:
            name = args[0]
            text = args[1]

        # Get host info or raise exception
        info = host_info_by_name(name)

        data = {
            "hostid": info["hostid"],
            "txt": text
        }

        # Add TXT record to host
        url = "http://{}:{}/txts/".format(conf["server_ip"], conf["server_port"])
        history.record_post(url, "", data, undoable=False)
        post(url, **data)
        cli_info("Added TXT record to {}".format(info["name"]), print_msg=True)

    def opt_txt_remove(self, args: typing.List[str]) -> None:
        """
        txt_remove <name> <text>
            Remove TXT record for host matching <text>.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            text = input("Enter text> ")
        else:
            name = args[0]
            text = args[1]

        # Get host info or raise exception
        info = host_info_by_name(name)

        # Check for matching TXT records for host
        url = "http://{}:{}/txts/?hostid={}&txt__contains={}".format(
            conf["server_ip"],
            conf["server_port"],
            info["hostid"],
            text,
        )
        history.record_get(url)
        txts = get(url).json()
        if len(txts) == 0:
            cli_warning("{} hasn't got any TXT records matching \"{}\"".format(info["name"], text))
        if len(txts) > 1 and "y" not in args:
            cli_warning("\"{}\" matched {} of {} TXT records. Must force.".format(
                text,
                len(args),
                info["name"],
            ))

        # Remove TXT records
        for txt in txts:
            url = "http://{}:{}/txts/{}".format(
                conf["server_ip"],
                conf["server_port"],
                txt["txtid"],
            )
            history.record_delete(url, txt)
            delete(url)
        cli_info("deleted {} of {} TXT records matching \"{}\"".format(
            len(args),
            info["name"],
            text
        ))

    def opt_txt_show(self, args: typing.List[str]) -> None:
        """
        txt_show <name>
            Show all TXT records for host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        url = "http://{}:{}/txts/?hostid={}".format(
            conf["server_ip"],
            conf["server_port"],
            info["hostid"],
        )
        history.record_get(url)
        txts = get(url).json()
        for txt in txts:
            print_txt(txt["txt"], padding=5)
        cli_info("showed TXT records for {}".format(info["name"]))

    def opt_ptr_set(self, args: typing.List[str]) -> None:
        """
        ptr_set <ipv4|ipv6> <name>
            Create a PTR record for host.
        """
        if len(args) < 2:
            ip = input("Enter ip> ") if len(args) < 1 else args[0]
            name = input("Enter host name> ")
        else:
            ip = args[0]
            name = args[1]

        # Ip sanity check
        if not is_valid_ip(ip):
            cli_warning("invalid ip: {}".format(ip))
        if not ip_in_mreg_net(ip):
            cli_warning("{} isn't in a subnet controlled by MREG".format(ip))

        # Get host info or raise exception
        info = host_info_by_name(name)

        # check that host haven't got a PTR record already
        if len(info["ptr_override"]):
            cli_warning("{} already got a PTR record".format(info["name"]))

        # check that a PTR record with the given ip doesn't exist
        url = "http://{}:{}/ptroverrides/?ipaddress={}".format(
            conf["server_ip"],
            conf["server_port"],
            ip,
        )
        history.record_get(url)
        ptrs = get(url).json()
        if len(ptrs):
            cli_warning("{} already exist in a PTR record".format(ip))

        # check if host is in mreg controlled zone, must force if not
        if not host_in_mreg_zone(info["name"]) and "y" not in args:
            cli_warning("{} isn't in a zone controlled by MREG, must force".format(info["name"]))

        # create PTR record
        data = {
            "hostid": info["hostid"],
            "ipaddress": ip,
        }
        url = "http://{}:{}/ptroverrides/".format(
            conf["server_ip"],
            conf["server_port"],
        )
        history.record_post(url, "", data, undoable=False)
        post(url, **data)
        cli_info("Added PTR record {} to {}".format(ip, info["name"]), print_msg=True)

    def opt_ptr_remove(self, args: typing.List[str]) -> None:
        """
        ptr_remove <ipv4|ipv6> <name>
            Remove PTR record from host.
        """
        if len(args) < 2:
            ip = input("Enter ip> ") if len(args) < 1 else args[0]
            name = input("Enter host name> ")
        else:
            ip = args[0]
            name = args[1]

        # Get host info or raise exception
        info = host_info_by_name(name)

        # Check that host got PTR record (assuming host got at most one record)
        if len(info["ptr_override"]) == 0:
            cli_warning("no PTR record for {} with ip {}".format(info["name"], ip))

        # Delete record
        url = "http://{}:{}/ptroverrides/{}".format(
            conf["server_ip"],
            conf["server_port"],
            info["ptr_override"][0]["id"],
        )
        history.record_delete(url, info["ptr_override"][0])
        delete(url)
        cli_info("deleted PTR record {} for {}".format(ip, info["name"]), print_msg=True)

    def opt_ptr_change(self, args: typing.List[str]) -> None:
        """
        ptr_change <ipv4|ipv6> <old-name> <new-name>
            Move PTR record from <old-name> to <new-name>.
        """
        if len(args) < 2:
            ip = input("Enter ip> ") if len(args) < 1 else args[0]
            old_name = input("Enter name of old host> ") if len(args) < 2 else args[1]
            new_name = input("Enter name of new host> ")
        else:
            ip = args[0]
            old_name = args[1]
            new_name = args[2]

        # Get host info or raise exception
        old_info = host_info_by_name(old_name)
        new_info = host_info_by_name(new_name)

        # check that new host haven't got a ptr record already
        if len(new_info["ptr_override"]):
            cli_warning("{} already got a PTR record".format(new_info["name"]))

        # check that old host has a PTR record with the given ip
        if not len(old_info["ptr_override"]):
            cli_warning("no PTR record for {} with ip {}".format(old_info["name"], ip))
        if old_info["ptr_override"][0]["ipaddress"] != ip:
            cli_warning("{} PTR record doesn't match {}".format(old_info["name"], ip))

        # change PTR record
        data = {
            "hostid": new_info["hostid"],
        }
        url = "http://{}:{}/ptroverrides/{}".format(
            conf["server_ip"],
            conf["server_port"],
            old_info["ptr_override"][0]["id"],
        )
        history.record_patch(url, data, old_info["ptr_override"][0])
        patch(url, **data)
        cli_info("changed owner of PTR record {} from {} to {}".format(
            ip,
            old_info["name"],
            new_info["name"],
        ), print_msg=True)

    def opt_ptr_show(self, args: typing.List[str]) -> None:
        """
        ptr_show <ipv4|ipv6>
            Show PTR record matching given ip (empty input shows all PTR records).
        """
        ip = input("Enter ip address> ") if len(args) < 1 else args[0]

        url = "http://{}:{}/ptroverrides/".format(
            conf["server_ip"],
            conf["server_port"],
        )
        history.record_get(url)
        ptrs = get(url).json()

        padding = 0
        for ptr in ptrs:
            if ip in ptr["ipaddress"]:
                if len(ptr["ipaddress"]) > padding:
                    padding = len(ptr["ipaddress"])

        for ptr in ptrs:
            if ip in ptr["ipaddress"]:
                url = "http://{}:{}/hosts/?hostid={}".format(
                    conf["server_ip"],
                    conf["server_port"],
                    ptr["hostid"],
                )
                history.record_get(url)
                hosts = get(url).json()
                if not hosts:
                    cli_error("{} PTR records host (hostid: {}) doesn't exist."
                              .format(ip, ptr["hostid"]))
                print_ptr(ptr["ipaddress"], hosts[0]["name"], padding)
        cli_info("showed PTR records matching {}".format(ip))

    def opt_naptr_add(self, args: typing.List[str]) -> None:
        """
        naptr_add <name> <preference> <order> <flagg> <service> <regexp> <replacement>
            Add a NAPTR record to host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        pref = input("Enter preference> ") if len(args) < 2 else args[1]
        order = input("Enter order> ") if len(args) < 3 else args[2]
        flag = input("Enter flag> ") if len(args) < 4 else args[3]
        service = input("Enter service> ") if len(args) < 5 else args[4]
        regex = input("Enter rexexp> ") if len(args) < 6 else args[5]
        repl = input("Enter replacement> ") if len(args) < 7 else args[6]

        # Get host info or raise exception
        info = host_info_by_name(name)

        data = {
            "preference": int(pref),
            "orderv": int(order),
            "flag": flag,
            "service": service,
            "regex": regex,
            "replacement": repl,
            "hostid": info["hostid"],
        }

        # Create NAPTR record
        url = "http://{}:{}/naptrs/".format(
            conf["server_ip"],
            conf["server_port"],
        )
        history.record_post(url, "", data, undoable=False)
        post(url, **data)
        cli_info("created NAPTR record for {}".format(info["name"]), print_msg=True)

    def opt_naptr_remove(self, args: typing.List[str]) -> None:
        """
        naptr_remove <name> <replacement>
            Remove NAPTR record.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        repl = input("Enter replacement> ") if len(args) < 2 else args[1]

        # Get host info or raise exception
        info = host_info_by_name(name)

        # get the hosts NAPTR records where repl is a substring of the replacement field
        url = "http://{}:{}/naptrs/?replacement__contains={}&hostid={}".format(
            conf["server_ip"],
            conf["server_port"],
            repl,
            info["hostid"]
        )
        history.record_get(url)
        naptrs = get(url).json()
        if not len(naptrs):
            cli_warning("{} hasn't got any NAPTR reocrds matching \"{}\"".format(
                info["name"],
                repl,
            ))
        if len(naptrs) > 1 and "y" not in args:
            cli_warning("{} got {} NAPTR records matching \"{}\", must force.".format(
                info["name"],
                len(naptrs),
                repl,
            ))

        # Delete NAPTR record(s)
        for ptr in naptrs:
            url = "http://{}:{}/naptrs/{}".format(
                conf["server_ip"],
                conf["server_port"],
                ptr["naptrid"],
            )
            history.record_delete(url, ptr)
            delete(url)
        cli_info("deleted {} NAPTR record(s) for {}".format(len(naptrs), info["name"]),
                 print_msg=True)

    def opt_naptr_show(self, args: typing.List[str]) -> None:
        """
        naptr_show <name>
            Show all NAPTR records for host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        url = "http://{}:{}/naptrs/?hostid={}".format(
            conf["server_ip"],
            conf["server_port"],
            info["hostid"],
        )
        history.record_get(url)
        naptrs = get(url).json()
        for ptr in naptrs:
            print_naptr(ptr, info["name"])
        cli_info("showed {} NAPTR records for {}".format(len(naptrs), info["name"]))


class Dhcp(CommandBase):
    """
    Handle MAC addresses.
        dhcp <option> <argument(s)>
    """

    def opt_assoc(self, args: typing.List[str]) -> None:
        """
        assoc <name|ip> <mac-addr>
            Associate MAC address with host. If host got multiple A/AAAA records an IP must be
            given instead of name.
        """
        name_or_ip = input("Enter host name/ip> ") if len(args) < 1 else args[0]
        addr = input("Enter MAC address> ") if len(args) < 2 else args[1]

        # MAC addr sanity check
        if not is_valid_mac_addr(addr):
            cli_warning("invalid MAC address: {}".format(addr))

        # Get A/AAAA record by either ip address or host name
        if is_valid_ip(name_or_ip):
            url = "http://{}:{}/ipaddresses/{}".format(
                conf["server_ip"],
                conf["server_port"],
                name_or_ip,
            )
            history.record_get(url)
            ip = get(url).json()
            if not len(ip):
                cli_warning("ip {} doesn't exist.".format(name_or_ip))
        else:
            info = host_info_by_name(name_or_ip)
            if len(info["ipaddress"]) > 1:
                cli_warning("{} got {} ip addresses, please enter an ip instead.".format(
                    info["name"],
                    len(info["ipaddress"]),
                ))
            ip = info["ipaddress"][0]

        # Update A/AAAA record
        url = "http://{}:{}/ipaddresses/{}".format(
            conf["server_ip"],
            conf["server_port"],
            ip["ipaddress"],
        )
        history.record_patch(url, new_data={"macaddress": addr}, old_data=ip)
        patch(url, macaddress=addr)
        cli_info("associated mac address {} with ip {}".format(addr, ip["ipaddress"]),
                 print_msg=True)

    def opt_disassoc(self, args: typing.List[str]) -> None:
        """
        disassoc <name|ip>
            Disassociate MAC address with host/ip. If host got multiple A/AAAA records an IP must be
            given instead of name
        """
        name_or_ip = input("Enter host name/ip> ") if len(args) < 1 else args[0]

        # Get A/AAAA record by either ip address or host name
        if is_valid_ip(name_or_ip):
            url = "http://{}:{}/ipaddresses/{}".format(
                conf["server_ip"],
                conf["server_port"],
                name_or_ip,
            )
            history.record_get(url)
            ip = get(url).json()
            if not len(ip):
                cli_warning("ip {} doesn't exist.".format(name_or_ip))
        else:
            info = host_info_by_name(name_or_ip)
            if len(info["ipaddress"]) > 1:
                cli_warning("{} got {} ip addresses, please enter an ip instead.".format(
                    info["name"],
                    len(info["ipaddress"]),
                ))
            ip = info["ipaddress"][0]

        # Update A/AAAA record
        url = "http://{}:{}/ipaddresses/{}".format(
            conf["server_ip"],
            conf["server_port"],
            ip["ipaddress"],
        )
        history.record_patch(url, new_data={"macaddress": ""}, old_data=ip)
        patch(url, macaddress="")
        cli_info("disassociated mac address {} from ip {}".format(
            ip["macaddress"],
            ip["ipaddress"]
        ), print_msg=True)


class Zone(CommandBase):
    """
    Handle zones.
        zone <option> <argument(s)>
    """

    def opt_create(self, args: typing.List[str]):
        """
        create <zone-name> (<nameservers>)
            Create new zone.
        """
        # TODO Validation for valid domain names
        force = False
        arguments = args
        if len(args) > 0 and args[-1] == 'y':
            force = True
            arguments = args[:-1]

        name = input("Enter zone name>") if len(arguments) < 1 else arguments[0]
        if not name:
            cli_warning('Name is required')

        nameservers = input("Enter nameservers>") if len(arguments) < 2 else arguments[1:]
        if isinstance(nameservers, str):
            nameservers = nameservers.split(' ')

        if not nameservers:
            cli_warning('At least one nameserver is required')

        for i in range(len(nameservers)):
            info = host_info_by_name(nameservers[i])
            if host_in_mreg_zone(info['name']):
                if not info['ipaddress'] and not force:
                    cli_warning("{} has no A-record/glue, must force".format(nameservers[i]))
            nameservers[i] = info['name']

        url = "http://{}:{}/zones/".format(conf["server_ip"], conf["server_port"])
        post(url, name=name, nameservers=nameservers)
        cli_info("created zone {}".format(name), True)

    def opt_delete(self, args: typing.List[str]):
        """
            delete <zone-name>
                Delete a zone
        """
        name = input("Enter zone name>") if len(args) < 1 else args[0]

        url_zone = "http://{}:{}/zones/{}".format(conf["server_ip"], conf["server_port"], name)
        zone = get(url_zone)

        url_hosts = "http://{}:{}/hosts/?name__endswith={}".format(conf["server_ip"], conf["server_port"], name)
        url_zones = "http://{}:{}/zones/?name__endswith={}".format(conf["server_ip"], conf["server_port"], name)

        hosts = get(url_hosts).json()
        zones = get(url_zones).json()

        if hosts and 'y' not in args:
            cli_warning("Zone has registered entries, must force")
        if zones and 'y' not in args:
            cli_warning("Zone has registered subzones, must force")

        for zone in zones:
            url_zone = "http://{}:{}/zones/{}".format(conf["server_ip"], conf["server_port"], zone['name'])
            delete(url_zone)
            cli_info("deleted zone {}".format(zone['name']), True)

    def opt_set_ns(self, args: typing.List[str]):
        """
              set_ns <zone-name> (<nameservers>)
                  Update nameservers for an existing zone.
        """
        # TODO Validation for valid domain names
        force = False
        arguments = args
        if len(args) > 0 and args[-1] == 'y':
            force = True
            arguments = args[:-1]

        name = input("Enter zone name>") if len(arguments) < 1 else arguments[0]
        if not name:
            cli_warning('Name is required')

        nameservers = input("Enter nameservers>") if len(arguments) < 2 else arguments[1:]
        if isinstance(nameservers, str):
            nameservers = nameservers.split(' ')

        if not nameservers:
            cli_warning('At least one nameserver is required')

        for i in range(len(nameservers)):
            info = host_info_by_name(nameservers[i])
            if host_in_mreg_zone(info['name']):
                if not info['ipaddress'] and not force:
                    cli_warning("{} has no A-record/glue, must force".format(nameservers[i]))
            nameservers[i] = info['name']

        url = "http://{}:{}/zones/{}/nameservers".format(conf["server_ip"], conf["server_port"], name)
        patch(url, nameservers=nameservers)
        cli_info("updated nameservers for {}".format(name), True)

    def opt_set_soa(self, args: typing.List[str]):
        """
              set_soa <zone-name> (<primary_ns> <email> <serialno> <refresh> <retry> <expire> <ttl>)
                  Updated the SOA of a zone.
        """
        #TODO Validation for valid domain names
        name = input("Enter zone name>") if len(args) < 1 else args[0]
        primary_ns = input("Enter primary_ns>") if len(args) < 2 else args[1]
        email = input("Enter email>") if len(args) < 3 else args[2]
        serialno = input("Enter serialno>") if len(args) < 4 else args[3]
        refresh = string_to_int(input("Enter refresh>") if len(args) < 5 else args[4], "refresh")
        retry = string_to_int(input("Enter retry>") if len(args) < 6 else args[5], "retry")
        expire = string_to_int(input("Enter expire>") if len(args) < 7 else args[6], "expire")
        ttl = string_to_int(input("Enter TTL>") if len(args) < 8 else args[7], "ttl")

        url = "http://{}:{}/zones/{}".format(conf["server_ip"], conf["server_port"], name)
        zone = get(url).json()
        nameservers = zone['nameservers']
        if primary_ns not in [nameserver['name'] for nameserver in nameservers]:
            cli_warning("{} is not one of {}'s nameservers. Add it with set_ns before trying again".format(primary_ns, name))

        url = "http://{}:{}/zones/{}".format(conf["server_ip"], conf["server_port"], name)
        patch(url, primary_ns=primary_ns, email=email, serialno=serialno, refresh=refresh, retry=retry, expire=expire, ttl=ttl)
        cli_info("set soa for {}".format(name), True)


class Subnet(CommandBase):
    """
    Handle subnets.
        subnet <option> <argument(s)>
    """

    def opt_info(self, args: typing.List[str]):
        """
        info <subnet>
            Display subnet info
        """
        if len(args) < 1:
            ip_range = input("Enter subnet> ")
        else:
            ip_range = args[0]

        # Get subnet info or raise exception
        subnet_info = get_subnet(ip_range)
        used_list = get_subnet_used_list(subnet_info['range'])
        network = ipaddress.ip_network(subnet_info['range'])

        # Pretty print all subnet info
        print_subnet(subnet_info['range'], "Subnet:")
        print_subnet(network.netmask.exploded, "Netmask:")
        print_subnet(subnet_info['description'], "Description:")
        print_subnet(subnet_info['category'], "Category:")
        print_subnet(subnet_info['location'], "Location:")
        print_subnet(subnet_info['vlan'], "VLAN")
        print_subnet(subnet_info['dns_delegated'] if subnet_info['dns_delegated'] else False, "DNS delegated:")
        print_subnet(subnet_info['frozen'] if subnet_info['frozen'] else False, "Frozen")
        print_subnet_reserved(subnet_info['range'], subnet_info['reserved'])
        print_subnet(len(used_list), "Used addresses:")
        print_subnet_unused(network.num_addresses - (subnet_info['reserved'] + 2) - len(used_list))
        cli_info("printed subnet info for {}".format(subnet_info['range']))

    def opt_create(self, args: typing.List[str]):
        """
        create <subnet> <description> <vlan> <dns_delegated> <category> <location> <frozen>
            Create a new subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet_new = ipaddress.ip_network(ip_range)
        description = input("Enter description>") if len(args) < 2 else args[1]
        if not description:
            cli_warning("No description provided")

        vlan = None
        category = None
        location = None
        frozen = False

        if len(args) != 2:
            vlan = input("Enter VLAN (optional)>") if len(args) < 3 else args[2]
            category = input("Enter category (optional)>") if len(args) < 4 else args[3]
            location = input("Enter location (optional)>") if len(args) < 5 else args[4]

            if vlan:
                string_to_int(vlan, "VLAN")
            if category and not is_valid_category_tag(category):
                cli_warning("Not a valid category tag")
            if location and not is_valid_location_tag(location):
                cli_warning("Not a valid location tag")
            frozen = input("Is the subnet frozen? y/n>") if len(args) < 6 else args[5]
            while frozen != 'y' and frozen != 'n':
                frozen = input("Is the subnet frozen? y/n>")
            frozen = True if frozen == 'y' else False

        url = "http://{}:{}/subnets/".format(conf["server_ip"], conf["server_port"])
        subnets_existing =  get(url).json()
        for subnet in subnets_existing:
            subnet_object = ipaddress.ip_network(subnet['range'])
            if subnet_object.overlaps(subnet_new):
                cli_warning( "Overlap found between new subnet {} and existing subnet {}".format(subnet_new, subnet['range']))

        url = "http://{}:{}/subnets/".format(conf["server_ip"], conf["server_port"])
        post(url, range=ip_range, description=description, vlan=vlan, category=category,
             location=location, frozen=frozen)
        cli_info("created subnet {}".format(ip_range), True)

    def opt_remove(self, args: typing.List[str]):
        """
        remove <subnet>
            Remove subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        ipaddress.ip_network(ip_range)

        host_list = get_subnet_used_list(ip_range)
        if host_list:
            cli_warning("Subnet contains addresses that are in use. Remove hosts before deletion")

        if 'y' not in args:
            cli_warning("Must force (y)")

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"], ip_range)
        delete(url)
        cli_info("removed subnet {}".format(ip_range), True)

    def opt_set_vlan(self, args: typing.List[str]):
        """
        set_vlan <subnet> <vlan>
            Set VLAN for subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)
        vlan = string_to_int(input("Enter new VLAN>") if len(args) < 2 else args[1], "VLAN")

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, vlan=vlan)
        cli_info("updated vlan to {} for {}".format(vlan, subnet['range']))

    def opt_set_description(self, args: typing.List[str]):
        """
        set_description <subnet> <description>
            Set description for subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)
        description = input("Enter new description>") if len(args) < 2 else args[1]
        if not description:
            cli_warning("No description")

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, description=description)
        cli_info("updated description to '{}' for {}".format(description, subnet['range']), True)

    def opt_set_location(self, args: typing.List[str]):
        """
        set_location <subnet> <location_tag>
            Set location tag for subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)
        location_tag = input("Enter new location tag>") if len(args) < 2 else args[1]
        if not is_valid_location_tag(location_tag):
            cli_warning("Not a valid location tag")

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, location=location_tag)
        cli_info("updated location tag to '{}' for {}".format(location_tag, subnet['range']), True)

    def opt_set_category(self, args: typing.List[str]):
        """
        set_category <subnet> <category_tag>
            Set category tag for subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)
        category_tag = input("Enter new category tag>") if len(args) < 2 else args[1]
        if not is_valid_category_tag(category_tag):
            cli_warning("Not a valid category tag")

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, category=category_tag)
        cli_info("updated category tag to '{}' for {}".format(category_tag, subnet['range']), True)

    def opt_set_dns_delegated(self, args: typing.List[str]):
        """
        set_dns_delegated <subnet>
            Set that DNS-administration is being handled elsewhere.
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, dns_delegated=True)
        cli_info("updated dns_delegated to '{}' for {}".format(True, subnet['range']), True)

    def opt_unset_dns_delegated(self, args: typing.List[str]):
        """
        unset_dns_delegated <subnet>
            Set that DNS-administration is not being handled elsewhere.
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, dns_delegated=False)
        cli_info("updated dns_delegated to '{}' for {}".format(False, subnet['range']), True)

    def opt_set_frozen(self, args: typing.List[str]):
        """
        set_frozen <subnet>
            Freeze a subnet.
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, frozen=True)
        cli_info("updated frozen to '{}' for {}".format(True, subnet['range']), True)

    def opt_unset_frozen(self, args: typing.List[str]):
        """
        unset_frozen <subnet>
            Unfreeze a subnet.
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"],
                                               subnet['range'])
        patch(url, frozen=False)
        cli_info("updated frozen to '{}' for {}".format(False, subnet['range']), True)

    def opt_set_reserved(self, args: typing.List[str]):
        """
        set_reserved <subnet> <number>
            Set number of reserved hosts.
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]
        subnet = get_subnet(ip_range)
        reserved = string_to_int(input("Enter number of reserved hosts>"), "Reserved")

        url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"], subnet['range'])
        patch(url, reserved=reserved)
        cli_info("updated reserved to '{}' for {}".format(reserved, subnet['range']), True)

    def opt_list_used_addresses(self, args: typing.List[str]):
        """
        list_used_addresses <subnet>
            Lists all the used addresses for a subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]

        if is_valid_ip(ip_range):
            subnet = get_subnet(ip_range)
            addresses = get_subnet_used_list(subnet['range'])
        elif is_valid_subnet(ip_range):
            addresses = get_subnet_used_list(ip_range)
        else:
            cli_warning("Not a valid ip or subnet")

        hosts = []
        for address in addresses:
            hosts.append(resolve_ip(address))

        for x in range(len(addresses)):
            print("{1:<{0}}{2}".format(25, addresses[x], hosts[x]))

    def opt_list_unused_addresses(self, args: typing.List[str]):
        """
        list_used_addresses <subnet>
            Lists all the used addresses for a subnet
        """
        ip_range = input("Enter subnet>") if len(args) < 1 else args[0]

        if is_valid_ip(ip_range):
            subnet = get_subnet(ip_range)
            addresses = get_subnet_used_list(subnet['range'])
        elif is_valid_subnet(ip_range):
            addresses = get_subnet_used_list(ip_range)
        else:
            cli_warning("Not a valid ip or subnet")

        unused_addresses = available_ips_from_subnet(subnet)

        for address in unused_addresses:
            print("{1:<{0}}".format(25, address))

    def opt_import(self, args: typing.List[str]):
        """
        import <file>
            Import subnet data from <file>.
        """
        input_file = input("Enter path to import file>") if len(args) < 1 else args[0]
        if not input_file:
            cli_warning("No file path")
        log_file = open('subnets_import.log', 'w+')
        vlans = get_vlan_mapping()
        ERROR = False  # Flag to check before making requests if something isn't right

        log_file.write("------ READ FROM {} START ------\n".format(input_file))

        # Read in new subnet structure from file
        import_data = {}
        with open(input_file, 'r') as file:
            line_number = 0
            for line in file:
                line_number += 1
                match = re.match(
                    r"(?P<range>\d+.\d+.\d+.\d+\/\d+)\s+:(?P<tags>.*):\|(?P<description>.*)", line)
                if match:
                    tags = match.group('tags').split(':')
                    info = {'location': None, 'category': ''}
                    for tag in tags:
                        if is_valid_location_tag(tag):
                            info['location'] = tag
                        elif is_valid_category_tag(tag):
                            info['category'] = ('%s %s' % (info['category'], tag)).strip()
                        else:
                            # TODO ERROR = True ?
                            log_file.write(
                                "{}: Invalid tag {}. Valid tags can be found in {}\n".format(
                                    line_number, tag, conf['tag_file']))
                    data = {
                        'range': match.group('range'),
                        'description': match.group('description').strip(),
                        'vlan': vlans[match.group('range')] if match.group('range') in vlans else 0,
                        'category': info['category'] if info['category'] else None,
                        'location': info['location'] if info['location'] else None,
                        'frozen': False
                    }
                    import_data['%s' % match.group('range')] = data

        log_file.write("------ READ FROM {} END ------\n".format(input_file))

        # Fetch existing subnets from server
        res = requests.get(
            'http://{}:{}/subnets'.format(conf["server_ip"], conf["server_port"])).json()
        current_subnets = {subnet['range']: subnet for subnet in res}

        subnets_delete = current_subnets.keys() - import_data.keys()
        subnets_post = import_data.keys() - current_subnets.keys()
        subnets_patch = set()
        subnets_ignore = import_data.keys() & current_subnets.keys()

        # Check if subnets marked for deletion have any addresses in use
        for subnet in subnets_delete:
            used_list = get_subnet_used_list(subnet)
            if used_list:
                ERROR = True
                log_file.write(
                    "WARNING: {} contains addresses that are in use. Remove hosts before deletion\n".format(
                        {subnet['range']}))

        # Check if subnets marked for creation have any overlap with existing subnets
        for subnet_new in subnets_post:
            subnet_object = ipaddress.ip_network(subnet_new)
            for subnet_existing in subnets_ignore:
                if subnet_object.overlaps(ipaddress.ip_network(subnet_existing)):
                    ERROR = True
                    log_file.write(
                        "ERROR: Overlap found between new subnet {} and existing subnet {}\n".format(
                            subnet_new, subnet_existing))

        # Check which existing subnets need to be patched
        for subnet in subnets_ignore:
            current_data = current_subnets[subnet]
            new_data = import_data[subnet]
            if (new_data['description'] != current_data['description'] \
                    or new_data['vlan'] != current_data['vlan'] \
                    or new_data['category'] != current_data['category'] \
                    or new_data['location'] != current_data['location']):
                subnets_patch.add(subnet)

        if ERROR:
            cli_warning("Errors detected during setup. Check subnets_import.log for details")

        if ((len(subnets_delete) + len(subnets_patch)) / len(
                current_subnets.keys())) > 0.2 and 'y' not in args:
            cli_warning("WARNING: The import will change over 20% of the subnets. Requires force")

        log_file.write("------ API REQUESTS START ------\n".format(input_file))

        for subnet in subnets_delete:
            url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"], subnet)
            delete(url)
            log_file.write("DELETE {}\n".format(url))

        for subnet in subnets_post:
            url = "http://{}:{}/subnets/".format(conf["server_ip"], conf["server_port"])
            data = import_data[subnet]
            post(url, range=data['range'], \
                 description=data['description'], \
                 vlan=data['vlan'], \
                 category=data['category'], \
                 location=data['location'], \
                 frozen=data['frozen'])
            log_file.write("POST {} - {}\n".format(url, subnet))

        for subnet in subnets_patch:
            url = "http://{}:{}/subnets/{}".format(conf["server_ip"], conf["server_port"], subnet)
            data = import_data[subnet]
            patch(url, description=data['description'], \
                  vlan=data['vlan'], \
                  category=data['category'], \
                  location=data['location'])
            log_file.write("PATCH {}\n".format(url))

        log_file.write("------ API REQUESTS END ------\n".format(input_file))
