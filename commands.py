import traceback
import inspect
import re
import types
import typing
import requests

from util import *
from config import *

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
    Base class of all commands for the mreg client. It provide functions which uses insight to
    auto-generate documentation and cli-info.

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
        """Returns all options of this command, identified by function prefix "opt_\""""
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

class Host(CommandBase):
    """
    Create, delete or edit host.
        host <option> <argument(s)>
    """

    # TODO CNAME håndtering. cname må være unik og peke til andre hosts

    def opt_info(self, args: typing.List[str]) -> None:
        """
        info <name|ip>
            Print information about host.
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
        cli_info("printed host info for {}".format(info["name"]))

    def opt_remove(self, args: typing.List[str]) -> None:
        """
        remove <name|ip>
            Remove host.
        """
        if len(args) < 1:
            name_or_ip = input("Enter name or ip> ")
        else:
            name_or_ip = args[0]

        # Require force if host has multiple A/AAAA records or any CNAME, SRV or NAPTR records.
        info = host_info_by_name_or_ip(name_or_ip)
        if "y" not in args:
            # TODO FORCE: kreve force hvis host har: flere A-records eller CNAME, SRV eller NAPTR pekende på seg
            pass

        # Delete host
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], info["name"])
        delete(url)
        cli_info("deleted {}".format(info["name"]))

    def opt_add(self, args: typing.List[str]) -> None:
        """
        add <name> <ip/net> <contact> [-hinfo <hinfo>] [-comment <comment>]
            Add a new host with the given name, ip or subnet and contact. hinfo and comment
            are optional.
        """
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
                cli_warning("invalid hinfo.")

        # Handle arbitrary ip from subnet if received a subnet
        if re.match(r"^.*([.:]0|::)/$", ip_or_net) or is_valid_subnet(ip_or_net):
            # TODO SUBNET: handle random ip address
            ip = choose_ip_from_subnet(ip_or_net)
        else:
            ip = ip_or_net

        # Check if given host exists on either short or long form
        try:
            resolve_input_name(name)
        except HostNotFoundWarning:
            pass
        else:
            if "y" not in args:
                cli_warning("host \"{}\" already exists, must force".format(name))

        # Contact sanity check
        if not is_valid_email(contact):
            cli_warning("invalid mail address \"{}\"".format(contact))

        # Always use long form host name
        host_name = name if is_longform(name) else to_longform(name)

        # Create the new host with an ip address
        host_url = "http://{}:{}/hosts/".format(conf["server_ip"], conf["server_port"])
        post(host_url, name=host_name, ipaddress=ip, contact=contact or None,
             hinfo=hinfo or None, comment=comment or None)
        cli_info("created host \"{}\"".format(host_name))

    def opt_set_contact(self, args: typing.List[str]) -> None:
        """
        set_contact <name> <contact>
            Set contact for host.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            contact = input("Enter contact> ")
        else:
            name = args[0]
            contact = args[1]

        # Contact sanity check
        if not is_valid_email(contact):
            cli_warning("invalid mail address: \"{}\"".format(contact))

        # Update contact information
        host_name = resolve_input_name(name)
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, contact=contact)
        cli_info("Updated contact")

    def opt_set_comment(self, args: typing.List[str]) -> None:
        """
        set_comment <name> <comment>
            Set comment for host.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            comment = input("Enter comment> ")
        else:
            name = args[0]
            comment = " ".join(args[1:])

        # Update comment
        host_name = resolve_input_name(name)
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, comment=comment)
        cli_info("{}: Updated comment.".format(host_name))

    def opt_rename(self, args: typing.List[str]) -> None:
        """
        rename <old-name> <new-name>
            Rename host.
        """
        if len(args) < 2:
            old_name = input("Enter old name> ") if len(args) < 1 else args[0]
            new_name = input("Enter new name> ")
        else:
            old_name = args[0]
            new_name = args[1]

        host_name = resolve_input_name(old_name)

        # Require force if the new name is already in use
        try:
            resolve_input_name(new_name)
        except HostNotFoundWarning:
            pass
        else:
            cli_warning("host \"{}\" already exists, must force (y)".format(name))

        # Always use long form host name
        new_name = new_name if is_longform(new_name) else to_longform(new_name)

        # Rename host
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, name=new_name)
        cli_info("{}: Changed name.".format(host_name))

    def opt_a_add(self, args: typing.List[str]) -> None:
        """
        a_add <name> <ip|subnet>
            Add an A record to host.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip_or_subnet = input("Enter ip/subnet> ")
        else:
            name = args[0]
            ip_or_subnet = args[1]

        # Verify host and get host id
        info = host_info_by_name(name)
        host_id = info["hostid"]

        # Verify ip or get ip from subnet
        if is_valid_ipv4(ip_or_subnet):
            ip = ip_or_subnet
        elif is_valid_subnet(ip_or_subnet):
            # TODO SUBNET: choose random ip (?)
            cli_warning("subnets not implemented")
            ip = ip_or_subnet
        else:
            cli_warning("not a valid ipv4 nor subnet: \"{}\"".format(ip_or_subnet))

        # Add A record
        url = "http://{}:{}/ipaddresses/".format(conf["server_ip"], conf["server_port"])
        post(url, hostid=host_id, ipaddress=ip)
        cli_info("Created ipaddress.")

    def opt_a_remove(self, args: typing.List[str]) -> None:
        """
        a_remove <name> <ip>
            Remove A record from host.
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
            cli_warning("\"{}\" is not owned by {}".format(ip, info["name"]))

        # Remove ip
        url = "http://{}:{}/ipaddresses/{}/".format(conf["server_ip"], conf["server_port"], ip)
        delete(url)
        cli_info("Removed ipaddress.")

    def opt_a_change(self, args: typing.List[str]) -> None:
        """
        a_change <name> <old-ip> <new-ip-or-subnet>
            Change A record.
        """
        if len(args) < 3:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            old_ip = input("Enter old ip> ") if len(args) < 2 else args[1]
            ip_or_subnet = input("Enter new ip/subnet> ")
        else:
            name = args[0]
            old_ip = args[1]
            ip_or_subnet = args[2]

        # Ip and subnet sanity checks
        if not is_valid_ipv4(old_ip):
            cli_warning("not a valid ipv4: \"{}\"".format(old_ip))
        elif not is_valid_ipv4(ip_or_subnet) and not is_valid_subnet(ip_or_subnet):
            cli_warning("not a valid ipv4 nor subnet: \"{}\"".format(ip_or_subnet))

        # Check that ip belongs to host
        info = host_info_by_name(name)
        found = False
        for rec in info["ipaddress"]:
            if rec["ipaddress"] == old_ip:
                found = True
                break
        if not found:
            cli_warning("\"{}\" is not owned by {}".format(old_ip, info["name"]))

        # Handle arbitrary ip from subnet if received a subnet
        if is_valid_ipv4(ip_or_subnet):
            ip = ip_or_subnet
        else:
            # TODO SUBNET: choose random ip from subnet
            cli_warning("subnets not implemented")
            ip = choose_ip_from_subnet(ip_or_subnet)

        # Update A record ip address
        url = "http://{}:{}/ipaddresses/{}/".format(conf["server_ip"], conf["server_port"], old_ip)
        patch(url, ipaddress=ip)
        cli_info("updated ipaddress.")

    def opt_a_show(self, args: typing.List[str]) -> None:
        """
        a_show <name>
            Show hosts ipaddresses.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_ipaddresses(info["ipaddress"])

    def opt_aaaa_add(self, args: typing.List[str]) -> None:
        """
        aaaa_add <name> <ipv6>
            Add an AAAA record to host.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip = input("Enter ipv6> ")
        else:
            name = args[0]
            ip = args[1]

        # Verify host and get host id
        info = host_info_by_name(name)
        host_id = info["hostid"]

        # Verify ip or get ip from subnet
        if not is_valid_ipv6(ip):
            cli_warning("not a valid ipv6: \"{}\"".format(ip))

        # Create AAAA records
        url = "http://{}:{}/ipaddresses/".format(conf["server_ip"], conf["server_port"])
        post(url, hostid=host_id, ipaddress=ip)
        cli_info("Created ipaddress.")

    def opt_aaaa_remove(self, args: typing.List[str]) -> None:
        """
        aaaa_remove <name> <ipv6>
            Remove AAAA record from host.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip = input("Enter ipv6> ")
        else:
            name = args[0]
            ip = args[1]

        # Ipv6 sanity check
        if not is_valid_ipv6(ip):
            cli_warning("not a valid ipv6: \"{}\"".format(ip))

        # Check that ip belongs to host
        info = host_info_by_name(name)
        found = False
        for rec in info["ipaddress"]:
            if rec["ipaddress"] == ip:
                found = True
                break
        if not found:
            cli_warning("\"{}\" is not owned by {}".format(ip, info["name"]))

        # Delete AAAA record
        url = "http://{}:{}/ipaddresses/{}/".format(conf["server_ip"], conf["server_port"], ip)
        delete(url)
        cli_info("Removed ipaddress.")

    def opt_aaaa_change(self, args: typing.List[str]) -> None:
        """
        aaaa_change <name> <old-ipv6> <new-ipv6>
            Change AAAA record.
        """
        if len(args) < 3:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            old_ip = input("Enter old ipv6> ") if len(args) < 2 else args[1]
            new_ip = input("Enter new ipv6> ")
        else:
            name = args[0]
            old_ip = args[1]
            new_ip = args[2]

        # Ipv6 sanity checks
        if not is_valid_ipv6(old_ip):
            cli_warning("not a valid ipv4: \"{}\"".format(old_ip))
        elif not is_valid_ipv6(new_ip):
            cli_warning("not a valid ipv6: \"{}\"".format(new_ip))

        # Check that ip belongs to host
        info = host_info_by_name(name)
        found = False
        for rec in info["ipaddress"]:
            if rec["ipaddress"] == old_ip:
                found = True
                break
        if not found:
            cli_warning("\"{}\" is not owned by {}".format(old_ip, info["name"]))

        # Update AAAA records ip address
        url = "http://{}:{}/ipaddresses/{}/".format(conf["server_ip"], conf["server_port"], old_ip)
        patch(url, ipaddress=new_ip)
        cli_info("updated ipaddress.")

    def opt_aaaa_show(self, args: typing.List[str]) -> None:
        """
        aaaa_show <name>
            Show hosts ipaddresses.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_ipaddresses(info["ipaddress"])

    def opt_ttl_set(self, args: typing.List[str]) -> None:
        """
        ttl_set <name> <ttl>
            Set ttl for host. Valid values are 300 <= TTL <= 68400 or "default".
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ttl = input("Enter ttl> ")
        else:
            name = args[0]
            ttl = args[1]

        host_name = resolve_input_name(name)

        # TTL sanity check
        if not is_valid_ttl(ttl):
            cli_warning("invalid TTL value: {}".format(ttl))

        # Update TTL
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, ttl=ttl if ttl != "default" else -1)
        cli_info("updated TTL.")

    def opt_ttl_remove(self, args: typing.List[str]) -> None:
        """
        ttl_remove <name>
            Remove explicit TTL for host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        host_name = resolve_input_name(name)

        # Remove TTL value
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, ttl=-1)
        cli_info("removed TTL.")

    def opt_ttl_show(self, args: typing.List[str]) -> None:
        """
        ttl_show <name>
            Show ttl for host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_ttl(info["ttl"])

    def opt_cname_add(self, args: typing.List[str]) -> None:
        """
        cname_add <existing-name> <new-alias>
            Add a CNAME record to host.
        """
        if len(args) < 2:
            name = input("Enter name> ") if len(args) < 1 else args[0]
            alias = input("Enter alias> ")
        else:
            name = args[0]
            alias = args[1]

        host_info = host_info_by_name(name)

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
                    alias_info["txt"]:
                cli_warning("\"{}\" already exists and has record(s)".format(
                    alias_info["name"]))

        # Create cname host if it doesn't exist
        if not alias_info:
            alias = alias if is_longform(alias) else to_longform(alias)
            url = "http://{}:{}/hosts/".format(conf["server_ip"], conf["server_port"])
            post(url, name=alias, contact=host_info["contact"])
            alias_info = host_info_by_name(alias)

        # Create CNAME record
        url = "http://{}:{}/cnames/".format(conf["server_ip"], conf["server_port"])
        post(url, hostid=alias_info["hostid"], cname=host_info["name"])
        cli_info("Added CNAME.")

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

        host_name = resolve_input_name(name)
        alias_info = host_info_by_name(alias)

        # Check that cname host is an alias for host
        cnames = alias_info["cname"]
        if len(cnames) < 1:
            cli_warning("\"{}\" doesn't have any CNAME records.".format(alias_info["name"]))
        if cnames[0]["cname"] != host_name:
            cli_warning("\"{}\" is not an alias for \"{}\"".format(
                alias_info["name"], host_name))

        # Delete CNAME host
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"],
                                              alias_info["name"])
        delete(url)
        cli_info("Removed CNAME.")

    def opt_cname_show(self, args: typing.List[str]) -> None:
        """
        cname_show <name>
            Show CNAME records for host.
        """
        name = input("Enter name> ") if len(args) < 1 else args[0]

        host_name = resolve_input_name(name)
        url = "http://{}:{}/hosts/?cname={}".format(conf["server_ip"], conf["server_port"],
                                                    host_name)
        host_get = get(url)
        for host in host_get.json():
            print_cname(host["name"])

    def opt_loc_set(self, args: typing.List[str]) -> None:
        """
        loc_set <name> <loc>
            Set location of host.
        """
        if len(args) < 2:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            loc = input("Enter loc> ")
        else:
            name = args[0]
            loc = " ".join(args[1:])

        host_name = resolve_input_name(name)

        # LOC sanity check
        if not is_valid_loc(loc):
            cli_warning("invalid TTL value: {}".format(loc))

        # Update LOC
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, loc=loc)
        cli_info("updated LOC.")

    def opt_loc_remove(self, args: typing.List[str]) -> None:
        """
        loc_remove <name>
            Remove location from host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        host_name = resolve_input_name(name)
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, loc="")
        cli_info("removed LOC.")

    def opt_loc_show(self, args: typing.List[str]) -> None:
        """
        loc_show <name>
            Show location of host.
        """
        name = input("Enter name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_loc(info["loc"])

    def opt_hinfo_set(self, args: typing.List[str]) -> None:
        """
        hinfo_set <name> <hinfo>
            Set hinfo for host.
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

        host_name = resolve_input_name(name)

        # Update hinfo
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, hinfo=hinfo)
        cli_info("{}: Updated hinfo.".format(host_name))

    def opt_hinfo_remove(self, args: typing.List[str]) -> None:
        """
        hinfo_remove <name>
            Remove hinfo for host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        host_name = resolve_input_name(name)
        url = "http://{}:{}/hosts/{}/".format(conf["server_ip"], conf["server_port"], host_name)
        patch(url, hinfo=-1)

    def opt_hinfo_show(self, args: typing.List[str]) -> None:
        """
        hinfo_show <name>
            Show hinfo for host.
        """
        name = input("Enter host name> ") if len(args) < 1 else args[0]
        info = host_info_by_name(name)
        print_hinfo(hinfo_id_to_strings(info["hinfo"]))

