import traceback
import inspect
import re
import types
import typing

from util import *
from configurations import *

try:
    conf = cli_config(required_fields=("server_ip", "server_port"))
except Exception as e:
    print(e)
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
        if isinstance(value, types.MethodType):
            if re.match("^opt_.*$", value.__name__):
                return True
        return False

    def _option_methods(self) -> typing.List[typing.Tuple[str, typing.Callable]]:
        # getmembers returns a list of tuples with: (<method name>, <method object>)
        return inspect.getmembers(self, predicate=self._is_option)

    def help(self) -> str:
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

    def do(self, opt: str) -> typing.Callable:
        """Returns the actual option method from a user-friendly option name."""
        for method in self._option_methods():
            if method[0] == "opt_" + opt:
                assert isinstance(method[1], types.MethodType)
                return method[1]
        raise UnknownOptionError("unknown option: {}".format(opt))


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

    def opt_info(self, args: typing.List[str]) -> None:
        """
        info <name|ip>
            Print information about host.
        """
        if len(args) < 1:
            name_or_ip = input("Enter name or ip> ")
        else:
            name_or_ip = args[0]
        try:
            host_name = resolve_name_or_ip(name_or_ip)
        except HostNotFoundError:
            cli_warning("couldn't get address for \"{}\"".format(name_or_ip))
        except Exception:
            traceback.print_exc()
        else:
            url = "http://{}:{}/hosts/{}/"
            host_get = requests.get(url.format(conf["server_ip"], conf["server_port"], host_name))
            if not host_get.ok:
                cli_error("{}: {}".format(host_get.status_code, host_get.reason))
            info = host_get.json()
            pre_len = 14
            # print name
            print("{1:<{0}}{2}".format(pre_len, "Name:", info["name"]))
            # print contact
            print("{1:<{0}}{2}".format(pre_len, "Contact:", info["contact"]))
            # print comment
            if info["comment"]:
                print("{1:<{0}}{2}".format(pre_len, "Comment:", info["comment"]))
            # print a records
            a_records = []
            aaaa_records = []
            len_ip = 0
            for record in info["ipaddress"]:
                if is_valid_ipv4(record["ipaddress"]):
                    a_records.append(record)
                    if len(record["ipaddress"]) > len_ip:
                        len_ip = len(record["ipaddress"])
                elif is_valid_ipv6(record["ipaddress"]):
                    aaaa_records.append(record)
                    if len(record["ipaddress"]) > len_ip:
                        len_ip = len(record["ipaddress"])
            len_ip += 2
            if a_records:
                print("{1:<{0}}{2:<{3}}{4}".format(pre_len, "A_Records:", "IP", len_ip, "MAC"))
                for record in a_records:
                    ip = record["ipaddress"]
                    mac = record["macaddress"]
                    print("{1:<{0}}{2:<{3}}{4}".format(
                        pre_len, "", ip if ip else "<not set>", len_ip,
                        mac if mac else "<not set>"))

            # print aaaa records
            if aaaa_records:
                print("{1:<{0}}{2:<{3}}{4}".format(pre_len, "AAAA_Records:", "IP", len_ip, "MAC"))
                for record in aaaa_records:
                    ip = record["ipaddress"]
                    mac = record["macaddress"]
                    print("{1:<{0}}{2:<{3}}{4}".format(
                        pre_len, "", ip if ip else "<not set>", len_ip,
                        mac if mac else "<not set>"))

            # print ttl
            ttl = info["ttl"]
            print("{1:<{0}}{2}".format(pre_len, "TTL:", ttl if ttl else "(Default)"))
            # print hinfo
            # TODO handle hinfo
            if info["hinfo"]:
                print("{1:<{0}}{2}".format(pre_len, "Hinfo:", info["hinfo"]))
            # print loc
            if info["loc"]:
                print("{1:<{0}}{2}".format(pre_len, "Loc:", info["loc"]))
            # print cname
            for cname in info["cname"]:
                print("{1:<{0}}{2}".format(pre_len, "Cname:", cname["cname"]))
            # print txt
            for txt in info["txt"]:
                print("{1:<{0}}{2}".format(pre_len, "TXT:", txt["txt"]))

    def opt_remove(self, args: typing.List[str]) -> None:
        """
        remove <name|ip>
            Remove host.
        """
        if len(args) < 1:
            name_or_ip = input("Enter name or ip> ")
        else:
            name_or_ip = args[0]
        try:
            host_name = resolve_name_or_ip(name_or_ip)
        except HostNotFoundError:
            cli_warning("couldn't get address for \"{}\"".format(name_or_ip))
        except Exception:
            traceback.print_exc()
        else:
            if "y" not in args:
                # TODO: kreve force hvis host har: flere A-records eller CNAME, SRV eller NAPTR pekende på seg
                pass
            url = "http://{}:{}/hosts/{}/"
            host_del = requests.delete(url.format(url.format(conf["server_ip"], conf["server_port"],
                                                             host_name)))
            if host_del.ok:
                cli_info("deleted {} ({})".format(host_name, host_del.status_code))
            else:
                cli_error("{} {}".format(host_del.status_code, host_del.reason))

    def opt_add(self, args: typing.List[str]) -> None:
        """
        add <name> <ip/net> <contact> [-hinfo <hinfo>] [-comment <comment>]
            Add a new host with the given name, ip or subnet and contact. hinfo and comment
            are optional.
        """
        # Dynamically handle input arguments
        if len(args) < 3:
            name = input("Enter host name> ") if len(args) < 1 else args[0]
            ip_or_net = input("Enter subnet or ip> ") if len(args) < 2 else args[1]
            contact = input("Enter contact> ")
            hinfo = input("Enter hinfo (optional)> ")
            comment = input("Enter comment (optional)> ")
        else:
            name = args[0]
            ip_or_net = args[1]
            contact = args[2]
            hinfo = "" if "-hinfo" not in args else args[args.index("-hinfo") + 1]
            comment = "" if "-comment" not in args else args[args.index("-comment") + 1]

        if re.match(r"^.*([.:]0|::)/$", ip_or_net):
            # TODO handle random ip address
            # find random ip address from subnet
            pass

        try:
            resolve_input_name(name)
        except HostNotFoundError:
            pass
        except Exception:
            traceback.print_exc()
            return
        else:
            if "y" not in args:
                cli_warning("host \"{}\" already exists, must force".format(name))
                return

        # TODO handle short names with uio.no as default?
        host_name = name if is_longform(name) else to_longform(name)
        host_url = "http://{}:{}/hosts/".format(conf["server_ip"], conf["server_port"])
        host_data = {"name": name}
        if is_valid_email(contact):
            host_data["contact"] = contact
        else:
            cli_warning("invalid mail address \"{}\"".format(contact))
            return
        if hinfo:
            host_data["hinfo"] = hinfo
        if comment:
            host_data["comment"] = comment
        post_host = requests.post(host_url, data=host_data)
        if post_host.ok:
            cli_info("{}: {} {}".format(host_name, post_host.status_code, post_host.reason))
        else:
            cli_error("{} {}".format(post_host.status_code, post_host.reason))
            return

        # 2 - add ip addresses to that host
        # TODO create ip or subnet depending on input
        ip_url = "http://{}:{}/hosts/{}/ipaddress/".format(conf["server_ip"],
                                                           conf["server_port"],
                                                           host_name)
        ip_data = {
            "ipaddress": ip_or_net
        }
        post_ip = requests.post(ip_url, ip_data)
        if post_ip.ok:
            cli_info("{}: {} {}".format(ip_or_net, post_host.status_code, post_host.reason))
        else:
            cli_error("{} {}".format(ip_or_net, post_ip.status_code, post_ip.reason))

    def opt_a_remove(self, args):
        """
        a_remove <name> <ip>
            Remove A record.
        """
        # DELETE /hosts/<ipaddress>/ipaddress/

    def opt_a_change(self, args):
        """
        a_change <name> <old-ip> <new-ip-or-subnet>
            Change A record.
        """
        # Case of create subnet: create the subnet before deleting old ip address.
        # PATCH /hosts/<old-ip/ipaddress/ og i body'en er den JSON object med nye ip'ens data.
