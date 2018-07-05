import sys
import requests
from email import utils

from configurations import *
from util import *

try:
    conf = cli_config(required_fields=("server_ip", "server_port"))
except Exception as e:
    print(e)
    sys.exit(1)


def host(option: str, args: Sequence[str]) -> None:
    if option == "add":
        # TODO implementere interaktivt modus dersom man ikke spesifiserer argumenter
        if len(args) < 3:
            print("Missing argument(s).")
            return
        hinfo = ""
        comment = ""
        try:
            if "-hinfo" in args:
                hinfo = args[args.index("-hinfo") + 1]
            if "-comment" in args:
                comment = args[args.index("-comment") + 1]
        except IndexError:
            print("Invalid input.")
            return
        host_add(args[0], args[1], args[2], hinfo, comment)

    elif option == "remove":
        if len(args) < 1:
            print("Missing name/ip")
            return
        host_remove(args[0])

    elif option == "info":
        if len(args) < 1:
            print("Missing name/ip.")
            return
        host_info(args[0])

    else:
        print("Option unknown/not implemented")


def host_add(name, ip_or_net, contact, hinfo=None, comment=None):
    # TODO handle short names with uio.no as default?
    # TODO handle ip or subnet handling
    # TODO handle random ip address
    if re.match(r"^.*([.:]0|::)/$", ip):
        # find random ip address from subnet
        pass

    # 1 - create host
    try:
        resolve_input_name(name)
    except HostNotFoundError:
        pass
    except Exception as e:
        cli_error(e)
        return
    else:
        cli_warning("host \"{}\" already exists".format(name))
        return

    host_name = name if is_longform(name) else to_longform(name)
    host_url = "http://{}:{}/hosts/".format(conf["server_ip"], conf["server_port"])
    host_data = {
        "name": name,
        "contact": contact,
    }
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


def host_remove(name_or_ip):
    # 1 - search with get req. if host exists (handle long and short name)
    try:
        host_name = resolve_name_or_ip(name_or_ip)
    except HostNotFoundError:
        cli_warning("couldn't get address for \"{}\"".format(name_or_ip))
    except Exception as e:
        cli_error(e)
    else:
        url = "http://{}:{}/hosts/{}/"
        host_del = requests.delete(url.format(url.format(conf["server_ip"], conf["server_port"],
                                                         host_name)))
        if host_del.ok:
            cli_info("deleted {} ({})".format(host_name, host_del.status_code))
        else:
            cli_error("{} {}".format(host_del.status_code, host_del.reason))


def host_info(name_or_ip):
    try:
        host_name = resolve_name_or_ip(name_or_ip)
    except HostNotFoundError:
        cli_warning("couldn't get address for \"{}\"".format(name_or_ip))
    except Exception as e:
        cli_error(e)
    else:
        url = "http://{}:{}/hosts/{}/"
        host_get = requests.get(url.format(conf["server_ip"], conf["server_port"], host_name))
        if host_get.ok:
            # TODO Pretty print host info when receiving correct info
            cli_info("received {} {}".format(host_get.status_code, host_get.reason))
            print(host_get.text)
        else:
            cli_error("{}: {}".format(host_get.status_code, host_get.reason))


def host_set_hinfo(name, hinfo):
    pass


def host_set_contact(name, contact):
    pass


def host_set_comment(name, comment):
    pass


def host_rename(old_name, new_name):
    pass


def host_change_ip(name_or_ip, new_ip_or_subnet):
    pass


def host_a_add(name, ip_or_subnet):
    pass


def host_a_remove(name, ip):
    pass


def host_a_change(name, old_ip, new_ip_or_subnet):
    pass


def host_a_show(name):
    pass


def host_aaaa_add(name, ipv6):
    pass


def host_aaaa_remove(name, ipv6):
    pass


def host_aaaa_change(name, old_ipv6, new_ipv6):
    pass


def host_aaaa_show(name):
    pass


def host_ttl_set(name, ttl):
    pass


def host_ttl_remove(name):
    pass


def host_ttl_show(name):
    pass


def host_cname_add(existing_name, new_alias):
    pass


def host_cname_remove(name, alias_to_delete):
    pass


def host_cname_show(name):
    pass


def host_hinfo_set(name, hinfo):
    pass


def host_hinfo_remove(name, hinfo):
    pass


def host_hinfo_show(name):
    pass


def host_loc_set(name, fritekst_i_fnutter):
    pass


def host_loc_remove(name, fritekst_i_fnutter):
    pass


def host_lov_show(name):
    pass
