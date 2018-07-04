from mh_log import log
from typing import *
from coreapi import Client, codecs


def host(option: str, args: Sequence[str]) -> None:
    log.trace("host({}, {})".format(option, args))
    if option == "add":
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

    elif option == "info":
        if len(args) < 1:
            print("Missing name/ip.")
            return
        host_info(args[0])


def host_add(name, ip_or_net, contact, hinfo="", comment=""):
    pass


def host_remove(name_or_ip):
    pass


def host_info(name_or_ip):
    log.trace("host_info({})".format(name_or_ip))
    decoders = [codecs.CoreJSONCodec(), codecs.JSONCodec()]
    client = Client(decoders=decoders)
    schema = client.get("http://localhost:8000/hosts/")
    # print("schema ({}):\n{}".format(type(schema), schema))
    for d in schema:
        if "uio.no" in d:
            print(d)


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
