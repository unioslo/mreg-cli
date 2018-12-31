from util import *
from log import *
# noinspection PyUnresolvedReferences
from cli import cli, Flag
from history import history

try:
    conf = cli_config(required_fields=("server_ip", "server_port"))
except Exception as e:
    print("commands.py: cli_config:", e)
    traceback.print_exc()
    sys.exit(1)

#################################
#  Add the main command 'dhcp'  #
#################################

dhcp = cli.add_command(
    prog='dhcp',
    description='Manage dhcp.',
)


#########################################
# Implementation of sub command 'assoc' #
#########################################

def assoc(args):
    # .name .mac .force
    """Associate MAC address with host. If host got multiple A/AAAA records an
    IP must be given instead of name.
    """
    # Get A/AAAA record by either ip address or host name
    if is_valid_ip(args.name):
        url = "http://{}:{}/ipaddresses/?ipaddress={}".format(
            conf["server_ip"],
            conf["server_port"],
            args.name,
        )
        history.record_get(url)
        ip = get(url).json()
        if not len(ip):
            cli_warning("ip {} doesn't exist.".format(args.name))
        elif len(ip) > 1:
            cli_warning(
                "ip {} is in use by {} hosts".format(args.name, len(ip)))
        ip = ip[0]
    else:
        info = host_info_by_name(args.name)
        if len(info["ipaddresses"]) > 1:
            cli_warning(
                "{} got {} ip addresses, please enter an ip instead.".format(
                    info["name"],
                    len(info["ipaddresses"]),
                ))
        ip = info["ipaddresses"][0]

    # MAC addr sanity check
    if is_valid_mac_addr(args.mac):
        new_mac = format_mac(args.mac)
        url = "http://{}:{}/ipaddresses/?macaddress={}&ordering=ipaddress".format(
            conf["server_ip"],
            conf["server_port"],
            new_mac,
        )
        history.record_get(url)
        macs = get(url).json()
        ips = ", ".join([i['ipaddress'] for i in macs])
        if len(macs) and not args.force:
            cli_warning("mac {} already in use by: {}. "
                        "Use force to add {} -> {} as well.".format(
                args.mac, ips, ip['ipaddress'], args.mac))
    else:
        cli_warning("invalid MAC address: {}".format(args.mac))

    old_mac = ip.get('macaddress')
    if old_mac == new_mac:
        cli_info("new and old mac are identical. Ignoring.", print_msg=True)
        return
    elif old_mac and not args.force:
        cli_warning("ip {} has existing mac {}. Use force to replace.".format(
            ip['ipaddress'], old_mac))

    # Update Ipaddress with a mac
    url = "http://{}:{}/ipaddresses/{}".format(
        conf["server_ip"],
        conf["server_port"],
        ip["id"],
    )
    history.record_patch(url, new_data={"macaddress": new_mac}, old_data=ip)
    patch(url, macaddress=new_mac)
    cli_info("associated mac address {} with ip {}"
             .format(args.mac, ip["ipaddress"]), print_msg=True)


dhcp.add_command(
    prog='assoc',
    description='Associate MAC address with host. If host got multiple A/AAAA '
                'records an IP must be given instead of name.',
    short_desc='Add MAC address to host.',
    callback=assoc,
    flags=[
        Flag('name',
             description='Name or IP of target host.',
             metavar='NAME/IP'),
        Flag('mac',
             description='Mac address.',
             metavar='MACADDRESS'),
        Flag('-force',
             action='count',
             description='Enable force.'),
    ]
)


############################################
# Implementation of sub command 'disassoc' #
############################################

def disassoc(args):
    """Disassociate MAC address with host/ip. If host got multiple A/AAAA
    records an IP must be given instead of name
    """
    # Get A/AAAA record by either ip address or host name
    if is_valid_ip(args.name):
        url = "http://{}:{}/ipaddresses/?ipaddress={}".format(
            conf["server_ip"],
            conf["server_port"],
            args.name,
        )
        history.record_get(url)
        ip = get(url).json()
        if not len(ip):
            cli_warning("ip {} doesn't exist.".format(args.name))
        elif len(ip) > 1:
            cli_warning(
                "ip {} is in use by {} hosts".format(args.name, len(ip)))
        ip = ip[0]
    else:
        info = host_info_by_name(args.name)
        if len(info["ipaddresses"]) > 1:
            cli_warning(
                "{} got {} ip addresses, please enter an ip instead.".format(
                    info["name"],
                    len(info["ipaddress"]),
                ))
        ip = info["ipaddresses"][0]

    if ip.get('macaddress'):
        # Update ipaddress
        url = "http://{}:{}/ipaddresses/{}".format(
            conf["server_ip"],
            conf["server_port"],
            ip["id"],
        )
        history.record_patch(url, new_data={"macaddress": ""}, old_data=ip)
        patch(url, macaddress="")
        cli_info("disassociated mac address {} from ip {}".format(
            ip["macaddress"],
            ip["ipaddress"]
        ), print_msg=True)
    else:
        cli_info("ipaddress {} has no associated mac address"
                 .format(ip["ipaddress"]), print_msg=True)


dhcp.add_command(
    prog='disassoc',
    description='Disassociate MAC address with host/ip. If host got multiple '
                'A/AAAA records an IP must be given instead of name.',
    short_desc='Disassociate MAC address.',
    callback=disassoc,
    flags=[
        Flag('name',
             description='Name or IP of host.',
             metavar='NAME/IP'),
    ]
)
