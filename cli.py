import cmd
import os

from host import host
from zone import zone
from mh_log import log


class MregShell(cmd.Cmd):
    intro = "Welcome to MREG CLI. Type help or ? for help."
    prompt = "mreg> "

    def do_quit(self, args):
        return True

    def do_shell(self, args):
        os.system(args)

    def do_zone(self, args):
        """Create, edit or delete zones. NOT IMPLEMENTED
    zone <option> <argument(s)>

Options:
    create <zone> (<name-server> [name-servers...])
        Create zone with the given name server(s)

    set_ns <zone> (<name-server> [name-servers...])
        Edit name server(s) for zone

    set_soa
    delete"""
        if len(args) == 0:
            print("Missing option.")
        else:
            zone(args[0], args[1:])

    def do_host(self, args):
        """Create, edit, delete or list hosts. NOT IMPLEMENTED
    host <option> <argument(s)>

Options:
    add <name> <ip/net> <contact> [-hinfo <hinfo>] [-comment <comment>]

    remove <name|ip>

    info <name|ip>

    set-hinfo <name> <hinfo>

    set-contact <name> <contact>

    set-comment <name> <comment>

    rename <old-name> <new-name>

    change-ip <name|ip> <new-ip|subnet>

    a_add <name> <ip|subnet>

    a_remove <name> <ip>

    a_change <name> <old-ip> <new-ip|subnet>

    a_show <name>

    aaaa_add <name> <ipv6>

    aaaa_remove <name> <ipv6>

    aaaa_change <name> <old-ipv6> <new-ipv6>

    aaaa_show <name>

    ttl_set <name> <ttl>

    ttl_remove <name>

    ttl_show <name>

    cname_add <existing-name> <new-alias>

    cname_remove <name> <alias-to-delete>

    cname_show <name>

    hinfo_set <name> <hinfo>

    hinfo_remove <name> <hinfo>

    hinfo_show <name>

    loc_set <name> <fritekst-i-fnutter>

    loc_remove <name> <fritekst-i-fnutter>

    lov_show <name>
    """
        args = args.split()
        if len(args) == 0:
            print("Missing option.")
        else:
            host(args[0], args[1:])


if __name__ == '__main__':
    log.set_file(open("cli.log", "w"))
    log.set_quiet()
    MregShell().cmdloop()
