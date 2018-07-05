import cmd
import os

from host import host
from zone import zone

################################################################################
#                                                                              #
#   Help messages                                                              #
#                                                                              #
################################################################################

host_add_help = """{indent}{prefix}add <name> <ip/net> <contact> [-hinfo <hinfo>] [-comment <comment>]
{indent}    Create a new host."""

host_remove_help = """{indent}{prefix}remove <name|ip>
{indent}    Remove host."""

host_info_help = """{indent}{prefix}info <name|ip>
{indent}    Print information about host."""

host_options_help_messages = {
    "add": host_add_help,
    "remove": host_remove_help,
    "info": host_info_help,
}

host_help = """Create, edit, delete or list hosts.
    host <option> <argument(s)>

Options:
"""

for msg_key in host_options_help_messages:
    host_help += host_options_help_messages[msg_key].format(indent="    ", prefix="") + "\n"

old_host_help = """Create, edit, delete or list hosts. NOT IMPLEMENTED
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
    
    loc_show <name>
"""

zone_help = """Create, edit or delete zones. NOT IMPLEMENTED
    zone <option> <argument(s)>

Options:
    create <zone> (<name-server> [name-servers...])
        Create zone with the given name server(s)

    set_ns <zone> (<name-server> [name-servers...])
        Edit name server(s) for zone

    set_soa
    delete"""


################################################################################
#                                                                              #
#   CLI code                                                                   #
#                                                                              #
################################################################################

class MregShell(cmd.Cmd):
    intro = "Welcome to mreg cli. Type help or ? for help."
    prompt = "mreg> "

    def do_quit(self, args):
        """Exit the mreg cli."""
        return True

    def do_shell(self, args):
        """Run a normal bash command."""
        os.system(args)

    def do_zone(self, args):
        """Create, edit or delete zones. NOT IMPLEMENTED"""
        if len(args) == 0:
            print("Missing option.")
        else:
            zone(args[0], args[1:])

    def do_host(self, args):
        """Create, delete or edit hosts."""
        args = args.split()
        if len(args) == 0:
            print("Missing option.")
        elif args[0] != "help":
            host(args[0], args[1:])
        else:
            # Print option help
            if len(args) < 2:
                print("Missing help option.")
                return
            try:
                print(host_options_help_messages[args[1]].format(indent="", prefix="host "))
            except KeyError:
                print("Unknown option: {}".format(args[1]))

    def help_host(self):
        print(host_help)

    def complete_host(self, text, line, begidx, endix):
        options = ("add", "remove", "info", "set-hinfo", "set-contact", "set-comment", "rename",
                   "change-ip", "a_add", "a_remove", "a_change", "a_show", "aaaa_add",
                   "aaaa_remove", "aaaa_change", "aaaa_show", "ttl_set", "ttl_remove", "ttl_show",
                   "cname_add", "cname_remove", "cname_show", "hinfo_set", "hinfo_remove",
                   "hinfo_show", "loc_set", "loc_remove", "loc_show", "help")
        args = line.split()
        l = len(args)
        if l < 2:
            return options
        elif l == 2 or (l == 3 and args[1] == "help"):
            if text:
                suggestions = []
                for opt in options:
                    if text == opt[0:len(text)]:
                        suggestions.append(opt)
                return suggestions
            elif args[1] == "help":
                return options
        return []


if __name__ == '__main__':
    MregShell().cmdloop()
