#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import sys
from typing import Tuple

from R2Log import logger, console

from dcshadow.manager.Controller import ExecManager


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='DCShadow attack tool')

    # general arguments
    parser.add_argument("-v", "--verbose", dest="verbosity", action="count", default=0, help="Verbosity level (-v for verbose, -vv for advanced, -vvv for debug)")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="Show no information at all")

    # arguments related to the domain controllers involved in the replication process
    rogue_dc = parser.add_argument_group('rogue domain controller')
    rogue_dc.add_argument('--legit-dc-fqdn', action='store', metavar="dc.domain.local", help='Fully Qualified Domain Name of the legitimate domain controller to replicate to')
    legit_dc = parser.add_argument_group('legit domain controller')
    legit_dc.add_argument('--rogue-dc-name', action='store', metavar="dc.domain.local", help='NetBIOS name of the rogue DC to use or create')

    # arguments related to the objects or attributes to replicate
    repl = parser.add_argument_group('replication')
    repl.add_argument('-ro', '--object', dest='repl_object', action='store', help='object to replicate (specified by sAMAccountName)')
    repl.add_argument('-rodn', '--object-dn', dest='repl_object_dn', action='store', help='object to replicate (specified by distinguishedName)')
    repl.add_argument('-ra', '--attribute', dest='repl_attribute', action='store', help="object's attribute to replicate")
    repl.add_argument('-rv', '--value', dest='repl_value', action='store', help='value to set for the attribute')
    repl.add_argument('-rj', '--json', dest='repl_json', action='store', help='path to JSON file containing objects and attributes to replicate')

    # authentication-related arguments
    auth = parser.add_argument_group('authentication')
    auth.add_argument("-d", "--domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    auth.add_argument("-u", "--user", metavar="USER", action="store", help="user to authenticate with")
    auth.add_argument("-p", "--password", metavar="PASSWORD", action="store", help="password to authenticate with")
    auth.add_argument("-H", "--hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    auth.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth.add_argument("--aes-key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth.add_argument("--no-pass", action="store_true", help='don\'t ask for password (useful for -k)')
    auth.add_argument("-td", "--target-domain", dest="target_domain", help="Target domain (if different than the domain of the authenticating user)")

    # connection-related arguments
    con = parser.add_argument_group('connection')
    con.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    con.add_argument('--dc-ip', action='store', metavar="ip address", help='IP address of the DC/KDC to authenticate to')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


def parse_hashes(hashes: str) -> Tuple[str, str]:
    if hashes is not None:
        lmhash, nthash = hashes.split(':')
        if lmhash == '':
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
    else:
        lmhash = ''
        nthash = ''
    return lmhash, nthash


def main():
    """main console entrypoint"""
    try:
        args = parse_args()
        args.lm_hash, args.nt_hash = parse_hashes(hashes=args.hashes)
        # Set logger verbosity depending on user input
        logger.setVerbosity(args.verbosity, args.quiet)
        console.width = 250
        # Start the work
        logger.info("Starting DCShadow attack")
        logger.debug(f"Arguments: {args}")
        ExecManager.main(args=args)
    except KeyboardInterrupt:
        logger.empty_line()
        logger.info("Exiting")
    # except Exception:
    #     console.print_exception(show_locals=True)
    #     # console.print_exception(show_locals=True, suppress=[requests])
    #     exit(1)


if __name__ == '__main__':
    main()
