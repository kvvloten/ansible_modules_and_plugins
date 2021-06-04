#!/bin/env python
# requires on the client:
# - "python-netaddr"
# - "python3-netaddr"

import argparse
import netaddr


def usable_ipaddr(network):
    ipnet = netaddr.IPNetwork(network)
    ips = []
    for ip in list(ipnet)[1:-1]:
        ips.append(str(ip))
    return ips


class FilterModule(object):
    def filters(self):
        return {'usable_ipaddr': usable_ipaddr}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--network', dest='network')
    args = parser.parse_args(argv)
    ips = usable_ipaddr(args.network)
    print(ips)


if __name__ == '__main__':
    main()
