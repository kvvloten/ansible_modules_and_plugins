#!/bin/env python
# requires on the client:
# - "python-netaddr"
# - "python3-netaddr"

import argparse
import re
import sys
import ipaddress
from dns import reversename


def get_reverse_zone(ip_network):
    """
    Like dns.reversename.from_address but for subnets.
    Code from: https://github.com/Wilm0r/dnsrev/blob/master/dnsrev.py
    """
    subnet, netmask = str(ip_network).split('/')
    full_label = str(reversename.from_address(subnet))
    if ':' in subnet:
        rest = int((128 - int(netmask)) / 4)
    else:
        rest = int((32 - int(netmask)) / 8)
    return full_label.split('.', rest)[-1]


def py2unicode(text):
    if sys.version_info.major < 3:
        return unicode(text)
    return text


def get_reverse_ip(ip_address, zone_name):
    reverse_name_regex = re.compile(r'^(?:(?:\d+\.)*\d+)\.(\.ip6\.arpa|IN-ADDR|in-addr\.arpa|\sSnd\s)\.?$')
    partial_ip_regex = re.compile(
        r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){0,3}$')

    if not reverse_name_regex.match(zone_name):
        try:
            ip_network = ipaddress.ip_network(py2unicode(zone_name))
            zone_name = get_reverse_zone(ip_network)
        except ValueError:
            raise('zone: invalid, should be reverse-name or network/netmask or network/prefix, '
                  'specified was {}'.format(zone_name))

    n_record_parts = 7 - len(zone_name.split('.'))
    if n_record_parts == 0:
        n_record_parts = 1
    if partial_ip_regex.match(ip_address):
        try:
            ipaddress.ip_address(py2unicode(ip_address))
            record_parts = str(reversename.from_address(ip_address)).split('.')
            ip_address = '.'.join(record_parts[0:n_record_parts])
        except ValueError:
            pass
    return ip_address


class FilterModule(object):
    def filters(self):
        return {
            'dns_reverse_zone': get_reverse_zone,
            'dns_reverse_ip': get_reverse_ip,
        }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--network', dest='network', required=True)
    parser.add_argument('-i', '--ip-address', dest='ip_address')

    args = parser.parse_args(argv)
    if not args.ip_address:
        result = get_reverse_zone(args.network)
    else:
        result = get_reverse_ip(args.ip_address, args.network)
    print(result)


if __name__ == '__main__':
    main()
