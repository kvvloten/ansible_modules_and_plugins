#!/usr/bin/env python
ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '0.1.0'}

DOCUMENTATION = '''
module: samba_dns_record
author: "kvvloten"
short_description: Manage Samba-ad-dc DNS records
description:
  - Manage Samba-ad-dc DNS records
  - Must run on a Samba-ad-dc
version_added: "2.8"
requirements:
  - Requires samba-tool to be installed on host
  - Requires python modules on host dnspython, ipaddress
  - Requires a Samba AD controller to run on
options:
  state:
    description:
      - Desired state of the record
    required: false
    default: present
    choices: [present, absent]
  samba_username:
    description:
      - Username for the DNS server.
    required: false
    default: null
  samba_password:
    description:
      - Password for the DNS server
    required: false
    default: null
  zone:
    description:
      - The DNS zone for this the record.
    required: true
  name:
    description:
      - The DNS reocrd name to manage. 
    required: true
  type:
    description:
      - The type of the DNS record name
    default: A
    choices: [A, AAAA, CNAME, PTR, TXT, SRV, NS, MX]
  value:
    description:
      - Manage the DNS record with this value. Required if `present`
      - If type 'A' or 'AAAA', the IP address.
      - If type 'CNAME', the target fqdn.
      - If type 'PTR', the fqdn.
      - If type 'TXT', a list of stings.
      - If type 'SRV', a list of [fqdn, port, priority, weight].
      - If type 'MX', a list of [fqdn, preference].
    required: true
'''

RETURN = '''
stdout:
  description: Output sent by the DNS server.
  returned: always
  type: string
  sample: ""
'''

EXAMPLES = '''
'''


# IPA is a good example to model this module after
# https://docs.ansible.com/ansible/latest/modules/list_of_identity_modules.html
#
# Univention is using samba-ad-dc in the background
# https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html - Univention

import re
import sys
import ipaddress
from dns import reversename, exception
from ansible.module_utils.basic import AnsibleModule


class SambaTool:
    def __init__(self, module, subcommand, user=None, password=None):
        self.module = module
        self.subcommand = subcommand
        self.options = []
        if user:
            self.options.append('--username={}'.format(user))
        if password:
            self.options.append('--password={}'.format(password))

    def run_command(self, params):
        if isinstance(params, str):
            params = params.split()
        cmd = [self.module.get_bin_path('samba-tool', True), self.subcommand] + params + self.options
        self.module.debug('command: [{}]'.format(cmd))
        return self.module.run_command(cmd)


class Module:
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                state=dict(default='present', choices=['present', 'absent'], type='str'),
                samba_username=dict(default=None, type='str'),
                samba_password=dict(default=None, type='str', no_log=True),
                zone=dict(required=True, type='str'),
                name=dict(required=True, type='str'),
                type=dict(default='A', choices=['A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'SRV', 'MX'], type='str'),
                value=dict(default=None, type='str'),
            ),
            supports_check_mode=False,
            required_if=[
                ['state', 'present', ['value']],
            ]
        )

    def error(self, message):
        result = {
            'msg': message,
            'rc': 1
        }
        self.module.fail_json(**result)

    def validate_inputs(self):
        zone_name = self.module.params['zone']
        record_name = self.module.params['name']
        record_type = self.module.params['type']
        record_value = self.module.params['value']

        hostname_regex = re.compile(r'(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
        reverse_name_regex = re.compile(r'^(?:(?:\d+\.)*\d+(?:-in\.addr\.arpa\.)?)$')
        domain_regex = re.compile(r'^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$')
        partial_ip_regex = re.compile(
            r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){0,3}$')

        if record_type in ['A', 'AAA', 'CNAME', 'TXT', 'SRV', 'MX']:
            if not domain_regex.match(zone_name):
                self.error('zone: invalid domainname, specified was: {}'.format(zone_name))
            if not hostname_regex.match(record_name):
                self.error('name: invalid hostname, specified was: {}'.format(record_name))

        if record_type == 'A':
            try:
                ipaddress.IPv4Address(self.py2unicode(record_value))
            except ipaddress.AddressValueError:
                self.error('value: invalid ipv4 address, specified was: {}'.format(record_value))

        elif record_type == 'AAA':
            try:
                ipaddress.IPv6Address(self.py2unicode(record_value))
            except ipaddress.AddressValueError:
                self.error('value: invalid ipv6 address, specified was: {}'.format(record_value))

        elif record_type == 'CNAME':
            if not domain_regex.match(record_value):
                try:
                    ipaddress.ip_address(self.py2unicode(zone_name))
                except ValueError:
                    self.error('value: invalid domainname or ipaddress, specified was: {}'.format(record_value))

        elif record_type == 'PTR':
            if not reverse_name_regex.match(zone_name):
                try:
                    ip_network = ipaddress.ip_network(self.py2unicode(zone_name))
                    zone_name = self.get_reverse_zone(ip_network)
                    self.module.debug('zone_name: [{}]'.format(zone_name))
                except ValueError:
                    self.error('zone: invalid, should be reverse-name or network/netmask or network/prefix, '
                               'specified was {}'.format(zone_name))

            n_record_parts = 7 - len(zone_name.split('.'))
            self.module.debug('n_record_parts: [{}]'.format(n_record_parts))
            if partial_ip_regex.match(record_name):
                try:
                    ipaddress.ip_address(self.py2unicode(record_name))
                    record_parts = str(reversename.from_address(record_name)).split('.')
                    self.module.debug('record_parts: [{}]'.format(record_parts))
                    record_name = '.'.join(record_parts[0:n_record_parts])
                    self.module.debug('record_name: [{}]'.format(record_name))
                except ValueError:
                    pass
            else:
                self.error('name: invalid, should be reverse-name or ip-address, specified was: {}'.format(record_name))
            if not domain_regex.match(record_value):
                self.error('value: invalid hostname, specified was: {}'.format(record_value))

        elif record_type == 'TXT':
            if not isinstance(record_value, list):
                self.error('ERROR: for type \'TXT\' the value must be a list of strings')
            record_value = '\'{}\''.format('\' \''.join(record_value))
            self.module.debug('record_value: [{}]'.format(record_value))

        elif record_type == 'SRV':
            if not isinstance(record_value, list) or len(record_value) != 4:
                self.error('ERROR: for type \'SRV\' the value must be a list of [fqdn, port, priority, weight]')
            record_value = ' '.join(record_value)
            self.module.debug('record_value: [{}]'.format(record_value))

        elif record_type == 'MX':
            if not isinstance(record_value, list) or len(record_value) != 2:
                self.error('ERROR: for type \'MX\' the value must be a list of [fqdn, preference]')
            record_value = ' '.join(record_value)
            self.module.debug('record_value: [{}]'.format(record_value))

        zone_name = zone_name.rstrip('.')
        return zone_name, record_name, record_type, record_value

    @staticmethod
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
        return full_label.split(".", rest)[-1]

    @staticmethod
    def py2unicode(text):
        if sys.version_info.major < 3:
            return unicode(text)
        return text

    def update_record(self, samba, zone_name, record_name, record_type, record_value):
        samba.module.debug('state: {}, zone: {}, name: {}, type: {}, value: {}'.format(self.module.params['state'],
                                                                                       zone_name, record_name,
                                                                                       record_type, record_value))
        command = []
        rc, stdout, stderr = samba.run_command(['query', 'localhost', zone_name, record_name, record_type])
        exists = (rc == 0)
        if exists and self.module.params['state'] == 'absent':
            command = ['delete', 'localhost', zone_name, record_name, record_type, record_value]
        elif not exists and self.module.params['state'] == 'present':
            command = ['add', 'localhost', zone_name, record_name, record_type, record_value]
        elif exists and self.module.params['state'] == 'present':
            current_dns_values = []
            regex = re.compile(r'^[\s\t]+{}: (.+) \(.+\)$'.format(re.escape(record_type)))
            for line in stdout.split('\n'):
                samba.module.debug('[{}]'.format(line))
                matches = re.search(regex, line)
                if matches:
                    samba.module.debug('MATCH add to list: [{}]'.format(matches.group(1)))
                    current_dns_values.append(matches.group(1))

            if record_value not in current_dns_values and '{}.'.format(record_value) not in current_dns_values:
                command = ['add', 'localhost', zone_name, record_name, record_type, record_value]
            else:
                result = {'changed': False}
                samba.module.exit_json(**result)
        else:
            result = {'changed': False}
            samba.module.exit_json(**result)

        rc, stdout, stderr = samba.run_command(command)
        samba.module.debug('rc: {}, stderr: {}'.format(rc, stderr))
        if rc is not None and rc:
            result = {'msg': stderr, 'rc': rc}
            samba.module.fail_json(**result)

        result = {'msg': stdout, 'rc': 0}
        samba.module.exit_json(**result)


def main():
    ansible = Module()
    ansible.module._debug = True
    zone_name, record_name, record_type, record_value = ansible.validate_inputs()

    samba = SambaTool(ansible.module, 'dns',
                      ansible.module.params['samba_username'], ansible.module.params['samba_password'])

    ansible.update_record(samba, zone_name, record_name, record_type, record_value)


if __name__ == '__main__':
    main()
