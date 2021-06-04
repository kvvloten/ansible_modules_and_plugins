#!/usr/bin/env python
ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '0.1.0'}

DOCUMENTATION = '''
module: samba_dns_zone
author: "kvvloten"
short_description: Manage Samba-ad-dc DNS zones
description:
  - Manage Samba-ad-dc DNS zones
  - Must run on a Samba-ad-dc
version_added: "2.8"
requirements:
  - Requires samba-tool to be installed on host
  - Requires python modules on host dnspython, ipaddress
  - Requires a Samba AD controller
options:
  state:
    description:
      - Desired state of the zone.
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
  name:
    description:
      - Specifies the name of the DNS zone, for a reverse zone, specify the subnet/netmask or use the .in-addr.arpa naming
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

# debconf has the right states: present, absent, read
# https://docs.ansible.com/ansible/latest/modules/dconf_module.html#dconf-module

# username / password parameter example is here
# https://docs.ansible.com/ansible/latest/modules/tower_project_module.html#tower-project-module
# https://docs.ansible.com/ansible/latest/modules/uri_module.html#uri-module
# i.e. samba_username, samba_password
#
# Univention is using samba-ad-dc in the background
# https://docs.ansible.com/ansible/latest/modules/list_of_cloud_modules.html - Univention

import re
import sys
import ipaddress
from dns import reversename
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
                name=dict(required=True, type='str'),
            ),
            supports_check_mode=False,
        )

    def error(self, message):
        result = {
            'msg': message,
            'rc': 1
        }
        self.module.fail_json(**result)

    def validate_inputs(self):
        zone_name = self.module.params['name']
        domain_regex = re.compile(r'^((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}$')
        reverse_name_regex = re.compile(r'^(?:(?:\d+\.)*\d+(?:-in\.addr\.arpa\.)?)$')

        if domain_regex.match(zone_name):
            return zone_name

        if not reverse_name_regex.match(zone_name):
            try:
                ip_network = ipaddress.ip_network(self.py2unicode(zone_name))
                zone_name = self.get_reverse_zone(ip_network)
            except ValueError:
                self.error('zone: invalid, should be a domain-name, a reverse-name or network/netmask or '
                           'network/prefix, specified was {}'.format(zone_name))

        zone_name = zone_name.rstrip('.')
        return zone_name

    @staticmethod
    def py2unicode(text):
        if sys.version_info.major < 3:
            return unicode(text)
        return text

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
        return full_label.split('.', rest)[-1]

    def needs_update(self, samba, zone_name):

        regex = re.compile('^[\s\t]+pszZoneName[\s\t]+: {}$'.format(re.escape(zone_name)))
        samba.module.debug(regex)
        rc, stdout, stderr = samba.run_command(['query', 'localhost', zone_name, '@', 'ALL'])
        samba.module.debug('rc: {}, stderr: {}'.format(rc, stderr))
        exists = not rc

        if self.module.params['state'] == 'present' and exists or \
                self.module.params['state'] == 'absent' and not exists:
            result = {'changed': False}
            samba.module.exit_json(**result)

    def update(self, samba, zone_name):
        self.needs_update(samba, zone_name)
        subcommand = 'zonecreate' if self.module.params['state'] == 'present' else 'zonedelete'
        rc, stdout, stderr = samba.run_command([subcommand, 'localhost', zone_name])
        samba.module.debug('rc: {}, stderr: {}'.format(rc, stderr))
        if rc is not None and rc:
            result = {'msg': stderr, 'rc': rc}
            samba.module.fail_json(**result)

        result = {'msg': stdout, 'rc': 0}
        samba.module.exit_json(**result)


def main():
    ansible = Module()
    ansible.module._debug = True
    zone_name = ansible.validate_inputs()

    samba = SambaTool(ansible.module, 'dns',
                      ansible.module.params['samba_username'], ansible.module.params['samba_password'])
    ansible.update(samba, zone_name)


if __name__ == '__main__':
    main()
