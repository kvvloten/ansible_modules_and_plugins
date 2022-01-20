#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, kvvloten, based on diff module from cytopia <cytopia@everythingcli.org>
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#
import json
import os
from grp import getgrnam
from pwd import getpwnam

ANSIBLE_METADATA = {'metadata_version': '2.0',
                    'supported_by': 'community',
                    'status': ['preview']}

DOCUMENTATION = '''
---
module: lxc_subordinate
author: kvvloten

short_description: Allocates a subordinate range and maps users and groups
description:
    - Allocates a subordinate range in /etc/subuid and /etc/subgid
    - Maps specific users and groups as subids for the owner in /etc/subuid and /etc/subgid
    - Returns lxc-config lines and owner/group(-ids) for the container rootfs 
version_added: "2.11"
options:
    name:
        description:
            - Container name
        required: true
        default: null
        aliases: []

    path:
        description:
            - Path to store subordinate config per container name (/<path>/<name>.json)
        required: true
        default: null
        aliases: []

    range_count:
        description:
            - Subid range-size to allocate
        required: false
        default: 65536
        aliases: []

    owner:
        description:
            - Container owner (user-id that will start the container)
        required: false
        default: root
        aliases: []

    map_users:
        description:
            - Host users to be mapped directly into the container (e.g. for permissions on mounted directories)
        required: false
        default: []
        aliases: []

    map_groups:
        description:
            - Host groups to be mapped directly into the container (e.g. for permissions on mounted directories)
        required: false
        default: []
        aliases: []
'''

EXAMPLES = '''
# Difflines compare lines in two strings
- difflines:
    source: "foo"
    target: "bar"
    source_type: string
    target_type: string

# Difflines compare lines in variable against template file (as strings)
- difflines:
    source: "{{ lookup('template', tpl.yml.j2) }}"
    target: "{{ my_var }}"
    source_type: string
    target_type: string

# Difflines compare lines in string against command output
- difflines:
    source: "/bin/bash"
    target: "which bash"
    source_type: string
    target_type: command

# Difflines compare lines in file against command output
- difflines:
    source: "/etc/hostname"
    target: "hostname"
    source_type: file
    target_type: command
'''

RETURN = '''
difflines:
    description: difflines output
    returned: success
    type: dict of lists
    sample: { added = ['line_a', 'line_b'], removed = [] }
'''

from ansible.module_utils.basic import AnsibleModule  #

# Default user/group subordinate id files
SUBID_USER_FILE = '/etc/subuid'
SUBID_GROUP_FILE = '/etc/subgid'
SUBID_MINIMUM_ID = 100000


class CustomAnsibleModule:
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                name=dict(type='str', required=True, default=None),
                path=dict(type='str', required=True, default=None),
                range_count=dict(type='int', required=False, default=65536),
                owner=dict(type='str', required=False, default='root'),
                group=dict(type='str', required=False, default='root'),
                map_users=dict(type='list', required=False, default=[]),
                map_groups=dict(type='list', required=False, default=[]),
            ),
            supports_check_mode=False
        )
        self.params = {
            'container_name': self.module.params['name'],
            'cache_path': self.module.params['path'],
            'range_count': self.module.params['range_count'],
            'container_owner': self.module.params['owner'],
            'container_group': self.module.params['group'],
            'map_users': self.module.params['map_users'],
            'map_groups': self.module.params['map_groups'],
        }

    def validate_inputs(self):
        if not os.path.isdir(self.params['cache_path']):
            self.exit_error("Path does not exist: {}".format(self.params['cache_path']))

    def exit_error(self, message):
        result = {
            'msg': message,
            'rc': 1
        }
        self.module.fail_json(**result)

    def exit_ok(self, changed=None, results=None):
        return_values = {}
        if results is not None:
            return_values = results
        if changed is not None:
            return_values['changed'] = changed
        self.module.exit_json(**return_values)


class BadIdFile(Exception):
    """
    BadIdFile(id_filename, lineno, message) -> BadIdFile object
    Exception raised when an id file is not correctly formatted.
    """

    def __init__(self, id_filename, lineno, message):
        super().__init__(str(message) + '\nfile: ' + str(id_filename) + ', line: ' + str(lineno))
        self.id_filename = id_filename
        self.lineno = lineno


class SubIdMap:
    # Code based on https://github.com/Meseira/subordinate.git
    def __init__(self, id_filename, minimum_free_subid):
        """
        Constructor method.
        On create, the map is empty.
        """
        self._map = {}
        self._subid_filename = id_filename
        self._minimum_free_subid = minimum_free_subid

    def user_append(self, name, first, count):
        if name not in self._map:
            self._map[name] = []
        for item in self._map[name]:
            if item[0] <= first and item[0] + item[1] >= first + count:
                return False
        self._map[name].append([first, count])
        return True

    def user_remove(self, name, first, count):
        if name not in self._map:
            return False
        for index, item in enumerate(self._map[name]):
            if item[0] == first and item[1] == count:
                del self._map[name][index]
                return True
        return False

    def free_id(self):
        first_free_id = self._minimum_free_subid
        for user in self._map:
            for user_item in self._map[user]:
                item_range_end = user_item[0] + user_item[1]
                first_free_id = max(first_free_id, item_range_end)
        return first_free_id

    def read(self):
        with open(self._subid_filename) as id_file:
            lineno = 0
            for line in id_file:
                lineno += 1
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                id_data = line.split(':')
                if len(id_data) != 3:
                    raise BadIdFile(id_file.name, lineno, 'incorrect number of fields')

                name = id_data[0]
                try:
                    first, count = int(id_data[1]), int(id_data[2])
                except ValueError:
                    raise BadIdFile(id_file.name, lineno, 'cannot get the id range')

                # Append the new range
                if name not in self._map:
                    self._map[name] = []
                self._map[name].append([first, count])

    def write(self):
        """
        Return a representation of the id map as a string. This string is
        properly formatted to be written in '/etc/subuid' or '/etc/subgid'.
        """
        map_as_str = []
        for name, id_range_set in self._map.items():
            for id_range in id_range_set:
                map_as_str.append(name + ':' + str(id_range[0]) + ':' + str(id_range[1]) + '\n')

        # Remove trailing newline
        if len(map_as_str) > 0:
            map_as_str[-1] = map_as_str[-1][:-1]

        with open(self._subid_filename, 'w') as id_file:
            id_file.write(''.join(map_as_str))
            id_file.write('\n')


class LxcSubordinate:
    # Cache file format
    # {
    #     'container_owner'
    #     'container_group'
    #     'range_count'
    #     'user': {
    #         'map_names'
    #         'map_ids'
    #         'lxc'
    #         'subid'
    #     },
    #     'group': {
    #         'map_names'
    #         'map_ids'
    #         'lxc'
    #         'subid'
    #     }
    # }
    def __init__(self, filename, container_owner, container_group, range_count, mapped_items):
        self._cache_filename = filename
        self._container_owner = container_owner
        self._container_group = container_group
        self._range_count = range_count
        self._mapped_items = {}
        self._mapped_config = {'user': {}, 'group': {}}
        self._range_count = range_count
        self.is_valid = False
        self._all_subids = {}
        self._initialize_mapped_items(mapped_items)
        self._read_all_subids()
        if self.read_cache():
            self._write_all_subids()

    def _read_all_subids(self):
        files = {
            'user': SUBID_USER_FILE,
            'group': SUBID_GROUP_FILE,
        }
        for kind in ['user', 'group']:
            self._all_subids[kind] = SubIdMap(files[kind], SUBID_MINIMUM_ID)
            self._all_subids[kind].read()

    def _write_all_subids(self):
        for kind in ['user', 'group']:
            self._all_subids[kind].write()

    def _initialize_mapped_items(self, mapped_items):
        # extra call for testability
        self._setup_mapped_items(mapped_items)

    def _setup_mapped_items(self, mapped_items):
        id_lookups = {
            'user': self._get_user_id,
            'group': self._get_group_id,
        }
        for kind in ['user', 'group']:
            self._mapped_items[kind] = {
                'map_names': sorted(mapped_items[kind]),
                'map_ids': sorted([id_lookups[kind](mapped_item) for mapped_item in mapped_items[kind]]),
                'start_subid': None
            }

    @staticmethod
    def _get_user_id(name):
        return getpwnam(name).pw_uid

    @staticmethod
    def _get_group_id(name):
        return getgrnam(name).gr_gid

    def lxc_config(self):
        lxc_config = []
        for kind in ['user', 'group']:
            for item in self._mapped_config[kind]['lxc']:
                lxc_config.append('{} {} {} {}'.format(kind[0], item[0], item[1], item[2]))
        return lxc_config

    def rootfs(self, kind):
        return self._mapped_config[kind]['subid'][0][0]

    def new_mapping(self):
        for kind in ['user', 'group']:
            start_subid = self._mapped_items[kind]['start_subid'] \
                if self._mapped_items[kind]['start_subid'] is not None else self._all_subids[kind].free_id()

            self._all_subids[kind].user_append(self._container_owner, start_subid, self._range_count)
            self._mapped_config[kind]['subid'] = [[start_subid, self._range_count]]
            self._mapped_config[kind]['lxc'] = []

            next_id = 0
            for map_id in self._mapped_items[kind]['map_ids']:
                self._all_subids[kind].user_append(self._container_owner, map_id, 1)
                self._mapped_config[kind]['subid'].append([map_id, 1])
                if map_id - next_id > 0:
                    # map until first object_id
                    self._mapped_config[kind]['lxc'].append([next_id, start_subid + next_id, map_id - next_id])
                # map the object_id
                self._mapped_config[kind]['lxc'].append([map_id, map_id, 1])
                next_id = map_id + 1

            if start_subid + next_id < start_subid + self._range_count:
                # map from last until range ends
                self._mapped_config[kind]['lxc'].append([next_id, start_subid + next_id, self._range_count - next_id])

        self.write_cache()
        self._write_all_subids()

    def _clean_subids(self, mapping_cache, kind):
        # cache values are not longer the desired values, remove suboridinate_map
        for mapping in mapping_cache[kind]['subid']:
            self._all_subids[kind].user_remove(self._container_owner, mapping[0], mapping[1])
            if self._mapped_items[kind]['start_subid'] is None and \
                    self._range_count <= mapping_cache['range_count']:
                # re-use subid range
                self._mapped_items[kind]['start_subid'] = mapping[0]

    def _validate_cache(self, mapping_cache):
        if mapping_cache['container_owner'] != self._container_owner or \
                mapping_cache['container_group'] != self._container_group or \
                mapping_cache['range_count'] != self._range_count:
            return False
        for kind in ['user', 'group']:
            if sorted(mapping_cache[kind]['map_names']) != self._mapped_items[kind]['map_names'] or \
                    sorted(mapping_cache[kind]['map_ids']) != self._mapped_items[kind]['map_ids']:
                return False
        return True

    def read_cache(self):
        if not os.path.exists(self._cache_filename):
            return

        with open(self._cache_filename, encoding='utf-8') as fh:
            mapping_cache = json.load(fh)

        is_subid_updated = False
        id_lookups = {
            'user': self._container_owner,
            'group': self._container_group,
        }
        self.is_valid = self._validate_cache(mapping_cache)
        if self.is_valid:
            for kind in ['user', 'group']:
                for item in ['lxc', 'subid']:
                    self._mapped_config[kind][item] = mapping_cache[kind][item]
                for mapped_id in mapping_cache[kind]['subid']:
                    changed = self._all_subids[kind].user_append(id_lookups[kind], mapped_id[0], mapped_id[1])
                    is_subid_updated = is_subid_updated or changed
        else:
            for kind in ['user', 'group']:
                self._clean_subids(mapping_cache, kind)
                for item in ['lxc', 'subid']:
                    self._mapped_config[kind][item] = None
        return is_subid_updated

    def write_cache(self):
        mapping_cache = {
            'container_owner': self._container_owner,
            'container_group': self._container_group,
            'range_count': self._range_count,
            'user': {},
            'group': {},
        }
        for kind in ['user', 'group']:
            for item in ['map_names', 'map_ids']:
                mapping_cache[kind][item] = self._mapped_items[kind][item]
            for item in ['lxc', 'subid']:
                mapping_cache[kind][item] = self._mapped_config[kind][item]

        with open(self._cache_filename, 'w', encoding='utf-8') as fh:
            json.dump(mapping_cache, fh, indent=2)


class ModuleLxcSubordinate:
    # self._module.params = {
    #     'container_name': self.module.params['name'],
    #     'cache_path': self.module.params['path'],
    #     'range_count': self.module.params['range_count'],
    #     'container_owner': self.module.params['owner'],
    #     'container_group': self.module.params['group'],
    #     'map_users': self.module.params['map_users'],
    #     'map_groups': self.module.params['map_groups'],
    # }
    def __init__(self):
        self._module = CustomAnsibleModule()
        self._module.validate_inputs()

        cache_path = '{}/{}.json'.format(self._module.params['cache_path'], self._module.params['container_name'])
        mapped_items = {
            'user': self._module.params['map_users'],
            'group': self._module.params['map_groups']
        }
        self.subordinate = LxcSubordinate(cache_path,
                                          self._module.params['container_owner'],
                                          self._module.params['container_group'],
                                          self._module.params['range_count'], mapped_items)

    def get_results(self):
        results = {
            'lxc_config': self.subordinate.lxc_config(),
            'rootfs': {
                'owner': self.subordinate.rootfs('user'),
                'group': self.subordinate.rootfs('group'),
            }
        }
        return results

    def main(self):
        if self.subordinate.is_valid:
            self._module.exit_ok(changed=False, results=self.get_results())
        self.subordinate.new_mapping()
        self._module.exit_ok(changed=True, results=self.get_results())


def main():
    ModuleLxcSubordinate().main()


if __name__ == '__main__':
    main()
