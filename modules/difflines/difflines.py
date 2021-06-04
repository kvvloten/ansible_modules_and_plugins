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

ANSIBLE_METADATA = {'metadata_version': '2.0',
                    'supported_by': 'community',
                    'status': ['preview']}

DOCUMENTATION = '''
---
module: difflines
author: kvvloten

short_description: Difflines compare strings, files or command outputs similar to the diff command.
description:
    - Difflines compare a string, file or command output similar to the diff command.
    - Check mode is only supported when diffing strings or files, commands will only be executed in actual run.
    - Returns a list of added- and a list of removed lines 
version_added: "2.9"
options:
    source:
        description:
            - The source input to diff. Can be a string, contents of a file or output from a command, depending on I(source_type).
        required: true
        default: null
        aliases: []

    target:
        description:
            - The target input to diff. Can be a string, contents of a file or output from a command, depending on I(target_type).
        required: true
        default: null
        aliases: []

    source_type:
        description:
            - Specify the input type of I(source).
        required: false
        default: string
        choices: [string, file, command]
        aliases: []

    target_type:
        description:
            - Specify the input type of I(target).
        required: false
        default: string
        choices: [string, file, command]
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

import os
import subprocess
import difflib
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes


class Module:
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                source=dict(type='str', required=True, default=None),
                target=dict(type='str', required=True, default=None),
                source_type=dict(
                    type='str',
                    required=False,
                    default='string',
                    choices=['string', 'file', 'command']
                ),
                target_type=dict(
                    type='str',
                    required=False,
                    default='string',
                    choices=['string', 'file', 'command']
                ),
            ),
            supports_check_mode=True
        )

    def error(self, message):
        result = {
            'msg': message,
            'rc': 1
        }
        self.module.fail_json(**result)

    def validate_inputs(self):
        source = self.module.params['source']
        target = self.module.params['target']
        source_type = self.module.params['source_type']
        target_type = self.module.params['target_type']

        if source_type == 'file':
            b_source = to_bytes(source, errors='surrogate_or_strict')
            if not os.path.exists(b_source):
                self.error("source %s not found" % source)
            if not os.access(b_source, os.R_OK):
                self.error("source %s not readable" % source)
            if os.path.isdir(b_source):
                self.error("diff does not support recursive diff of directory: %s" % source)

        if target_type == 'file':
            b_target = to_bytes(target, errors='surrogate_or_strict')
            if not os.path.exists(b_target):
                self.error("target %s not found" % target)
            if not os.access(b_target, os.R_OK):
                self.error("target %s not readable" % target)
            if os.path.isdir(b_target):
                self.error("diff does not support recursive diff of directory: %s" % target)

        source = self.retrieve_input('source')
        target = self.retrieve_input('target')
        return source, target

    def retrieve_input(self, direction):
        input_data_name = direction
        input_type_name = direction + '_type'

        input_data = self.module.params.get(input_data_name)
        input_type = self.module.params.get(input_type_name)

        # Input is a file
        if input_type == 'file':
            with open(input_data, 'r') as fhandle:
                input_data = fhandle.read()
        # Input is a command
        elif input_type == 'command':
            if self.module.check_mode:
                result = dict(
                    changed=False,
                    msg="This module does not support check mode when {} is 'command'.".format(input_type_name),
                    skipped=True
                )
                self.module.exit_json(**result)
            else:
                command = input_data.split()
                process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                input_data = process.stdout.decode('utf-8')
                if process.returncode:
                    self.error("%s command failed: %s" % (input_data_name, input_data))
        return input_data

    @staticmethod
    def shell_exec(command):
        process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return process.returncode, process.stdout.decode()


def compare(ansible, source, target):

    added = []
    removed = []
    for line in difflib.unified_diff(source.splitlines(), target.splitlines(), lineterm='', n=0):
        for prefix in ('---', '+++', '@@'):
            if line.startswith(prefix):
                break
        else:
            if line.startswith('+'):
                added.append(line[1:])
            elif line.startswith('-'):
                removed.append(line[1:])

    result = dict(
        lines_added=added,
        lines_removed=removed,
        changed=(source != target)
    )
    ansible.module.exit_json(**result)


def main():
    ansible = Module()
    source, target = ansible.validate_inputs()
    compare(ansible, source, target)


if __name__ == '__main__':
    main()
