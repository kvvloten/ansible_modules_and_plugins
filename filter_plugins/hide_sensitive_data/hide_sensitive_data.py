#!/bin/env python
#
# https://social.technet.microsoft.com/Forums/en-US/5e6a97b5-186c-40dd-a165-2cc3e7eb2682/how-to-encrypt-a-password-in-unattendendxml?forum=itprovistadeployment
#
# All that is required to create your own password is an editor that can insert NULL bytes and a base64 encoder.
# One editor capable of inserting NULL bytes is Notepad++.
# A Linux machine with installed "base64" can be used to encode the password.
#
# So how to create a password? Let's take your above example.
# You want to create a local account and need set to value inside the <Password> tag.
#
# Write you password into the editor. Lets assume you choose "IamAdmin" as a password. Now append "Password" to the
# line (see above mentioned tag). It must now read "IamAdminPassword". Now we need to insert the padding bytes.
#
# In Notepad++ choose Edit->Character Panel. Now insert a "00" byte after each character on your line by double
# clicking the first line in the ASCII Insertion Panel.
# The string should now look similar to this: "I a m A d m i n P a s s w o r d ".
#
# Do not add a carriage return to the end of your line! Now save your file to something meaningful like base64-pw.txt .
#
# All we need to do now, is to encode the file. I prefer the Linux command line, but you may choose any other
# available option. Transfer the file to the Linux machine and then run:
# cat base64-pw.txt | base64
#
# This will be the output for above example: SQBhAG0AQQBkAG0AaQBuAFAAYQBzAHMAdwBvAHIAZAA=
#
# Voila, we are done.
#
# You may want to encode the Password for the tag <AdministratorPassword> as well. Make sure to append
# "AdministratorPassword" to the end of your password before inserting the NULL bytes.
# It should read "IamAdminAdministratorPassword" then.

import argparse
import base64


def hide_sensitive_data(plain_data, admin_password=False):
    null_injected_data = b''
    plain_data = '{}{}'.format(plain_data, 'AdministratorPassword' if admin_password else 'Password')
    for char in plain_data:
        null_injected_data += char.encode() + b'\0'
    hidden_data = base64.b64encode(null_injected_data).decode('utf-8')
    return hidden_data


class FilterModule(object):
    def filters(self):
        return {'hide_sensitive_data': hide_sensitive_data}


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--plain', dest='plain_data')
    parser.add_argument('-a', '--admin-password', action='store_true', dest='admin_password', default=False)
    # use False only for the tag <AdministratorPassword>
    args = parser.parse_args(argv)
    return args


def main():
    args = parse_args()
    hidden_data = hide_sensitive_data(args.plain_data, args.admin_password)
    print(hidden_data)


if __name__ == '__main__':
    main()
