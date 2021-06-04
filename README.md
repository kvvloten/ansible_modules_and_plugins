# Ansible modules and plugins

A collection of modules and plugins for Ansible. 
Tested on Ansible 2.9

## Filter plugins

### dns_reverse

Given a subnet it returns the reverse dns-zone:

```ansible
- debug:
    msg: "{{ '192.168.1.73/29' | dns_reverse_zone }}"
```
Output:
```text
ok: [host] => {
    "msg": "73.1.168.192.in-addr.arpa."
}
```


### hide_sensitive_data

Create obfuscated output for Windows unattend.xml files

```xml
    <LocalAccount wcm:action="add">
        <Password>
            <Value>{{ local_administrator_password | hide_sensitive_data() }}</Value>
            <PlainText>false</PlainText>
        </Password>
        <DisplayName>Local Administrator</DisplayName>
        <Group>Administrators</Group>
        <Name>local_admin</Name>
    </LocalAccount>
```


### usable_ipaddress

Given a subnet it returns a range of ipadresses:

```ansible
- debug:
    msg: "{{ '192.168.1.73/29' | usable_ipaddr }}"
```
Output:
```text
ok: [host] => {
    "msg": [
        "192.168.1.73",
        "192.168.1.74",
        "192.168.1.75",
        "192.168.1.76",
        "192.168.1.77",
        "192.168.1.78"
    ]
}
```

This can be used to loop over usable ips:
```jinja2
{% for ipaddress in "192.168.1.73/29" | usable_ipaddr() %}
{{ ipaddress }}
{% endfor %}
```

## Modules

### difflines

Compares two texts line by lines. Text can be in a file or in a variable.

```ansible
- difflines:
    source: "file_one"
    target: "file_two"
    source_type: file
    target_type: file
  register: diff

- debug:
    msg: "{{ diff.lines_removed }}"

- debug:
    msg: "{{ diff.lines_added }}"
```

### samba_dns

Manage a zone in samba-dns

```ansible
-  samba_dns_zone:
    name: "192.168.1.73/29"
    state: "present"
    samba_username: "{{ samba_user }}"
    samba_password: "{{ samba_password }}"
```

Manage records in a zone in samba-dns

```ansible
-  samba_dns_record:
    zone: "192.168.1.73/29"
    name: "my_host"
    type: "A"
    value: "192.168.1.75"
    state: "present"
    samba_username: "{{ samba_user }}"
    samba_password: "{{ samba_password }}"
```
