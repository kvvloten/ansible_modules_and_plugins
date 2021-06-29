# Ansible modules and plugins

A collection of modules and plugins for Ansible. 

Tested on Ansible 2.9

Filter plugins:
* dns_reverse
* hide_sensitive_data
* usable_ipaddresses
* vaultwarden_*

Modules:
* difflines
* ldap_search 
* samba_dns_record
* samba_dns_zone

## Filter plugins

### bitwise

Filters for bitwise operations:
* bitwise_and
* bitwise_or

```ansible
- debug:
    msg: "{{ 3 | bitwise_and(2) }}"
```
Output:
```text
ok: [host] => {
    "msg": "2"
}
```

```ansible
- debug:
    msg: "{{ 1 | bitwise_or(2) }}"
```
Output:
```text
ok: [host] => {
    "msg": "2"
}
```


### dns_reverse

Given a subnet it returns the reverse dns-zone (IPv6 not implemented):

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

This can be used to iterate over usable ips:
```jinja2
{% for ipaddress in "192.168.1.73/29" | usable_ipaddr() %}
{{ ipaddress }}
{% endfor %}
```

### vaultwarden

[vaultwarden](https://github.com/dani-garcia/vaultwarden) is an "Unofficial Bitwarden compatible server written in Rust".

A great help to install Vaultwarden in Debian is [vaultwarden debian package helper](https://github.com/greizgh/vaultwarden-debian)

A set of filters for all crypto operations in Vaultwarden (or Bitwarden).
* vaultwarden_master_key
* vaultwarden_symmetric_key
* vaultwarden_hashed_password
* vaultwarden_encrypt_key
* vaultwarden_decrypt_key
* vaultwarden_encrypt
* vaultwarden_decrypt
* vaultwarden_string_encrypt
* vaultwarden_string_decrypt
* vaultwarden_rsa_generate_keypair
* vaultwarden_rsa_get_keypair
* vaultwarden_rsa_encrypt
* vaultwarden_rsa_decrypt
* vaultwarden_email_verify_token
* vaultwarden_org_invite_token
* vaultwarden_get_users_overview

This set of filter-plugins enables management of users and organizations in Vaultwarden (or Bitwarden) by Ansible.

Options are:
* Admin login with token: (un)lock users, remove users, remove 2fa
* Create user and validate email, add logins etc, add organization(s)
* Create organization
And much more as long as the API calls are known. 

API documentation is incomplete, some helpful links are:
* https://github.com/jcs/rubywarden/blob/master/API.md
* https://docs.cozy.io/en/cozy-stack/bitwarden/  
* http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python-%3A-identifiant

Reverse engineering of API calls can easily be done by using the web-interface. Put the browser in developer mode and watch client-server calls in 'Network'-tab.

An example: create user and automatically accept the email invitation 
```ansible
- name: "user data"
  set_fact:
    user_email: "test1@example.com"
    user_displayname: "firstname lastname"
    user_password: "initial_password_of_user_test1"

- name: "get prelogin data"
  uri:
    method: "POST"
    url: "http://localhost/vaultwarden/api/accounts/prelogin"
    body_format: "json"
    body: >
      {
        "email": "{{ user_email }}"
      }
    status_code: [200, 500]
  register: r_prelogin

- name: "create keys"
  set_fact:
    user_master_key: "{{ user_email | vaultwarden_master_key(user_password, r_prelogin.json.KdfIterations) }}"
    register_symmetric_key: "{{ '' | vaultwarden_symmetric_key }}"
    register_rsa_keypair: "{{ '' | vaultwarden_rsa_generate_keypair }}"

- name: "register new user"
  uri:
    method: "POST"
    url: "http://localhost/vaultwarden/api/accounts/register"
    body_format: "json"
    # because the json contains a number (in kdfIterations) it must be a folded string block in yaml
    #   otherwise yaml + jinja2 + ansible will put quotes around all values, i.e. make it strings,
    #   that results in "http 422: Unprocessable Entity"
    # https://stackoverflow.com/questions/53307595/ansible-how-print-number-instead-string-in-json-module-uri
    body: >
      {
        "name": "{{ user_displayname }}",
        "email": "{{ user_email }}",
        "masterPasswordHash": "{{ user_email | vaultwarden_hashed_password(user_password, r_prelogin.json.KdfIterations) }}",
        "masterPasswordHint": "",
        "kdfIterations": {{ r_prelogin.json.KdfIterations }},
        "key": "{{ register_symmetric_key | vaultwarden_encrypt_key(user_master_key) }}",
        "keys": {
          "encryptedPrivateKey": "{{ register_rsa_keypair['private_key'] | vaultwarden_encrypt(register_symmetric_key) }}",
          "publicKey": "{{ register_rsa_keypair['public_key'] }}"
        }
      }
    status_code: [200, 400]
  register: r_register

- name: "login user"
  # Since the user is just created, we can login with the initial password
  uri:
    method: "POST"
    url: "http://localhost/vaultwarden/identity/connect/token"
    body_format: "form-urlencoded"
     # browser types:
     #   https://github.com/bitwarden/server/blob/c9a2e67d0965fd046a0b3099e9511c26f0201acd/src/Core/Enums/DeviceType.cs
    body: >
      {
        "grant_type": "password",
        "username": "{{ user_email }}",
        "password": "{{ user_mail | vaultwarden_hashed_password(user_password, r_prelogin.json.KdfIterations) }}",
        "scope": "api offline_access",
        "client_id": "browser",
        "deviceType": 3,
        "deviceIdentifier": "aac2e34a-44db-42ab-a733-5322dd582c3d",
        "deviceName": "firefox",
        "devicePushToken": ""
      }
    status_code: [200, 400]
  register: r_login

- name: "stop when login failed"
  assert:
    - not ansible_check_mode
    - r_login.status == 200

- name: "set access token and symmetic key"
  set_fact:
    i_user_access_token: "{{ r_login.json.access_token }}"
    i_user_symmetric_key: "{{ r_login.json.Key | vaultwarden_decrypt_key(user_master_key) }}"

- name: "set rsa keypair"
  set_fact:
    i_user_rsa_keypair: "{{ r_login.json.PrivateKey | vaultwarden_decrypt(i_user_symmetric_key) | vaultwarden_rsa_get_keypair }}"

- name: " get user profile"
  uri:
    method: "GET"
    url: "http://localhost/vaultwarden/api/accounts/profile"
    headers:
      authorization: "Bearer {{ i_user_access_token }}"
    status_code: [200]
  register: r_user_profile

- name: "api_user_profile_get.yml - set organizations"
  set_fact:
    i_user_profile: "{{ r_user_profile.json }}"

- name: "verify account email"
  uri:
    method: "POST"
    url: "http://localhost/vaultwarden/api/accounts/verify-email-token"
    headers:
      authorization: "Bearer {{ i_user_access_token }}"
    body_format: "json"
    body:
      userId: "{{ i_user_profile.Id }}"
      token: "{{ i_user_access_token | vaultwarden_email_verify_token(vaultwarden_private_der) }}"
    status_code: [200]
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

### ldap_search

### samba_dns

Manage a zone in samba-dns (IPv6 not implemented)

```ansible
-  samba_dns_zone:
    name: "192.168.1.73/29"
    state: "present"
    samba_username: "{{ samba_user }}"
    samba_password: "{{ samba_password }}"
```

Manage records in a zone in samba-dns (IPv6 not implemented)

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

