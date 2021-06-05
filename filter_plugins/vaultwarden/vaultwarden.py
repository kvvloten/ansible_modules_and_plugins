#!/bin/env python
# requires on the client:
# - "python-passlib"
# - "python3-passlib"
#
# Documentation is here:
#   https://github.com/jcs/rubywarden
#   https://github.com/jcs/rubywarden/blob/master/API.md
#   https://github.com/learnrust/bitwarden-cli/blob/master/python/bitwarden/crypto.py
#   https://docs.cozy.io/en/cozy-stack/bitwarden/
#   https://github.com/GurpreetKang/bitwardenDecrypt
#   https://github.com/doy/rbw

import os
import time
import hashlib
import hmac
import base64
import jwt
from bs4 import BeautifulSoup
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, padding, hashes, asymmetric
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


class BwCipherString:
    AESCBC256_B64 = 0
    AESCBC128_HMACSHA256_B64 = 1  # not implemented
    AESCBC256_HMACSHA256_B64 = 2
    RSA2048_OAEPSHA256_B64 = 3  # not implemented
    RSA2048_OAEPSHA1_B64 = 4
    RSA2048_OAEPSHA256_HMACSHA256_B64 = 5  # not implemented
    RSA2048_OAEPSHA1_HMACSHA256_B64 = 6  # not implemented


class BwCrypto:
    @staticmethod
    def make_key(password, email_salt, iterations):
        # make master key
        if not hasattr(password, 'decode'):
            password = password.encode('utf-8')
        if not hasattr(email_salt, 'decode'):
            email_salt = email_salt.lower().encode('utf-8')
        return hashlib.pbkdf2_hmac('sha256', password, email_salt, iterations, dklen=32)

    def hashed_password(self, password, email_salt, kdf_iterations):
        # base64-encode a wrapped, stretched password+salt for signup/login
        if not hasattr(password, 'decode'):
            password = password.encode('utf-8')

        master_key = self.make_key(password, email_salt, kdf_iterations)
        return base64.b64encode(hashlib.pbkdf2_hmac('sha256', master_key, password, 1, dklen=32)).decode('utf-8')

    @staticmethod
    def hkdf_expand(master_key, key):
        hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=key.encode('utf-8'), backend=default_backend())
        return hkdf.derive(master_key)

    def derive_symmetric_key(self, master_key):
        # http://gnunux.info/dotclear2/index.php?post/2020/10/11/%C3%89crire-un-client-Bitwarden-en-python
        # https://github.com/GurpreetKang/bitwardenDecrypt/blob/master/BitwardenDecrypt.py
        mkey = self.hkdf_expand(master_key, 'enc')
        mmac_key = self.hkdf_expand(master_key, 'mac')
        return mkey, mmac_key

    @staticmethod
    def symmetric_key():
        # create symmetrickey
        pt = os.urandom(64)
        key = pt[:32]
        mac_key = pt[32:64]
        return key, mac_key

    @staticmethod
    def get_rsa_public_from_private_key(private_key):
        public_key = private_key.public_key()
        public_der = public_key.public_bytes(encoding=serialization.Encoding.DER,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return public_der

    def generate_rsa_keypair(self):
        private_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537,  # must be 65537
            key_size=2048,  # must be 2048 - https://bitwarden.com/help/article/what-encryption-is-used/
            backend=default_backend()
        )
        private_der = private_key.private_bytes(encoding=serialization.Encoding.DER,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
        return private_der, self.get_rsa_public_from_private_key(private_key)

    def get_rsa_public_key(self, private_der):
        private_key = serialization.load_der_private_key(private_der, password=None, backend=default_backend())
        return self.get_rsa_public_from_private_key(private_key)

    @staticmethod
    def macs_equal(mac1, mac2):
        # compare two hmacs, with double hmac verification
        cmp_key = os.urandom(32)
        # log.debug("macsEqual lengths:%s:%s:%s", len(cmpKey), len(mac1), len(mac2))
        hmac1 = hmac.new(cmp_key, mac1, 'sha256').digest()
        hmac2 = hmac.new(cmp_key, mac2, 'sha256').digest()
        return hmac1 == hmac2

    @staticmethod
    def encode_cipher_string(enc_type, data, iv=None, mac_key=None):
        # return vaultwarden cipherstring
        cipher_string = '{}.{}|{}'.format(enc_type, iv.decode('utf-8'), data.decode('utf-8')) if iv is not None else \
            '{}.{}'.format(enc_type, data.decode('utf-8'))
        if mac_key is not None:
            cipher_string = '{}|{}'.format(cipher_string, mac_key.decode('utf-8'))
        return cipher_string

    @staticmethod
    def decode_cipher_string(cipher_string):
        # decode a cipher string into it's parts
        iv = mac_key = None
        enc_type = int(cipher_string[0:1])
        assert enc_type < 9
        assert enc_type not in [BwCipherString.AESCBC128_HMACSHA256_B64,
                                BwCipherString.RSA2048_OAEPSHA256_B64,
                                BwCipherString.RSA2048_OAEPSHA256_HMACSHA256_B64,
                                BwCipherString.RSA2048_OAEPSHA1_HMACSHA256_B64]
        if enc_type == BwCipherString.AESCBC256_B64:  # 0
            iv, ct = cipher_string[2:].split("|", 2)
        elif enc_type == BwCipherString.RSA2048_OAEPSHA1_B64:  # 4
            ct = cipher_string[2:]
        else:  # 2
            iv, ct, mac_key = cipher_string[2:].split("|", 3)

        ct = base64.b64decode(ct)
        if iv:
            iv = base64.b64decode(iv)
        if mac_key:
            mac_key = base64.b64decode(mac_key)[0:32]
        return enc_type, iv, ct, mac_key

    def encrypt_symmetric_key(self, key, mac_key, master_key):
        pt = key + mac_key
        mkey, mmac_key = self.derive_symmetric_key(master_key)
        cipher_string = self.encrypt(pt, mkey, mmac_key)
        return cipher_string

    def decrypt_symmetric_key(self, cipher_string, master_key):
        mkey, mmac_key = self.derive_symmetric_key(master_key)
        pt = self.decrypt(cipher_string, mkey, mmac_key, decode=False)
        key = pt[:32]
        mac_key = pt[32:64]
        return key, mac_key

    def encrypt(self, pt, key, mac_key):
        # encrypt+mac a value with a key and mac key and random iv, return cipherString
        if not hasattr(pt, 'decode'):
            pt = pt.encode('utf-8')
        padder = padding.PKCS7(128).padder()
        pt = padder.update(pt) + padder.finalize()
        iv = os.urandom(16)
        # key = hashlib.sha256(key).digest()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(pt) + encryptor.finalize()
        mac = hmac.new(mac_key, iv + ct, 'sha256').digest()
        # mac = hmac.new(mac_key, msg=iv + ct, digestmod=hashlib.sha256).digest()
        return self.encode_cipher_string(BwCipherString.AESCBC256_HMACSHA256_B64, base64.b64encode(ct),
                                         base64.b64encode(iv), base64.b64encode(mac))

    def decrypt(self, cipher_string, key, mac_key, decode=True):
        # decrypt a CipherString and return plaintext
        # Remove the PKCS#7 padding from a text string
        # https://tools.ietf.org/html/rfc2315#section-10.3 section 2
        enc_type, iv, ct, mac = self.decode_cipher_string(cipher_string)
        assert enc_type == BwCipherString.AESCBC256_HMACSHA256_B64

        cmac = hmac.new(mac_key, iv + ct, 'sha256').digest()
        if not self.macs_equal(mac, cmac):
            print("macsEqual error: {}:{}".format(mac, cmac))
            raise IOError("Invalid mac on decrypt")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        unpad = padding.PKCS7(128).unpadder()
        pt = unpad.update(pt) + unpad.finalize()
        if decode:
            return pt.decode('utf-8')
        return pt

    def rsa_encrypt(self, pt, public_der, mac_key=None):
        # https://github.com/bitwarden/jslib/blob/b4fad203b94da53d33693f4283d7249e3a8f1afe/src/services/crypto.service.ts#L312
        # https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
        if not hasattr(pt, 'decode'):
            pt = bytes(pt, 'utf-8')

        rsa_pub_key = serialization.load_der_public_key(public_der, backend=default_backend())
        ct = rsa_pub_key.encrypt(pt, asymmetric.padding.OAEP(asymmetric.padding.MGF1(hashes.SHA1()),
                                                             hashes.SHA1(), label=None))
        if mac_key is None:
            return self.encode_cipher_string(BwCipherString.RSA2048_OAEPSHA1_B64, base64.b64encode(ct))

        mac = hmac.new(mac_key, ct, 'sha256').digest()
        return self.encode_cipher_string(BwCipherString.RSA2048_OAEPSHA1_HMACSHA256_B64,
                                         base64.b64encode(ct), mac_key=mac)

    def rsa_decrypt(self, cipher_string, private_der, decode=True):
        enc_type, iv, ct, mac = self.decode_cipher_string(cipher_string)
        assert enc_type == BwCipherString.RSA2048_OAEPSHA1_B64
        rsa_priv_key = serialization.load_der_private_key(private_der, password=None, backend=default_backend())
        pt = rsa_priv_key.decrypt(ct, asymmetric.padding.OAEP(asymmetric.padding.MGF1(hashes.SHA1()),
                                                              hashes.SHA1(), label=None))
        if decode:
            return pt.decode('utf-8')
        return pt


class ConvertTo:
    @staticmethod
    def string(bin_text):
        result = base64.b64encode(bin_text).decode('utf-8')
        return result

    @staticmethod
    def bytes(str_text):
        result = base64.b64decode(str_text.encode('utf-8'))
        return result


class Vaultwarden:
    @staticmethod
    def master_key(email, password, kdf_iterations):
        crypto = BwCrypto()
        master_key = crypto.make_key(password, email, kdf_iterations)
        return ConvertTo.string(master_key)

    @staticmethod
    def symmetric_key(_):
        crypto = BwCrypto()
        key, mac_key = crypto.symmetric_key()
        return {'key': ConvertTo.string(key),
                'mac_key': ConvertTo.string(mac_key)}

    @staticmethod
    def hashed_password(email, password, kdf_iterations):
        if isinstance(kdf_iterations, str):
            kdf_iterations = int(kdf_iterations)
        crypto = BwCrypto()
        hashed_password = crypto.hashed_password(password, email, kdf_iterations)
        return hashed_password

    @staticmethod
    def encrypt_key(symmetric_key, master_key):
        crypto = BwCrypto()
        key = ConvertTo.bytes(symmetric_key['key'])
        mac_key = ConvertTo.bytes(symmetric_key['mac_key'])
        enc_key = crypto.encrypt_symmetric_key(key, mac_key, ConvertTo.bytes(master_key))
        return enc_key

    @staticmethod
    def decrypt_key(cipher_string, master_key):
        crypto = BwCrypto()
        key, mac_key = crypto.decrypt_symmetric_key(cipher_string, ConvertTo.bytes(master_key))
        return {'key': ConvertTo.string(key),
                'mac_key': ConvertTo.string(mac_key)}

    @staticmethod
    def encrypt(pt, symmetric_key):
        crypto = BwCrypto()
        pt = ConvertTo.bytes(pt)
        key = ConvertTo.bytes(symmetric_key['key'])
        mac_key = ConvertTo.bytes(symmetric_key['mac_key'])
        cipher_string = crypto.encrypt(pt, key, mac_key)
        return cipher_string

    @staticmethod
    def decrypt(cipher_string, symmetric_key):
        crypto = BwCrypto()
        key = ConvertTo.bytes(symmetric_key['key'])
        mac_key = ConvertTo.bytes(symmetric_key['mac_key'])
        pt = crypto.decrypt(cipher_string, key, mac_key, decode=False)
        pt = ConvertTo.string(pt)
        return pt

    @staticmethod
    def string_encrypt(pt, symmetric_key):
        crypto = BwCrypto()
        key = ConvertTo.bytes(symmetric_key['key'])
        mac_key = ConvertTo.bytes(symmetric_key['mac_key'])
        cipher_string = crypto.encrypt(pt, key, mac_key)
        return cipher_string

    @staticmethod
    def string_decrypt(cipher_string, symmetric_key):
        crypto = BwCrypto()
        key = ConvertTo.bytes(symmetric_key['key'])
        mac_key = ConvertTo.bytes(symmetric_key['mac_key'])
        pt = crypto.decrypt(cipher_string, key, mac_key, decode=True)
        return pt

    @staticmethod
    def rsa_generate_keypair(_):
        crypto = BwCrypto()
        private_der, public_der = crypto.generate_rsa_keypair()
        return {'private_key': ConvertTo.string(private_der), 'public_key': ConvertTo.string(public_der)}

    @staticmethod
    def rsa_get_keypair(private_der_str):
        # use this when output comes from Ansible
        crypto = BwCrypto()
        private_der = ConvertTo.bytes(private_der_str)
        public_der = crypto.get_rsa_public_key(private_der)
        return {'private_key': ConvertTo.string(private_der), 'public_key': ConvertTo.string(public_der)}

    @staticmethod
    def rsa_encrypt(pt, keypair):
        crypto = BwCrypto()
        if isinstance(pt, dict):
            # if dict then must be the symmetric key
            pt = ConvertTo.bytes(pt['key']) + ConvertTo.bytes(pt['mac_key'])

        public_der = ConvertTo.bytes(keypair['public_key'])
        cipher_string = crypto.rsa_encrypt(pt, public_der)
        return cipher_string

    @staticmethod
    def rsa_decrypt(cipher_string, keypair, return_symmetric_key=True):
        crypto = BwCrypto()
        private_der = ConvertTo.bytes(keypair['private_key'])
        pt = crypto.rsa_decrypt(cipher_string, private_der, decode=False)
        if return_symmetric_key:
            key = pt[:32]
            mac_key = pt[32:64]
            return {'key': ConvertTo.string(key),
                    'mac_key': ConvertTo.string(mac_key)}
        return ConvertTo.string(pt)

    @staticmethod
    def email_verify_token(access_token, b64_private_der):
        # http://gnunux.info/dotclear2/index.php?post/2020/10/11/Écrire-un-client-Bitwarden-en-python-%3A-créer-une-organisation-et-une-collection
        access_data = jwt.decode(access_token, algorithms=["RS256"], options={"verify_signature": False})

        private_der = base64.b64decode(b64_private_der)
        private_key = serialization.load_der_private_key(private_der, password=None, backend=default_backend())
        private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
        now = int(time.time())
        data = {
            'nbf': now,
            'exp': now + 432000,
            'iss': '{}|verifyemail'.format(access_data['iss'].split('|')[0]),
            'sub': access_data['sub']
        }
        jwt_token = jwt.encode(data, private_pem, algorithm="RS256")
        return jwt_token

    @staticmethod
    def org_invite_token(access_token, b64_private_der, email, user_id, org_id):
        access_data = jwt.decode(access_token, algorithms=["RS256"], options={"verify_signature": False})

        private_der = base64.b64decode(b64_private_der)
        private_key = serialization.load_der_private_key(private_der, password=None, backend=default_backend())
        private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.PKCS8,
                                                encryption_algorithm=serialization.NoEncryption())
        now = int(time.time())
        data = {
            'nbf': now,
            'exp': now + 432000,
            'iss': '{}|invite'.format(access_data['iss'].split('|')[0]),
            'sub': access_data['sub'],
            'email': email,
            'org_id': org_id,
            'user_org_id': user_id,
            'invited_by_email': True,
        }
        jwt_token = jwt.encode(data, private_pem, algorithm="RS256")
        return jwt_token

    @staticmethod
    def get_users_overview(html_content):
        users = []
        html = BeautifulSoup(html_content, "html.parser")
        table = html.find(id="users-table")
        table_body = table.find('tbody')
        rows = table_body.find_all('tr')
        for row in rows:
            cols = row.find_all('td')
            lines = [line for line in cols[0].text.split('\n') if line]
            # lines: [
            #   'user@example.com',
            #   'user@example.com',
            #   'Created at: 2021-01-28 22:31:05 +01:00',
            #   'Last active: Never',
            #   'Disabled',
            #   'Verified'
            #  ]
            last_active = ':'.join(lines[3].split(':')[1:]).strip()
            # Vaultwarden replies in camel case
            user = {
                'Email': lines[0],
                'Locked': lines[4] == 'Disabled',
                'CreationTimestamp': ':'.join(lines[2].split(':')[1:]).strip(),
                'LoginTimestamp': last_active if last_active != 'Never' else '',
                'Items': int(cols[1].text.strip('\n')),
                'Attachments': int(cols[2].text.strip('\n').split(':')[1].strip()),
            }
            users.append(user)

        return users


class FilterModule(object):
    def filters(self):
        return {
            'vaultwarden_master_key': Vaultwarden.master_key,
            'vaultwarden_symmetric_key': Vaultwarden.symmetric_key,
            'vaultwarden_hashed_password': Vaultwarden.hashed_password,
            'vaultwarden_encrypt_key': Vaultwarden.encrypt_key,
            'vaultwarden_decrypt_key': Vaultwarden.decrypt_key,
            'vaultwarden_encrypt': Vaultwarden.encrypt,
            'vaultwarden_decrypt': Vaultwarden.decrypt,
            'vaultwarden_string_encrypt': Vaultwarden.string_encrypt,
            'vaultwarden_string_decrypt': Vaultwarden.string_decrypt,
            'vaultwarden_rsa_generate_keypair': Vaultwarden.rsa_generate_keypair,
            'vaultwarden_rsa_get_keypair': Vaultwarden.rsa_get_keypair,
            'vaultwarden_rsa_encrypt': Vaultwarden.rsa_encrypt,
            'vaultwarden_rsa_decrypt': Vaultwarden.rsa_decrypt,
            'vaultwarden_email_verify_token': Vaultwarden.email_verify_token,
            'vaultwarden_org_invite_token': Vaultwarden.org_invite_token,
            'vaultwarden_get_users_overview': Vaultwarden.get_users_overview,
        }
