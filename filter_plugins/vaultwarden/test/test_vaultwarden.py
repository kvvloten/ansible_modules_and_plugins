import base64
import jwt
import pytest

from filter_plugins.vaultwarden.vaultwarden import BwCrypto, Vaultwarden, ConvertTo


class TestBwCrypto:
    @pytest.fixture
    def bw_crypto(self):
        bw_crypto = BwCrypto()
        return bw_crypto

    def test_make_key(self, bw_crypto):
        master_key = bw_crypto.make_key("password", "nobody@example.com", 5000)
        print("masterKey: {}".format(master_key))
        assert master_key == \
               b'\x95\xa9\xc3\xb6W\xfb\xa7r\x80\xbfY\xdf\xfc\x18S\x81\x9e+\xf7W\xd0\x1db\x92$\x1bN\x05\xf5\xb8s\xe7'

    def test_hashed_password(self, bw_crypto):
        master_password_hash = bw_crypto.hashed_password("p4ssw0rd", "nobody@example.com", 5000)
        assert master_password_hash == "r5CFRR+n9NQI8a525FY+0BPR0HGOjVJX0cR1KEMnIOo="

    def test_encrypt_decrypt_symmetric_key(self, bw_crypto):
        master_key = bw_crypto.make_key("password", "nobody@example.com", 5000)
        key = b''.join([chr(i).encode('utf-8') for i in range(0, 32)])
        mac_key = b''.join([chr(i).encode('utf-8') for i in range(0, 32)])
        cipher_string = bw_crypto.encrypt_symmetric_key(key, mac_key, master_key)
        pt_key, pt_mac_key = bw_crypto.decrypt_symmetric_key(cipher_string, master_key)
        assert key == pt_key
        assert mac_key == pt_mac_key

    def test_encrypt_decrypt(self, bw_crypto):
        expected_plain_text = "a secret message"
        encryption_key, mac_key = bw_crypto.symmetric_key()
        encrypted_text = bw_crypto.encrypt(expected_plain_text, encryption_key, mac_key)
        decrypted_plain_text = bw_crypto.decrypt(encrypted_text, encryption_key, mac_key)
        assert decrypted_plain_text == expected_plain_text

    def test_decrypt(self, bw_crypto):
        expected_plain_text = 'EncryptMe!'
        encryption_key = b''.join([chr(i).encode('utf-8') for i in range(0, 32)])
        mac_key = b''.join([chr(i).encode('utf-8') for i in range(0, 32)])
        cipher_string = '2.Ymfe/IY4NGxN/j4xDXUUvg==|c6Wv6O8vT7MUdtQtTKWAMg==|VXZshW+IwUW1NTIvVZ2Pe1zaLnB/nr76kkQZRYze3h4='
        plain_text = bw_crypto.decrypt(cipher_string, encryption_key, mac_key)
        assert plain_text == expected_plain_text

    def test_rsa_encrypt_generated_keys(self, bw_crypto):
        priv_key, pub_key = bw_crypto.generate_rsa_keypair()
        expected_plain_text = 'EncryptMe!'
        encrypted_text = bw_crypto.rsa_encrypt(expected_plain_text, pub_key)
        decrypted_plain_text = bw_crypto.rsa_decrypt(encrypted_text, priv_key)
        assert decrypted_plain_text == expected_plain_text

    def test_rsa_encrypt_predef_keys(self, bw_crypto):
        priv_key = b'0\x82\x04\xbd\x02\x01\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04\x82\x04\xa70\x82\x04\xa3\x02\x01\x00\x02\x82\x01\x01\x00\xb1K\xd1-5V\x05\xa7d\xf2Ml\xd3:@V\xd7l)\x14&\xc7\x19p\xef\xd3\x91\x03,\x85-E\x13mZ\xe5\xb7\x1aU\xf8\x8f\x16\xb3B\x07\xc0\toa\x96\x8f\xb9Xg\xa5\n@r\xa2\xd5Q\xf1\xd3\xad\x12\xafZG%ga\xf4A\xc3\x89\xca\xc6\xcd\xaa\x97\xee\xea\xf8n\xa7\xffW-\x15\xd1c#wK\xf9\xdb\xcfv:\x14\x10\xf1\xd1%\x83\x9b*\x02\x1e\x8d\xd3n7\xa7\xdc\xad%\x9dhQj\xbf\t\xf5:\x00Z\xab\xea\x8b\xcb\xba\xd1G\\\x96\x80\xf5En\x94\xfe\xc0\xd1\x00ILs@\xe6l\xcc\x10Mp|\xe1\xd9~\xb9\x13\xcf\x00\xfb\xd2p\xa4\x9a\xf5\xb4\x16\x05P\x95[\xbf \xd1;\xd3\x08\x86\xac\xf76\x8fJ\xaa?\xb0\x8e[\xdd\x05|\x01\x87\x19(\xeb\xcf;\xd1\x19\xdc\xdd\xf5\x95\x93\xc9\x8a~E9"`\xf6\xfa\x99\x18\xe3\xed\x01y\x86\x8d\x05\xe6o\xac\xda\xe1\x1c\xfc\x93=l\t\xd4\x1e\xa89\xd0,\t5\xc7Z\x07\xc8\x86\x04\\fBw\x02\x03\x01\x00\x01\x02\x82\x01\x00[\x0c\x8c\x87\xa2\xf4bB\xec\xdcbV\x98\xc39w_y\xf4>\x9d\x0brME\\i\x040@\xd4V\xbc\xfbS\xca\xd4\x95y\xc1\x03\xfa\xacd$\x86\xc2Q\xa8\xd4!K\x15\xd3d67\x92\xa7|\xd5pS<vt\x06\xf0\xb2\x8c\xbd\t+\x1c\xb8\x0e\xa2\xb9\xcb\xf9\xea\x80P\xc4\xc3\x11\xa6;I\x11\x16\xd0\x87\xdbD\x9dU\x95i\x8e\x14\x85\x9a\xda\xa1\x13v\'Py\x952\xec\xf2\x0f\xa9\xfb\xbf2k]^nF\xb9Z\xa54\xf9K\x7f\xfc\xf5a\x01\x07\xa2E,\xb2\xb7p\xf4t0\xbct\xea!Mm\'c\x8eY\n\x04\xfe\xef{a\x1b`\xc8WR\xd8m\x02Ms\x1ez\xa4\x02\x8e.\xcc5\xd7:\x05\x96?\xdb\x0bdG\xa8\x08\xf8\t\x06\xfbhJ[@\xfb\x81\xd7qSo\x10\xd8]\xccL\x98N9\x03\xe2\x12qk\xd2y\x03\xbf\x0cXVv`v\xef~\\f\xd3\xe4,\xca5;\xd1\xad\xea\xa8h\xa2\xf7\x87q\x1c\x92\xbek\xd2G\x99a\xb3\xc1\x02\x81\x81\x00\xe0A\xc2\xce\xb9\xb4\x05\xfe\xc84\x08\xd5\x8c\xb1#\'z\x04\x18\x1d\xad\x96\xb6\xfe`-\x08\xc0\x8f:\xe3V\xd8\x04\x15\x9e\xde\\A\x930\xdfFmIb\x18\xbe\xa4\x1b+\xf0\x1a\xd9)\xe9f\xe4\x10F\x84^\xb6,z0@\x94E\x9dd *\xa7\xd4A\xf6\xc0W?\xde\x15K\xc7\xa3\xdeg7\x0b\xdc\x18\x99\x7f\xe1/\x0c\xf8\x98/\xb9p\xac6\xab-v\x83\xae\x8fQ5\x8e\xaa\x93\x7f\x95G\xb4?\x9b\x1a\xd91\xca\x18g\xb3\x15\x02\x81\x81\x00\xcad_\xa1\xa1k \xbc\x15\xe1\x8eqr\xa4\x8a\xd1\xf3n\x99\xd8,\xd7z\xfc\x1c\xa4\x1c\xd3GKD\x97\xb7\x92\xad\xc0\xeeFIZ3\x80 @\x9a2}\xf3&\x87+\xe9\x9f\x82/\x19\\\xf0\xaa\x07%\x03X\xa0U:\xbc\xb0\xf4\xb9\x9aL\xce\x9a\x1c\x9a\xc5\xa0\'u\x176\x90\xf9N\x92\xd92\x92\x8d\'.\x94\x8b0\rd\xb5%gn\xff\xdf,L`\x87,\xf7\xce\xe0\xac\xaa\x13\x84@\x06bg\xa5\xe4\x9b\xf56\x961\xb2[\x02\x81\x80\x04\x08\xca\xd3c=\xdc\xd9\xbf\x8aH\x1agd\x8chZf\x96tz9\xfa\xe2\xca\xa2$\xc5*\x0ez&\x86\xceT\x01>\xa8\xd49,\xa8\xe7\xa0q\xb0\x85\x17p\xe6X=\x02\x8e\xa3\x95bWy\xffz\xc4%l\xd9i\xe2\xcf\x88\r\x13\xcf\x0cUf\x99%2B\x9f\x90\x84;\x8f\xc4\xdf\xecen\x1e0\x87\x1ah\xd7\xaa\xd9\x12\x0b\xd1\xbf8)\xe7\x9cr\xc4]\xb0\x90ZqM\x9aG\xb2L\xce\xeeR\x01\x02\xa5E\xa8x\xbd\x1d\x02\x81\x81\x00\xb0\xb9\xd8\xaf\x80\r\xd55\xa7=\x9fm\xfc\x97%\x08\x931\xfep?\'\xa1"G\xb8\x1d\xdbw#\x88/\x9a\x82\x1f\xea\x99\xa5\x12$\x0bXS\xd1US\xc5\x9a\xee\x07\x96\x16\x97\xcb\xcbh\xb09\r\x9e\xd3y\n\x88f#\xb5\xe4&\xadr\xc8\xa2\x96\xfbgB-\xc8\x86{\xd0\x8f\xe2\xc1\xf3\x84h\x9e\x83V\xb5[\xcb\xf6\x17\x9b\xday`\xca\x11\xefC\xf5%L\xa3\xbdw\r\xc4wv7B\xd8\xd0P\x85\x11\x0c\x05\xa0\xb6\xa1\x8a\x85\x02\x81\x80$"\xdb\xdf\xb9m\xd1\xf7w\xc9\xc9v\xe0\xbf\x11\x1fb\x98\xd7\x8e\xd7\xf7\x88\xae\x83\x851k\xac.\x9f\xcf1\xfa\xce\xf9\xf3\xc5\x97\\\xe2\xe7\xb4\x07\x96j\xc8n89O\x10\x06\xae\xe07\x9e\xf5s\xfb\x95?\x1a\xd4\xb8\xfcz\x8e\xa0U\xb8\xc9\x8c\x90X\xcf\x01\x07;K$\xf3\x85\x82\x04\xe4\\\x16\xe0,\x01\x19\x03>\x1cx\xc1\xb2\x1e\xd9E\x8b\x11\x91\xa8VF\xd2\xd2\x01(I\xe5(\xff\x17S$Xx\xb5[ry\xd2DR\xec'
        pub_key = b'0\x82\x01"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xb1K\xd1-5V\x05\xa7d\xf2Ml\xd3:@V\xd7l)\x14&\xc7\x19p\xef\xd3\x91\x03,\x85-E\x13mZ\xe5\xb7\x1aU\xf8\x8f\x16\xb3B\x07\xc0\toa\x96\x8f\xb9Xg\xa5\n@r\xa2\xd5Q\xf1\xd3\xad\x12\xafZG%ga\xf4A\xc3\x89\xca\xc6\xcd\xaa\x97\xee\xea\xf8n\xa7\xffW-\x15\xd1c#wK\xf9\xdb\xcfv:\x14\x10\xf1\xd1%\x83\x9b*\x02\x1e\x8d\xd3n7\xa7\xdc\xad%\x9dhQj\xbf\t\xf5:\x00Z\xab\xea\x8b\xcb\xba\xd1G\\\x96\x80\xf5En\x94\xfe\xc0\xd1\x00ILs@\xe6l\xcc\x10Mp|\xe1\xd9~\xb9\x13\xcf\x00\xfb\xd2p\xa4\x9a\xf5\xb4\x16\x05P\x95[\xbf \xd1;\xd3\x08\x86\xac\xf76\x8fJ\xaa?\xb0\x8e[\xdd\x05|\x01\x87\x19(\xeb\xcf;\xd1\x19\xdc\xdd\xf5\x95\x93\xc9\x8a~E9"`\xf6\xfa\x99\x18\xe3\xed\x01y\x86\x8d\x05\xe6o\xac\xda\xe1\x1c\xfc\x93=l\t\xd4\x1e\xa89\xd0,\t5\xc7Z\x07\xc8\x86\x04\\fBw\x02\x03\x01\x00\x01'
        expected_plain_text = 'EncryptMe!'
        encrypted_text = bw_crypto.rsa_encrypt(expected_plain_text, pub_key)
        decrypted_plain_text = bw_crypto.rsa_decrypt(encrypted_text, priv_key)
        assert decrypted_plain_text == expected_plain_text

    def test_rsa_decrypt(self, bw_crypto):
        priv_key = b'0\x82\x04\xbd\x02\x01\x000\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x04\x82\x04\xa70\x82\x04\xa3\x02\x01\x00\x02\x82\x01\x01\x00\xb1K\xd1-5V\x05\xa7d\xf2Ml\xd3:@V\xd7l)\x14&\xc7\x19p\xef\xd3\x91\x03,\x85-E\x13mZ\xe5\xb7\x1aU\xf8\x8f\x16\xb3B\x07\xc0\toa\x96\x8f\xb9Xg\xa5\n@r\xa2\xd5Q\xf1\xd3\xad\x12\xafZG%ga\xf4A\xc3\x89\xca\xc6\xcd\xaa\x97\xee\xea\xf8n\xa7\xffW-\x15\xd1c#wK\xf9\xdb\xcfv:\x14\x10\xf1\xd1%\x83\x9b*\x02\x1e\x8d\xd3n7\xa7\xdc\xad%\x9dhQj\xbf\t\xf5:\x00Z\xab\xea\x8b\xcb\xba\xd1G\\\x96\x80\xf5En\x94\xfe\xc0\xd1\x00ILs@\xe6l\xcc\x10Mp|\xe1\xd9~\xb9\x13\xcf\x00\xfb\xd2p\xa4\x9a\xf5\xb4\x16\x05P\x95[\xbf \xd1;\xd3\x08\x86\xac\xf76\x8fJ\xaa?\xb0\x8e[\xdd\x05|\x01\x87\x19(\xeb\xcf;\xd1\x19\xdc\xdd\xf5\x95\x93\xc9\x8a~E9"`\xf6\xfa\x99\x18\xe3\xed\x01y\x86\x8d\x05\xe6o\xac\xda\xe1\x1c\xfc\x93=l\t\xd4\x1e\xa89\xd0,\t5\xc7Z\x07\xc8\x86\x04\\fBw\x02\x03\x01\x00\x01\x02\x82\x01\x00[\x0c\x8c\x87\xa2\xf4bB\xec\xdcbV\x98\xc39w_y\xf4>\x9d\x0brME\\i\x040@\xd4V\xbc\xfbS\xca\xd4\x95y\xc1\x03\xfa\xacd$\x86\xc2Q\xa8\xd4!K\x15\xd3d67\x92\xa7|\xd5pS<vt\x06\xf0\xb2\x8c\xbd\t+\x1c\xb8\x0e\xa2\xb9\xcb\xf9\xea\x80P\xc4\xc3\x11\xa6;I\x11\x16\xd0\x87\xdbD\x9dU\x95i\x8e\x14\x85\x9a\xda\xa1\x13v\'Py\x952\xec\xf2\x0f\xa9\xfb\xbf2k]^nF\xb9Z\xa54\xf9K\x7f\xfc\xf5a\x01\x07\xa2E,\xb2\xb7p\xf4t0\xbct\xea!Mm\'c\x8eY\n\x04\xfe\xef{a\x1b`\xc8WR\xd8m\x02Ms\x1ez\xa4\x02\x8e.\xcc5\xd7:\x05\x96?\xdb\x0bdG\xa8\x08\xf8\t\x06\xfbhJ[@\xfb\x81\xd7qSo\x10\xd8]\xccL\x98N9\x03\xe2\x12qk\xd2y\x03\xbf\x0cXVv`v\xef~\\f\xd3\xe4,\xca5;\xd1\xad\xea\xa8h\xa2\xf7\x87q\x1c\x92\xbek\xd2G\x99a\xb3\xc1\x02\x81\x81\x00\xe0A\xc2\xce\xb9\xb4\x05\xfe\xc84\x08\xd5\x8c\xb1#\'z\x04\x18\x1d\xad\x96\xb6\xfe`-\x08\xc0\x8f:\xe3V\xd8\x04\x15\x9e\xde\\A\x930\xdfFmIb\x18\xbe\xa4\x1b+\xf0\x1a\xd9)\xe9f\xe4\x10F\x84^\xb6,z0@\x94E\x9dd *\xa7\xd4A\xf6\xc0W?\xde\x15K\xc7\xa3\xdeg7\x0b\xdc\x18\x99\x7f\xe1/\x0c\xf8\x98/\xb9p\xac6\xab-v\x83\xae\x8fQ5\x8e\xaa\x93\x7f\x95G\xb4?\x9b\x1a\xd91\xca\x18g\xb3\x15\x02\x81\x81\x00\xcad_\xa1\xa1k \xbc\x15\xe1\x8eqr\xa4\x8a\xd1\xf3n\x99\xd8,\xd7z\xfc\x1c\xa4\x1c\xd3GKD\x97\xb7\x92\xad\xc0\xeeFIZ3\x80 @\x9a2}\xf3&\x87+\xe9\x9f\x82/\x19\\\xf0\xaa\x07%\x03X\xa0U:\xbc\xb0\xf4\xb9\x9aL\xce\x9a\x1c\x9a\xc5\xa0\'u\x176\x90\xf9N\x92\xd92\x92\x8d\'.\x94\x8b0\rd\xb5%gn\xff\xdf,L`\x87,\xf7\xce\xe0\xac\xaa\x13\x84@\x06bg\xa5\xe4\x9b\xf56\x961\xb2[\x02\x81\x80\x04\x08\xca\xd3c=\xdc\xd9\xbf\x8aH\x1agd\x8chZf\x96tz9\xfa\xe2\xca\xa2$\xc5*\x0ez&\x86\xceT\x01>\xa8\xd49,\xa8\xe7\xa0q\xb0\x85\x17p\xe6X=\x02\x8e\xa3\x95bWy\xffz\xc4%l\xd9i\xe2\xcf\x88\r\x13\xcf\x0cUf\x99%2B\x9f\x90\x84;\x8f\xc4\xdf\xecen\x1e0\x87\x1ah\xd7\xaa\xd9\x12\x0b\xd1\xbf8)\xe7\x9cr\xc4]\xb0\x90ZqM\x9aG\xb2L\xce\xeeR\x01\x02\xa5E\xa8x\xbd\x1d\x02\x81\x81\x00\xb0\xb9\xd8\xaf\x80\r\xd55\xa7=\x9fm\xfc\x97%\x08\x931\xfep?\'\xa1"G\xb8\x1d\xdbw#\x88/\x9a\x82\x1f\xea\x99\xa5\x12$\x0bXS\xd1US\xc5\x9a\xee\x07\x96\x16\x97\xcb\xcbh\xb09\r\x9e\xd3y\n\x88f#\xb5\xe4&\xadr\xc8\xa2\x96\xfbgB-\xc8\x86{\xd0\x8f\xe2\xc1\xf3\x84h\x9e\x83V\xb5[\xcb\xf6\x17\x9b\xday`\xca\x11\xefC\xf5%L\xa3\xbdw\r\xc4wv7B\xd8\xd0P\x85\x11\x0c\x05\xa0\xb6\xa1\x8a\x85\x02\x81\x80$"\xdb\xdf\xb9m\xd1\xf7w\xc9\xc9v\xe0\xbf\x11\x1fb\x98\xd7\x8e\xd7\xf7\x88\xae\x83\x851k\xac.\x9f\xcf1\xfa\xce\xf9\xf3\xc5\x97\\\xe2\xe7\xb4\x07\x96j\xc8n89O\x10\x06\xae\xe07\x9e\xf5s\xfb\x95?\x1a\xd4\xb8\xfcz\x8e\xa0U\xb8\xc9\x8c\x90X\xcf\x01\x07;K$\xf3\x85\x82\x04\xe4\\\x16\xe0,\x01\x19\x03>\x1cx\xc1\xb2\x1e\xd9E\x8b\x11\x91\xa8VF\xd2\xd2\x01(I\xe5(\xff\x17S$Xx\xb5[ry\xd2DR\xec'
        cipher_string = '4.m0XNnf5pIkm0+vpHTsJomE4+L7hJR1JOw9syjZesKUPvlEY8AgyDoH04aJ8asdGi7X9sHo3FpAB1xxXeSP8KMtNmjBoxbWDblBaJMFAfjPSSqhrTy0mu4TiuksLwqZdMcr2Nc7u7KjgFBCV/v3kqelEMOIt4NA/gZq8wmiwrEojEJWNLWYd5ycHnvntcORs1SBpoVbz6phSkZW/CRtDSXv2JDQd/fAbMu7r+1BT42tiY25hQWujIpqv1qNna5jDW7imc2Ln4vY6Dbt9eT6S0TPKMMq5WoAlZn80e3Ts9KoPVSM3ivvkuK1gvhRNw3LA5J+dKCjQS6n7yFHtrkE2PRg=='
        expected_plain_text = 'EncryptMe!'
        decrypted_plain_text = bw_crypto.rsa_decrypt(cipher_string, priv_key)
        assert decrypted_plain_text == expected_plain_text


class TestVaultwarden:
    def test_encrypt(self):
        rsa_keypair = {
            "private_key": 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxS9EtNVYFp2TyTWzTOkBW12wpFCbHGXDv05EDLIUtRRNtWuW3GlX4jxazQgfACW9hlo+5WGelCkByotVR8dOtEq9aRyVnYfRBw4nKxs2ql+7q+G6n/1ctFdFjI3dL+dvPdjoUEPHRJYObKgIejdNuN6fcrSWdaFFqvwn1OgBaq+qLy7rRR1yWgPVFbpT+wNEASUxzQOZszBBNcHzh2X65E88A+9JwpJr1tBYFUJVbvyDRO9MIhqz3No9Kqj+wjlvdBXwBhxko68870Rnc3fWVk8mKfkU5ImD2+pkY4+0BeYaNBeZvrNrhHPyTPWwJ1B6oOdAsCTXHWgfIhgRcZkJ3AgMBAAECggEAWwyMh6L0YkLs3GJWmMM5d1959D6dC3JNRVxpBDBA1Fa8+1PK1JV5wQP6rGQkhsJRqNQhSxXTZDY3kqd81XBTPHZ0BvCyjL0JKxy4DqK5y/nqgFDEwxGmO0kRFtCH20SdVZVpjhSFmtqhE3YnUHmVMuzyD6n7vzJrXV5uRrlapTT5S3/89WEBB6JFLLK3cPR0MLx06iFNbSdjjlkKBP7ve2EbYMhXUthtAk1zHnqkAo4uzDXXOgWWP9sLZEeoCPgJBvtoSltA+4HXcVNvENhdzEyYTjkD4hJxa9J5A78MWFZ2YHbvflxm0+QsyjU70a3qqGii94dxHJK+a9JHmWGzwQKBgQDgQcLOubQF/sg0CNWMsSMnegQYHa2Wtv5gLQjAjzrjVtgEFZ7eXEGTMN9GbUliGL6kGyvwGtkp6WbkEEaEXrYsejBAlEWdZCAqp9RB9sBXP94VS8ej3mc3C9wYmX/hLwz4mC+5cKw2qy12g66PUTWOqpN/lUe0P5sa2THKGGezFQKBgQDKZF+hoWsgvBXhjnFypIrR826Z2CzXevwcpBzTR0tEl7eSrcDuRklaM4AgQJoyffMmhyvpn4IvGVzwqgclA1igVTq8sPS5mkzOmhyaxaAndRc2kPlOktkyko0nLpSLMA1ktSVnbv/fLExghyz3zuCsqhOEQAZiZ6Xkm/U2ljGyWwKBgAQIytNjPdzZv4pIGmdkjGhaZpZ0ejn64sqiJMUqDnomhs5UAT6o1DksqOegcbCFF3DmWD0CjqOVYld5/3rEJWzZaeLPiA0TzwxVZpklMkKfkIQ7j8Tf7GVuHjCHGmjXqtkSC9G/OCnnnHLEXbCQWnFNmkeyTM7uUgECpUWoeL0dAoGBALC52K+ADdU1pz2fbfyXJQiTMf5wPyehIke4Hdt3I4gvmoIf6pmlEiQLWFPRVVPFmu4HlhaXy8tosDkNntN5CohmI7XkJq1yyKKW+2dCLciGe9CP4sHzhGieg1a1W8v2F5vaeWDKEe9D9SVMo713DcR3djdC2NBQhREMBaC2oYqFAoGAJCLb37lt0fd3ycl24L8RH2KY147X94iug4Uxa6wun88x+s7588WXXOLntAeWashuODlPEAau4Dee9XP7lT8a1Lj8eo6gVbjJjJBYzwEHO0sk84WCBORcFuAsARkDPhx4wbIe2UWLEZGoVkbS0gEoSeUo/xdTJFh4tVtyedJEUuw=',
            "public_key": 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsUvRLTVWBadk8k1s0zpAVtdsKRQmxxlw79ORAyyFLUUTbVrltxpV+I8Ws0IHwAlvYZaPuVhnpQpAcqLVUfHTrRKvWkclZ2H0QcOJysbNqpfu6vhup/9XLRXRYyN3S/nbz3Y6FBDx0SWDmyoCHo3Tbjen3K0lnWhRar8J9ToAWqvqi8u60UdcloD1RW6U/sDRAElMc0DmbMwQTXB84dl+uRPPAPvScKSa9bQWBVCVW78g0TvTCIas9zaPSqo/sI5b3QV8AYcZKOvPO9EZ3N31lZPJin5FOSJg9vqZGOPtAXmGjQXmb6za4Rz8kz1sCdQeqDnQLAk1x1oHyIYEXGZCdwIDAQAB',
        }
        symmetric_key = {
            "key": "U6Rn8qOWnzZUROFWOuHB/WTrDzoSPivBQ+cD8eBGS5M=",
            "mac_key": "O1TKc3ydrgH9g2J1c+nN62HuXbyIa4FC8CpNgLXzROc="
        }
        result = Vaultwarden.encrypt(rsa_keypair['private_key'], symmetric_key)
        assert result.startswith('2.')
        assert len(result.split('|')) == 3

    def test_symmetric_key_and_convert_to(self):
        crypto = BwCrypto()
        key, mac_key = crypto.symmetric_key()
        ansible_key = ConvertTo.string(key)
        ansible_mac_key = ConvertTo.string(mac_key)
        assert key == ConvertTo.bytes(ansible_key)
        assert mac_key == ConvertTo.bytes(ansible_mac_key)

    def test_keypair_and_convert_to(self):
        keypair = Vaultwarden.rsa_generate_keypair(None)
        symmetric_key = Vaultwarden.symmetric_key(None)
        crypto = BwCrypto()
        cipher_string = crypto.encrypt(base64.b64decode(keypair['private_key'].encode('utf-8')),
                                       base64.b64decode(symmetric_key['key'].encode('utf-8')),
                                       base64.b64decode(symmetric_key['mac_key'].encode('utf-8')))

        ansible_cipher_string = Vaultwarden.encrypt(keypair['private_key'], symmetric_key)
        assert len(cipher_string) == len(ansible_cipher_string)

    def test_decrypt_private_key(self):
        encrypted_private_key = '2.tkWcZuldakx7tF4DHVZOxQ==|/MiPz2Y9oVojP3bis5ikDGWLM3B5JOLw5pFQbQzmiNkmyPLxkllS5RLvtrjtQTEkaWvkfOWrJ+OqxaDdbtu+uJz64/SUTkAKnayVwfiD/AepEWH1RcnOfieUWVHS5le5bjhbShTFUVR3A/Nmb1PkAds4JPeGk2tyr+3vz7rLscWKU540SI5QqzNfWi8PR3aY2O2esgBR4UAXakc9d3+qanMlzCitzxsIbcuARW4h69FoNzTKW76gmoINDOE2LHBSSOD6wUgWhMZCcTdWT81EP8F0iajWfB4e5RWQ0wfzStMxTw9qKCDpCckAjEos2rvKBwlL5iM5mEGnRWZV6bodKS+PgSvfnSTWiW1frx+w5lgwm31TGa+j3CVJElwJ3n5Xl6T8wU8gou9gVkG7AAEHjpUyjJfS9vCp21gKTHInx+IKsrXDjZVvzXUyWxj7EegdYyQugXjwgeantiHqgA3JtYHFxAUKLpMILZCE8VoQGenE6s3ZEx8tQArb+DMkCnA70bBZhBMRNKD7jI+OHSmyxO5phyPQhIBvmvfpSTDtJwgZrlUKd/WVKO1PJAFIupOeZ3fB5jHdyUe+WUT1Pby77W2drgYmBzie0Le7iri+C7iDtad58RFksSr8FMc/k9x1CIY4GbqME3j1O+uJo7EW1Or2seVSUYs7LXX16+8UMPdNZSiLvaU2sXKo9ak7yIgpcbdDIuBppOqNNo17+IGLRNN/NYFusULrPnnmzKFseyvk+GbKxKp3qRY4kFLeWUjiSni92tXr2lQg4lS0U4t52UohKXVIf+MedXkMK3KROxcnbcjmHrL6CoqhlhZix9yxT1+sB4K6fRdNmbt6iUGWOG1grOv/8ptLEkpfj89varKNV/YRQXeAPSfBeiqcKW4SAumJhT6N1LzV1WQYaAWx6wRE2T5BMsP5vQKgwdmG0/GDmbzxxHvQ6c0oiUwj4ftAVPqVHPJNPueUWhPzKpPEludeHhk8IAzNAmxvcXE1O00i2rRzIcNo3qhYuSSeE/h+1I+d3/Divsn1mXUxcO2/MKDa+TaQfTsNUfA1orhZrQUplXs7bu/AqIIMjAPzsDUQbxVmywfN9GtX4yLqEvdWG4Y6HkRpyWjurShWpcJ7AiGODp5i/7FVm4/ZuJ03Z26LmORuPaKwylNdPw7epnhqGufJi7n7kGhryV7kAvpqtgIUlxB2jDIwedoaJwD1lrFK23ZJYvle1R1djp6vLiV4ACtVya8Y/eZVGN/MjfGdObGfqyROa8jE9tybIF+Ethb8RMDM8gI0SSKzinuvrF4iVsZiDAWUM6fHjXXx3ZbMvulHkfMo4g3BUavfviGy5MWsMGU0XNFMJVpHti495oCP1HNQGdY1AJwPWsx8L0jsPxYWub7q3mKTd86gWQ4jKQbKpG28TpQ/7GFp4fZVMFZXiCKdY45dtE1R3kylOXvFpWKluVQZJaPBMfuPd+GgoKFy0GFA9SCZpPnQNYi8AqOZgl54uWzdLZPTfa84Y5WyK2dQe70tIQlmmqLjQeijlYjjqVF75M0R3Jj276vEkv+hDCdcYGWMz8MF9++OXKxl6qO0huUzJ1rk17OxW5Kp7IkDCU+GSjLj2qo8PJpCRHj9PRF2gQovgB8EbZSymh+C2AU=|7Q8Nf44+r0Fbc2u6ZVhk/Iene3HVEII5ha0gRB3MzgQ='
        symmetric_key = {
            'key': 'xLBAPc4/O1IRvCVvEplXkf0SLWTPcl6QgFOxfy4Iw0U=',
            'mac_key': 'RBieJYc+cDXAufD5p4aoF1MDk9BxvHTXV69L4x4h9TU='
        }
        private_key = Vaultwarden.decrypt(encrypted_private_key, symmetric_key)
        assert private_key == 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDt9ZsH2rj8KeF+5Wm3md9wxHzyzbUx6c8sc/2FiHQTg2pb8KeHnsn5gWWMHC/JdYLbAiRaRx+wY7V17V3jdQswnqcRiL1f57K61UdD11V1HZzc4rduk4/QYqfgGiZTB30aGwq35Uns/A8wUhExNlIc2CpYBBUr74Zu1Mh5UIIKQHXZpqjDtIzY17IwgVnlD3YaZdVSG0MErtmN4ZBuYHT5lheYbgMeqhl7lP+3QAKNOIqFnViUrjQ6GsDdHDKGaut+mEyaBJePYzbwdDJvY0LlEXvz2O/Ccc2Hj//qlU4cMYlMTH9DPX+Wl0E7AuS93o4Nj+3km3hw5wOwI6nTgck5AgMBAAECggEAMxvZXGqB6McmA5dKiYCnGRVasNu12y6YrLeM8C1KoRZMtcqOcPaN8uTz5o/3Q5HVtSxUmn9EMyJ3SwjcbYoqCRtKTt3LrtmY7b/5Onz5gdoGYvre4wUWkm9eFygGqzakjALa3nyE0D2jFYHK54L/R+q1zYmy8mjTuuJA3K2KAKFFphJyn6nAll5MaUjt2HVLZ5Rme66D/RDoT7QAnPvaCuw6rDaVKDRyLRQAgDbVztYvpYntAhQnUUiTazc7u+rOY2sOPnaFeubvKtwjmkzLWy4hgFyo0D/swg7+wcU9R2B6mHLzApcsCPs2tIZBLYp6Z6srhBFnV7kACTEe/GVccQKBgQD6ST0usrGx+OAxEEWDEp+Kj0g483dXtiYjn3ToWr8BqIG6dYdbJLr/3UPUuNTuj7LKOjhwoq8hsL8Ybuy29Z9YjEXI8n5uImwCUORGH1NjTrIFGusFQAzZp8psHi8XEmlSgaM8ypd1cNm0ZUL9xYSmPzuLtB4M9w6ZVO+LUj7W2wKBgQDzZFM0C2cY2pqOAoc4ycu7ATBqPq+QmQL5k2k7TPKVBXP/kw40w/+kr0zrex7NLRmHoP1pgmFBuU0F17HLGDSnIUqN9PyYtEBHk+9ld2lSv3LNhICglLahV4T2W6PZi8AtBsut5Fk+KM87zGuhECVh6SUcup8c40A7LPzT1oQKewKBgQCvS86DP3q/aM007+2PoOKG/FWcNcF3eEb8GjmaZ7xx3+CEhL55sp8ah5FzksToFVMm2mIfWYIJua4N4dr/RccGELDrzhOI9ajqcld/WX9hBYQfmTvUIIkfhKp80SMwKKAFvnBjKo2sHo8MDwQ9kzKV8aG19kA52muqLtfbn44NkwKBgBgZUeewTVf3pR/0fiEQUfzFJF8Qr994VwQRJXU6rDY3IQIoNFrjITfUJ6CVQzp7gbCdLxo4T5rrVwYCEleSoPv/Xttpa21PQ6ISsrxwM1x/GkXhHb9ImkClYsPl1PZgUPnkV1xzZKaz8bjxB6Md7yWfqQ4MKF763Uw+qxXqgo5rAoGBANoZnkmpoZTXJEmzM+wfTaFfoXBvnffl1JrMZqd3aoSy2Qgg72+p5EiC4+5hhQusdRLBC5ODMsqzdhuhDvOjAUlIAkKJRCsGx5fqfwAV52Xf/pZW+2DP8Ns9MFiT1MTclJ/E4F2i8zvXmpRQoGe1sklc8N8tDBvzI6MKYp23EJBa'

        keypair = Vaultwarden.rsa_get_keypair(private_key)
        assert 'private_key' in keypair
        assert 'public_key' in keypair
        assert keypair['public_key'] == 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7fWbB9q4/CnhfuVpt5nfcMR88s21MenPLHP9hYh0E4NqW/Cnh57J+YFljBwvyXWC2wIkWkcfsGO1de1d43ULMJ6nEYi9X+eyutVHQ9dVdR2c3OK3bpOP0GKn4BomUwd9GhsKt+VJ7PwPMFIRMTZSHNgqWAQVK++GbtTIeVCCCkB12aaow7SM2NeyMIFZ5Q92GmXVUhtDBK7ZjeGQbmB0+ZYXmG4DHqoZe5T/t0ACjTiKhZ1YlK40OhrA3RwyhmrrfphMmgSXj2M28HQyb2NC5RF789jvwnHNh4//6pVOHDGJTEx/Qz1/lpdBOwLkvd6ODY/t5Jt4cOcDsCOp04HJOQIDAQAB'

    def test_email_verify_token(self):
        private_der = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxS9EtNVYFp2TyTWzTOkBW12wpFCbHGXDv05EDLIUtRRNtWuW3GlX4jxazQgfACW9hlo+5WGelCkByotVR8dOtEq9aRyVnYfRBw4nKxs2ql+7q+G6n/1ctFdFjI3dL+dvPdjoUEPHRJYObKgIejdNuN6fcrSWdaFFqvwn1OgBaq+qLy7rRR1yWgPVFbpT+wNEASUxzQOZszBBNcHzh2X65E88A+9JwpJr1tBYFUJVbvyDRO9MIhqz3No9Kqj+wjlvdBXwBhxko68870Rnc3fWVk8mKfkU5ImD2+pkY4+0BeYaNBeZvrNrhHPyTPWwJ1B6oOdAsCTXHWgfIhgRcZkJ3AgMBAAECggEAWwyMh6L0YkLs3GJWmMM5d1959D6dC3JNRVxpBDBA1Fa8+1PK1JV5wQP6rGQkhsJRqNQhSxXTZDY3kqd81XBTPHZ0BvCyjL0JKxy4DqK5y/nqgFDEwxGmO0kRFtCH20SdVZVpjhSFmtqhE3YnUHmVMuzyD6n7vzJrXV5uRrlapTT5S3/89WEBB6JFLLK3cPR0MLx06iFNbSdjjlkKBP7ve2EbYMhXUthtAk1zHnqkAo4uzDXXOgWWP9sLZEeoCPgJBvtoSltA+4HXcVNvENhdzEyYTjkD4hJxa9J5A78MWFZ2YHbvflxm0+QsyjU70a3qqGii94dxHJK+a9JHmWGzwQKBgQDgQcLOubQF/sg0CNWMsSMnegQYHa2Wtv5gLQjAjzrjVtgEFZ7eXEGTMN9GbUliGL6kGyvwGtkp6WbkEEaEXrYsejBAlEWdZCAqp9RB9sBXP94VS8ej3mc3C9wYmX/hLwz4mC+5cKw2qy12g66PUTWOqpN/lUe0P5sa2THKGGezFQKBgQDKZF+hoWsgvBXhjnFypIrR826Z2CzXevwcpBzTR0tEl7eSrcDuRklaM4AgQJoyffMmhyvpn4IvGVzwqgclA1igVTq8sPS5mkzOmhyaxaAndRc2kPlOktkyko0nLpSLMA1ktSVnbv/fLExghyz3zuCsqhOEQAZiZ6Xkm/U2ljGyWwKBgAQIytNjPdzZv4pIGmdkjGhaZpZ0ejn64sqiJMUqDnomhs5UAT6o1DksqOegcbCFF3DmWD0CjqOVYld5/3rEJWzZaeLPiA0TzwxVZpklMkKfkIQ7j8Tf7GVuHjCHGmjXqtkSC9G/OCnnnHLEXbCQWnFNmkeyTM7uUgECpUWoeL0dAoGBALC52K+ADdU1pz2fbfyXJQiTMf5wPyehIke4Hdt3I4gvmoIf6pmlEiQLWFPRVVPFmu4HlhaXy8tosDkNntN5CohmI7XkJq1yyKKW+2dCLciGe9CP4sHzhGieg1a1W8v2F5vaeWDKEe9D9SVMo713DcR3djdC2NBQhREMBaC2oYqFAoGAJCLb37lt0fd3ycl24L8RH2KY147X94iug4Uxa6wun88x+s7588WXXOLntAeWashuODlPEAau4Dee9XP7lT8a1Lj8eo6gVbjJjJBYzwEHO0sk84WCBORcFuAsARkDPhx4wbIe2UWLEZGoVkbS0gEoSeUo/xdTJFh4tVtyedJEUuw='
        access_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJuYmYiOjE2MTE3ODI3NzQsImV4cCI6MTYxMTc4OTk3NCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdHxsb2dpbiIsInN1YiI6ImZlZmMxN2EyLTJjZTctNDVkOC04YzgzLThkNWYwMzU3MjYzYSIsInByZW1pdW0iOnRydWUsIm5hbWUiOiJhbnNpYmxlLWFkbWluIiwiZW1haWwiOiJiaXR3YXJkZW4tYWRtaW5AY2hvcGluLmRlbW9uLm5sIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJvcmdvd25lciI6W10sIm9yZ2FkbWluIjpbXSwib3JndXNlciI6W10sIm9yZ21hbmFnZXIiOltdLCJzc3RhbXAiOiJmMTUyMTFhNi00MWJiLTQ4NDctYjkwYi0zYmE4MmJhMjdmZDAiLCJkZXZpY2UiOiJhYWMyZTM0YS00NGRiLTQyYWItYTczMy01MzIyZGQ1ODJjM2QiLCJzY29wZSI6WyJhcGkiLCJvZmZsaW5lX2FjY2VzcyJdLCJhbXIiOlsiQXBwbGljYXRpb24iXX0.On71Wf9GDc_yogIjlI0ZULZAIoI9MKKQElpFhy3JedqNJIQ2JP5ZQdwMY9zjUYZkWSoxzm2D1cXfw30dMSya9o8lfJ41Agb5ubfsc5p9AiAaYLbKLK1hHqQCI6RQ-Ovi7vNOb4_rlM5Lk9QOiYgrfbdiyAwrGt3moRskfnwDMLSTJPR9CbMlNqsRCYOII-d0HTMikS3haQHcdzDLaC4APlvNUrGjT8x-W2gwZVYYk192q2_YF1GKtzds24Zbd8b9Tx2Pm7chMFqDhSR48HQ2djEDQlZZPIQKGY5XmEBCtyJj5PjV6zUOgqNJOdxu75RBigXcOeI9AHst4JzQq_-J1w"

        access_data = jwt.decode(access_token, algorithms=["RS256"], options={"verify_signature": False})

        jwt_token = Vaultwarden.email_verify_token(access_token, private_der)
        jwt_data = jwt.decode(jwt_token, algorithms=["RS256"], options={"verify_signature": False})
        assert jwt_data['iss'] == 'http://localhost|verifyemail'
        assert jwt_data['sub'] == access_data['sub']

    def test_get_users_overview(self):
        html_content = """
            <!DOCTYPE html>\n
            <html lang=\"en\">\n
            <head>\n
                <meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"/>\n
                <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\"/>\n
                <meta name=\"robots\" content=\"noindex,nofollow\"/>\n <title>Vaultwarden Admin Panel</title>\n
                <link rel=\"stylesheet\" href=\"/vaultwarden/bwrs_static/bootstrap.css\"/>\n
                <style>\n body {
                    \n padding-top: 75px;\n
                }
                \n img {
                    \n width: 48px;
                    \n height: 48px;
                    \n
                }
                \n .navbar img {
                    \n height: 24px;
                    \n width: auto;\n
                }
                \n    </style>\n
                <script src=\"/vaultwarden/bwrs_static/md5.js\"></script>\n
                <script src=\"/vaultwarden/bwrs_static/identicon.js\"></script>\n
                <script>\n
                function reload() {
                    window.location.reload();
                }\n
                function msg(text, reload_page = true) {\n
                    text && alert(text);\n
                    reload_page && reload();\n
                }\n
                function identicon(email) {\n
                    const data = new Identicon(md5(email), {size: 48, format: 'svg'});\n
                    return \"data:image/svg+xml;base64,\" + data.toString();\n        }\n        function toggleVis(input_id) {\n            const elem = document.getElementById(input_id);\n            const type = elem.getAttribute(\"type\");\n            if (type === \"text\") {\n                elem.setAttribute(\"type\", \"password\");\n            } else {\n                elem.setAttribute(\"type\", \"text\");\n            }\n            return false;\n        }\n        function _post(url, successMsg, errMsg, body, reload_page = true) {\n            fetch(url, {\n                method: 'POST',\n                body: body,\n                mode: \"same-origin\",\n                credentials: \"same-origin\",\n                headers: { \"Content-Type\": \"application/json\" }\n            }).then( resp => {\n                if (resp.ok) { msg(successMsg, reload_page); return Promise.reject({error: false}); }\n                respStatus = resp.status;\n                respStatusText = resp.statusText;\n                return resp.text();\n            }).then( respText => {\n                try {\n                    const respJson = JSON.parse(respText);\n                    return respJson ? respJson.ErrorModel.Message : \"Unknown error\";\n                } catch (e) {\n                    return Promise.reject({body:respStatus + ' - ' + respStatusText, error: true});\n                }\n            }).then( apiMsg => {\n                msg(errMsg + \"\\n\" + apiMsg, reload_page);\n            }).catch( e => {\n                if (e.error === false) { return true; }\n                else { msg(errMsg + \"\\n\" + e.body, reload_page); }\n            });\n        }\n    </script>
                \n\n
            </head>
            \n\n
            <body class=\"bg-light\">\n
            <nav class=\"navbar navbar-expand-md navbar-dark bg-dark mb-4 shadow fixed-top\">\n
            <div class=\"container\">\n <a class=\"navbar-brand\" href=\"/vaultwarden/admin\"><img class=\"pr-1\"
                                                                                                 src=\"/vaultwarden/bwrs_static/shield-white.png\">Vaultwarden
                Admin</a>\n
                <button class=\"navbar-toggler\" type=\"button\" data-toggle=\"collapse\" data-target=\"#navbarCollapse\"\n
                        aria-controls=\"navbarCollapse\" aria-expanded=\"false\" aria-label=\"Toggle navigation\
                ">\n <span class=\"navbar-toggler-icon\"></span>\n            </button>\n
                <div class=\"collapse navbar-collapse\
                " id=\"navbarCollapse\">\n
                <ul class=\"navbar-nav mr-auto\
                ">\n \n
                <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"/vaultwarden/admin\">Settings</a>\n</li>
                \n
                <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"/vaultwarden/admin/users/overview\">Users</a>\n</li>
                \n
                <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"/vaultwarden/admin/organizations/overview\">Organizations</a>\n
                </li>
                \n
                <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"/vaultwarden/admin/diagnostics\">Diagnostics</a>\n</li>
                \n \n
                <li class=\"nav-item\">\n <a class=\"nav-link\" href=\"/vaultwarden/\">Vault</a>\n</li>
                \n                </ul>\n\n \n <a class=\"btn btn-sm btn-secondary\" href=\"/vaultwarden/admin/logout\">Log Out</a>\n
                \n
            </div>
            \n        </div>\n    </nav>\n\n
            <main class=\"container\">\n
                <div id=\"users-block\" class=\"my-3 p-3 bg-white rounded shadow\
                ">\n <h6 class=\"border-bottom pb-2 mb-3\">Registered Users</h6>\n\n
                <div class=\"table-responsive-xl small\">\n
                <table id=\"users-table\" class=\"table table-sm table-striped table-hover\">\n
                <thead>\n
                <tr>\n
                    <th>User</th>\n
                    <th style=\"width:60px; min-width: 60px;\
                    ">Items</th>\n
                    <th>Attachments</th>\n
                    <th style=\"min-width: 120px;\
                    ">Organizations</th>\n
                    <th style=\"width: 140px; min-width: 140px;\
                    ">Actions</th>\n
                </tr>\n
                </thead>\n
                <tbody>\n\n
                <tr>\n
                    <td>\n <img class=\"float-left mr-2 rounded identicon\" data-src=\"user@example.com\">\n
                        <div class=\"float-left\">\n <strong>user@example.com</strong>\n 
                            <span class=\"d-block\">user@example.com</span>\n
                            <span class=\"d-block\">Created at: 2021-01-28 22:31:05 +01:00</span>\n 
                            <span class=\"d-block\">Last active: Never</span>\n
                            <span class=\"d-block\">\n\n
                                <span class=\"badge badge-danger mr-2\" title=\"User is disabled\">Disabled</span>\n \n \n \n \n 
                                <span class=\"badge badge-success mr-2\" title=\"Email has been verified\">Verified</span>\n\n
                            </span>\n
                        </div>\n
                    </td>\n
                    <td>\n <span class=\"d-block\">0</span>\n</td>\n
                    <td>\n <span class=\"d-block\"><strong>Amount:</strong> 0</span>\n \n</td>\n
                    <td>\n \n <span class=\"badge badge-primary\" data-orgtype=\"0\">Composers</span>\n \n</td>\n
                    <td style=\"font-size: 90%; text-align: right; padding-right: 15px\">\n \n 
                        <a class=\"d-block\" href=\"#\" onclick='deauthUser(&quot;aff5d3bc-e76f-45b7-83e6-fbe781cef8ab&quot;)'>Deauthorize sessions</a>\n 
                        <a class=\"d-block\" href=\"#\" onclick='deleteUser(&quot;aff5d3bc-e76f-45b7-83e6-fbe781cef8ab&quot;, &quot;user@example.com&quot;)'>Delete User</a>\n \n 
                        <a class=\"d-block\" href=\"#\" onclick='enableUser(&quot;aff5d3bc-e76f-45b7-83e6-fbe781cef8ab&quot;, &quot;user@example.com&quot;)'>Enable User</a>\n \n                        
                    </td>\n
                </tr>\n \n
                </tbody>\n
                </table>\n
                </div>\n\n
                <div class=\"mt-3\">\n
                    <button type=\"button\" class=\"btn btn-sm btn-danger\
                    " onclick=\"updateRevisions();\"\n title=\"Force all clients to fetch new data next time they connect. Useful
                    after restoring a backup to remove any stale data.\">\n Force clients to resync\n            </button>\n\n
                    <button type=\"button\" class=\"btn btn-sm btn-primary float-right\
                    " onclick=\"reload();\">Reload users</button>\n
                </div>
                \n    </div>\n\n
                <div id=\"invite-form-block\" class=\"align-items-center p-3 mb-3 text-white-50 bg-secondary rounded shadow\
                ">\n
                <div>\n <h6 class=\"mb-0 text-white\">Invite User</h6>\n <small>Email:</small>\n\n
                    <form class=\"form-inline\" id=\"invite-form\" onsubmit=\"inviteUser(); return false;\
                    ">\n <input type=\"email\" class=\"form-control w-50 mr-2\" id=\"email-invite\" placeholder=\"Enter email\">\n
                    <button type=\"submit\" class=\"btn btn-primary\
                    ">Invite</button>\n            </form>\n
                </div>
                \n    </div>\n
            </main>
            \n\n
            <link rel=\"stylesheet\" href=\"/vaultwarden/bwrs_static/datatables.css\"/>
            \n
            <script src=\"/vaultwarden/bwrs_static/jquery-3.5.1.slim.js\"></script>
            \n
            <script src=\"/vaultwarden/bwrs_static/datatables.js\"></script>
            \n
            <script>\n
            
            function deleteUser(id, mail) {\n
                var input_mail = prompt(\"To delete user '\" + mail + \"', please type the email below\")\n        if (input_mail != null) {\n            if (input_mail == mail) {\n                _post(\"/vaultwarden/admin/users/\" + id + \"/delete\",\n                    \"User deleted correctly\",\n                    \"Error deleting user\");\n            } else {\n                alert(\"Wrong email, please try again\")\n            }\n        }\n        return false;\n    }\n    function remove2fa(id) {\n        _post(\"/vaultwarden/admin/users/\" + id + \"/remove-2fa\",\n            \"2FA removed correctly\",\n            \"Error removing 2FA\");\n        return false;\n    }\n    function deauthUser(id) {\n        _post(\"/vaultwarden/admin/users/\" + id + \"/deauth\",\n            \"Sessions deauthorized correctly\",\n            \"Error deauthorizing sessions\");\n        return false;\n    }\n    function disableUser(id, mail) {\n        var confirmed = confirm(\"Are you sure you want to disable user '\" + mail + \"'? This will also deauthorize their sessions.\")\n        if (confirmed) {\n            _post(\"/vaultwarden/admin/users/\" + id + \"/disable\",\n                \"User disabled successfully\",\n                \"Error disabling user\");\n        }\n        return false;\n    }\n    function enableUser(id, mail) {\n        var confirmed = confirm(\"Are you sure you want to enable user '\" + mail + \"'?\")\n        if (confirmed) {\n            _post(\"/vaultwarden/admin/users/\" + id + \"/enable\",\n                \"User enabled successfully\",\n                \"Error enabling user\");\n        }\n        return false;\n    }\n    function updateRevisions() {\n        _post(\"/vaultwarden/admin/users/update_revision\",\n            \"Success, clients will sync next time they connect\",\n            \"Error forcing clients to sync\");\n        return false;\n    }\n    function inviteUser() {\n        inv = document.getElementById(\"email-invite\");\n        data = JSON.stringify({ \"email\": inv.value });\n        inv.value = \"\";\n        _post(\"/vaultwarden/admin/invite/\", \"User invited correctly\",\n            \"Error inviting user\", data);\n        return false;\n    }\n\n    let OrgTypes = {\n        \"0\": { \"name\": \"Owner\", \"color\": \"orange\" },\n        \"1\": { \"name\": \"Admin\", \"color\": \"blueviolet\" },\n        \"2\": { \"name\": \"User\", \"color\": \"blue\" },\n        \"3\": { \"name\": \"Manager\", \"color\": \"green\" },\n    };\n\n    document.querySelectorAll(\"img.identicon\").forEach(function (e, i) {\n        e.src = identicon(e.dataset.src);\n    });\n\n    document.querySelectorAll(\"[data-orgtype]\").forEach(function (e, i) {\n        let orgtype = OrgTypes[e.dataset.orgtype];\n        e.style.backgroundColor = orgtype.color;\n        e.title = orgtype.name;\n    });\n\n    document.addEventListener(\"DOMContentLoaded\", function(event) {\n        $('#users-table').DataTable({\n            \"responsive\": true,\n            \"lengthMenu\": [ [-1, 5, 10, 25, 50], [\"All\", 5, 10, 25, 50] ],\n            \"pageLength\": -1, // Default show all\n            \"columns\": [\n                null,                                        // Userdata\n                null,                                        // Items\n                null,                                        // Attachments\n                null,                                        // Organizations\n                { \"searchable\": false, \"orderable\": false }, // Actions\n            ],\n        });\n    });\n</script>
            \n\n    <!-- This script needs to be at the bottom, else it will fail! -->\n
            <script>\n        // get current URL path and assign 'active' class to the correct nav-item\n        (function () {\n            var pathname = window.location.pathname;\n            if (pathname === \"\") return;\n            var navItem = document.querySelectorAll('.navbar-nav .nav-item a[href=\"'+pathname+'\"]');\n            if (navItem.length === 1) {\n                navItem[0].parentElement.className = navItem[0].parentElement.className + ' active';\n            }\n        })();\n    </script>
            \n    <!-- This script needs to be at the bottom, else it will fail! -->\n
            <script src=\"/vaultwarden/bwrs_static/bootstrap-native.js\"></script>
            \n
            </body>
            \n
            </html>
        """
        expected_user = {
            'Email': 'user@example.com',
            'Locked': True,
            'CreationTimestamp': '2021-01-28 22:31:05 +01:00',
            'LoginTimestamp': '',
            'Items': 0,
            'Attachments': 0,
        }
        users = Vaultwarden.get_users_overview(html_content)
        assert users == [expected_user]
