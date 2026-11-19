import base64,unittest
from channel_setup import public_key,configure
from install_context import Sponsor
class KeyTests(unittest.TestCase):
    def test_only_exact_ed25519_transport_key_is_accepted(self):
        blob=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'x'*32
        key='ssh-ed25519 '+base64.b64encode(blob).decode()
        self.assertEqual(public_key(key),key)
        with self.assertRaises(ValueError):configure(Sponsor('owner',1234,1234,'/home/owner','/bin/sh'),key,key)
        for value in ('command="sh" '+key,key+' comment','ssh-rsa '+key.split()[1],'ssh-ed25519 bad!', 'ssh-ed25519 '+base64.b64encode(blob[:-1]).decode()):
            with self.subTest(value=value),self.assertRaises(ValueError):public_key(value)
if __name__=='__main__':unittest.main(verbosity=2)
