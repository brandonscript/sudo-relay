import base64,hashlib,unittest,uuid
from mac_setup import validate,matches_transport_key
class SetupTests(unittest.TestCase):
    def test_transport_key_comments_do_not_change_identity(self):
        key=self.fixture()['agent_transport_public_key']
        self.assertTrue(matches_transport_key(key,key))
        self.assertTrue(matches_transport_key(key+' owner@machine\n',key))
        self.assertFalse(matches_transport_key(self.fixture()['review_transport_public_key'],key))
        self.assertFalse(matches_transport_key('ssh-rsa '+key.split()[1],key))
        self.assertFalse(matches_transport_key('',key))
    def fixture(self):
        raw='04'+'11'*64
        return dict(version=1,machine_id=str(uuid.uuid4()),machine_name='Test VM',operating_system='Ubuntu 24.04',account='owner',
            agent_account='sr-agent-1234',review_account='sr-review-1234',lima_vm='preview-test',remote_port=2222,
            team='R86CYUZWPR',bundle_id='com.sudorelay.test',keychain_group='R86CYUZWPR.com.sudorelay.test',cdhash='a'*40,binary_sha256='b'*64,
            signing_key='p256-sha256:'+raw,key_fingerprint=hashlib.sha256(bytes.fromhex(raw)).hexdigest(),
            agent_transport_public_key='ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'a'*32).decode(),
            review_transport_public_key='ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'r'*32).decode(),
            host_key='sudo-relay-linux ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+b'x'*32).decode()+'\n')
    def test_plan_binds_key_identity_and_safe_transport(self):
        value=self.fixture();validate(value)
        for key,bad in [('machine_id','bad'),('account','spoof\nroot'),('review_account','root'),('review_account',value['agent_account']),
                        ('remote_port',True),('lima_vm','--set=bad'),('signing_key','00'),('key_fingerprint','c'*64),
                        ('team','bad" or true'),('host_key','* ssh-ed25519 AAAA\n')]:
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError)):validate({**value,key:bad})
if __name__=='__main__':unittest.main(verbosity=2)
