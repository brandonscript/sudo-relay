"""Check the human-trial session without biometrics, host sudo, mounts or published ports."""
from __future__ import annotations
import json
from pathlib import Path
import select
import subprocess
import unittest
import uuid

REPO = Path(__file__).resolve().parents[2]
COMPOSE = ['docker','compose','-p','sudo-relay-integrated','-f',str(REPO/'security-lab/integrated-sudo/compose.yaml')]


class HumanSession(unittest.TestCase):
    def test_public_key_only_request_cancel_and_cleanup(self) -> None:
        public = json.loads((REPO/'ui/test/p256-fixture.json').read_text())['public_key_sec1']
        name = 'sudo-relay-human-check-'+uuid.uuid4().hex[:12]
        child = subprocess.Popen(COMPOSE+['run','--rm','--no-deps','-T','--name',name,
            '--entrypoint','python3','integration','-I','/integration/human_session.py'],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            def call(value: dict[str, object]) -> dict[str, object]:
                assert child.stdin and child.stdout
                child.stdin.write(json.dumps(value)+'\n');child.stdin.flush()
                self.assertTrue(select.select([child.stdout],[],[],20)[0],'session response timed out')
                line = child.stdout.readline()
                self.assertTrue(line,'session closed without a reply')
                result = json.loads(line);self.assertTrue(result['ok'],result)
                return result
            ready = call({'public_key':'p256-sha256:'+public})
            self.assertTrue(ready['software_approval_key_absent'])
            # The transport identity is deliberately not printed or persisted by this check.
            self.assertIn('OPENSSH PRIVATE KEY',str(ready['transport_identity']))
            self.assertEqual(ready['account'],'sponsor_a')
            pending = call({'operation':'request'})['pending']
            self.assertIsInstance(pending,dict)
            assert isinstance(pending,dict)
            env = pending['envelope']
            self.assertEqual(env['spec']['command']['argv'],['/usr/bin/id','-u'])
            self.assertEqual(env['expires_at']-env['created_at'],300)
            result = call({'operation':'status'})
            self.assertEqual(result['sudo_launches'],0)
            cancel = subprocess.run(['docker','exec','-i','--user','11003:11004',name,
                '/usr/local/bin/integrated-sudo-lab','review-channel'],
                input=json.dumps({'method':'cancel_execution','id':env['id']}),capture_output=True,text=True,timeout=10)
            self.assertEqual(cancel.returncode,0,cancel.stderr)
            self.assertTrue(json.loads(cancel.stdout)['ok'])
            result = call({'operation':'status'})
            self.assertEqual(result['status']['state'],'cancelled')
            self.assertEqual(result['sudo_launches'],0)
            assert child.stdin
            child.stdin.write('{"operation":"stop"}\n');child.stdin.flush()
            child.communicate(timeout=10)
            self.assertEqual(child.returncode,0)
            gone = subprocess.run(['docker','inspect',name],capture_output=True,timeout=10)
            self.assertNotEqual(gone.returncode,0,'container remained after stop')
        finally:
            subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=10)
            if child.poll() is None: child.kill()
            child.communicate(timeout=5)


if __name__=='__main__':
    unittest.main(verbosity=2)
