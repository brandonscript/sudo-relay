"""Real subprocess stdio/correlation test; fake reviewer records only its reference."""
from __future__ import annotations
import json,os,select,subprocess,sys,tempfile,time,unittest,uuid
from pathlib import Path

class StdioTests(unittest.TestCase):
    def test_remote_failure_exits_cleanly_with_client_input_still_open(self):
        module=Path(__file__).resolve().parent
        config={'mcp_command':[sys.executable,'-c','raise SystemExit(1)'],'reviewer':'/unused','enrollment':'/unused'}
        code='import sys,json;sys.path.insert(0,'+repr(str(module))+');from mac_mcp import bridge;bridge(json.loads(sys.argv[1]))'
        child=subprocess.Popen([sys.executable,'-I','-c',code,json.dumps(config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            child.wait(timeout=10)
            self.assertEqual(child.returncode,1)
            self.assertNotIn(b'Fatal Python error',child.stderr.read())
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)
            for stream in (child.stdin,child.stdout,child.stderr):stream.close()

    def test_response_forwarded_and_one_review_reference_opened_without_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);identifier=str(uuid.uuid4());record=root/'reference.json'
            server=root/'server.py';server.write_text('import sys,json\nfor line in sys.stdin:\n m=json.loads(line)\n print(json.dumps({"jsonrpc":"2.0","id":m["id"],"result":{"structuredContent":{"envelope":{"id":"'+identifier+'"}}}}),flush=True)\n')
            reviewer=root/'reviewer';reviewer.write_text('#!'+sys.executable+'\nimport sys,json\nfrom pathlib import Path\nPath('+repr(str(record))+').write_text(json.dumps(sys.argv[1:]))\n');reviewer.chmod(0o700)
            config={'mcp_command':[sys.executable,str(server)],'reviewer':str(reviewer),'enrollment':'/protected/enrollment'}
            module=Path(__file__).resolve().parent
            code='import sys,json;sys.path.insert(0,'+repr(str(module))+');from mac_mcp import bridge;bridge(json.loads(sys.argv[1]))'
            child=subprocess.Popen([sys.executable,'-I','-c',code,json.dumps(config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                message={'jsonrpc':'2.0','id':17,'method':'tools/call','params':{'name':'request_execution'}}
                child.stdin.write(json.dumps(message)+'\n');child.stdin.flush()
                self.assertTrue(select.select([child.stdout],[],[],5)[0]);reply=json.loads(child.stdout.readline())
                self.assertEqual(reply['result']['structuredContent']['envelope']['id'],identifier)
                for _ in range(100):
                    if record.exists():break
                    time.sleep(.01)
                self.assertEqual(json.loads(record.read_text()),['/protected/enrollment',identifier])
                child.stdin.close();child.stdin=None
                stdout,stderr=child.communicate(timeout=10)
                self.assertEqual(child.returncode,0,stderr);self.assertEqual(stdout,'')
            finally:
                if child.poll() is None:child.kill();child.communicate(timeout=5)
if __name__=='__main__':unittest.main(verbosity=2)
