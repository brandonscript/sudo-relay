"""A persistent MCP connection must leave room for a concurrent review connection."""
from __future__ import annotations
import importlib.util,socket,sys,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('relay',Path(__file__).resolve().parents[1]/'security-lab/native-execution/loopback.py')
assert spec and spec.loader
relay=importlib.util.module_from_spec(spec);spec.loader.exec_module(relay)
class CarrierTests(unittest.TestCase):
    def test_persistent_mcp_and_review_can_coexist_and_close(self):
        with tempfile.TemporaryDirectory() as directory:
            echo=Path(directory)/'echo.py';echo.write_text('import sys\nwhile data:=sys.stdin.buffer.read1(16384):\n sys.stdout.buffer.write(data);sys.stdout.buffer.flush()\n')
            with relay.LoopbackRelay('','preview',command=[sys.executable,str(echo)],connections=3,idle_timeout=None) as carrier:
                port=carrier.port
                with socket.create_connection(('127.0.0.1',port),timeout=5) as mcp,socket.create_connection(('127.0.0.1',port),timeout=5) as review:
                    mcp.sendall(b'mcp');self.assertEqual(mcp.recv(3),b'mcp')
                    review.sendall(b'review');self.assertEqual(review.recv(6),b'review')
                    mcp.sendall(b'still-open');self.assertEqual(mcp.recv(10),b'still-open')
            with self.assertRaises(OSError):socket.create_connection(('127.0.0.1',port),timeout=1)
    def test_bad_bounds_fail_before_start(self):
        for value in (-1,65536,True):
            with self.assertRaises(ValueError):relay.LoopbackRelay('','preview',command=['unused'],port=value)
if __name__=='__main__':unittest.main(verbosity=2)
