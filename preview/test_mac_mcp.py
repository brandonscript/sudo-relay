"""Exercise MCP request/result correlation without native UI or signatures."""
import unittest
from unittest.mock import patch,Mock
import uuid
from mac_mcp import ReviewTrigger
class TriggerTests(unittest.TestCase):
    def test_only_correlated_success_opens_exact_request_once(self):
        trigger=ReviewTrigger('/protected/reviewer','/protected/enrollment')
        request={'method':'tools/call','id':7,'params':{'name':'request_execution'}}
        identifier=str(uuid.uuid4())
        response={'id':7,'result':{'structuredContent':{'envelope':{'id':identifier}}}}
        with patch('mac_mcp.subprocess.Popen') as launch:
            launch.return_value.poll.return_value=0
            trigger.response(response);launch.assert_not_called()
            trigger.request(request);trigger.response(response)
            self.assertEqual(launch.call_args.args[0],['/protected/reviewer','/protected/enrollment',identifier])
            trigger.request(request);trigger.response(response);self.assertEqual(launch.call_count,1)
    def test_errors_other_tools_and_injected_references_do_not_open(self):
        with patch('mac_mcp.subprocess.Popen') as launch:
            for result in ({'isError':True},{'structuredContent':{'envelope':{'id':'--enroll'}}},{'structuredContent':{'envelope':{'id':'../../other'}}}):
                t=ReviewTrigger('/reviewer','/enrollment');t.request({'id':1,'method':'tools/call','params':{'name':'request_execution'}})
                try:t.response({'id':1,'result':result})
                except ValueError:pass
            t=ReviewTrigger('/reviewer','/enrollment');t.request({'id':1,'method':'tools/call','params':{'name':'execution_status'}})
            t.response({'id':1,'result':{'structuredContent':{'envelope':{'id':str(uuid.uuid4())}}}})
            launch.assert_not_called()
if __name__=='__main__':unittest.main(verbosity=2)
