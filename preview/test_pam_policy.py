import unittest
from admin import reviewed_pam
class PamTests(unittest.TestCase):
    def test_stock_only_and_mfa_or_custom_include_rejected(self):
        sudo='session required pam_env.so\n@include common-auth\n@include common-account\n@include common-session-noninteractive\n'
        common='auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\n'
        reviewed_pam(sudo,common);reviewed_pam(sudo,common+'auth optional pam_cap.so\n')
        for bad in (common+'auth required pam_google_authenticator.so\n',common.replace('pam_unix.so nullok','pam_sss.so'),common+'@include company-auth\n'):
            with self.assertRaises(RuntimeError):reviewed_pam(sudo,bad)
        for bad in (sudo+'auth required pam_u2f.so\n',sudo.replace('common-auth','company-auth')):
            with self.assertRaises(RuntimeError):reviewed_pam(bad,common)
if __name__=='__main__':unittest.main(verbosity=2)
