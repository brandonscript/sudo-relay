"""Identity forgery and per-sponsor namespace checks; no elevated operations."""
import os
import pwd
import unittest
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch
from install_context import Sponsor,InstallPaths,sponsoring_account,read_source

class ContextTests(unittest.TestCase):
    def test_account_provenance_must_match_all_sudo_fields(self):
        account=pwd.struct_passwd(('alice','x',1234,5678,'','/home/alice','/bin/sh'))
        env={'SUDO_USER':'alice','SUDO_UID':'1234','SUDO_GID':'5678'}
        self.assertEqual(Sponsor.from_record(env,account).uid,1234)
        for key,value in [('SUDO_USER','other'),('SUDO_UID','0'),('SUDO_UID','4321'),('SUDO_GID','1'),('SUDO_UID','bad')]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):Sponsor.from_record({**env,key:value},account)
        with self.assertRaises(ValueError):Sponsor.from_record({},account)

    def test_forged_environment_cannot_replace_real_sudo_elevation(self):
        with patch.dict(os.environ,{'SUDO_USER':'root','SUDO_UID':'0','SUDO_GID':'0'}),patch('install_context.os.getuid',return_value=1234):
            with self.assertRaises(PermissionError):sponsoring_account()

    def test_paths_are_separate_and_cannot_be_selected_by_names(self):
        for uid in (1234,4321):
            p=InstallPaths(uid)
            self.assertEqual(p.configuration.name,str(uid))
            self.assertEqual(p.socket.parent.name,str(uid))
        self.assertNotEqual(InstallPaths(1234).state,InstallPaths(4321).state)
        for uid in (0,-1,True,'../root'):
            with self.assertRaises(ValueError):InstallPaths(uid)

    def test_source_reader_rejects_symlinks_and_oversized_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source';path.write_bytes(b'public source')
            self.assertEqual(read_source(path,os.getuid(),os.getgid()),b'public source')
            link=Path(directory)/'link';link.symlink_to(path)
            with self.assertRaises(subprocess.CalledProcessError):read_source(link,os.getuid(),os.getgid())
            with self.assertRaises(subprocess.CalledProcessError):read_source(path,os.getuid(),os.getgid(),1)

if __name__=='__main__':unittest.main(verbosity=2)
