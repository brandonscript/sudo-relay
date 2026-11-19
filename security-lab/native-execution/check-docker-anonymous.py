"""Public manifest probe with fake helpers; no saved credentials or sudo used."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from run_trial import isolated_docker


def main() -> None:
    docker=shutil.which('docker')
    if docker is None:raise RuntimeError('Docker CLI required')
    image='rust@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07'
    with tempfile.TemporaryDirectory(prefix='sr-helper-probe-') as directory:
        root=Path(directory);marker=root/'helper-called'
        for name in ('osxkeychain','desktop','pass','secretservice','wincred','gcloud'):
            helper=root/('docker-credential-'+name)
            helper.write_text('#!/bin/sh\n: > "$SR_HELPER_MARKER"\nexit 42\n');helper.chmod(0o700)
        env=dict(os.environ,PATH=directory+os.pathsep+os.environ.get('PATH',''),SR_HELPER_MARKER=str(marker))
        with isolated_docker(docker):
            env.update(DOCKER_CONFIG=os.environ['DOCKER_CONFIG'],DOCKER_HOST=os.environ['DOCKER_HOST'])
            env.pop('DOCKER_CONTEXT',None);env.pop('DOCKER_AUTH_CONFIG',None)
            config=Path(env['DOCKER_CONFIG'])/'config.json';fixed=config.read_text()
            config.write_text('{"auths":{}}\n')
            subprocess.run([docker,'manifest','inspect',image],env=env,capture_output=True,timeout=60)
            if not marker.exists():raise RuntimeError('Inconclusive: empty-config control did not invoke a fake helper')
            marker.unlink();config.write_text(fixed)
            result=subprocess.run([docker,'manifest','inspect',image],env=env,capture_output=True,text=True,timeout=60)
            if marker.exists():raise RuntimeError('Anonymous config invoked a credential helper')
            if result.returncode:raise RuntimeError('Anonymous manifest fetch failed: '+result.stderr[:500])
            json.loads(result.stdout)
            print('PASS: empty config invoked fake helper; explicit anonymous config fetched public manifest without helpers')


if __name__=='__main__':main()
