"""Exercise the remote bootstrap with a local fake curl; no installs or real network."""
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash bootstrap')
class BootstrapTests(unittest.TestCase):
    def execute(self, *, corrupt=False, traversal=False, failed_download=False):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # The copied bootstrap has no sibling setup.py, so it takes the download path.
            loader = root/'install.sh';loader.write_bytes((ROOT/'install.sh').read_bytes())
            archive = root/'fixture.tar.gz'
            files = {'setup.py': b'# test fixture\n', 'site/index.html': b'<html>fixture</html>',
                     'run.sh': b'#!/bin/bash\nread -r value\nprintf "BOOTSTRAP_OK:%s:%s\\n" "$*" "$value"\n'}
            manifest = ''.join(hashlib.sha256(content).hexdigest()+'  '+name+'\n' for name,content in files.items())
            files['SHA256SUMS'] = manifest.encode()
            if corrupt:
                files['setup.py'] = b'# changed after manifest\n'
            if traversal:
                files['../outside'] = b'bad'
            with tarfile.open(archive,'w:gz') as tar:
                for name,content in files.items():
                    info = tarfile.TarInfo('fixture-root/'+name);info.size=len(content)
                    tar.addfile(info,io.BytesIO(content))
            bin_dir = root/'bin';bin_dir.mkdir()
            curl = bin_dir/'curl'
            curl.write_text('#!/bin/bash\n' + ('exit 22\n' if failed_download else
                            'while [[ $# -gt 0 ]]; do if [[ "$1" == --output ]]; then cp "$FIXTURE_TAR" "$2"; exit; fi; shift; done\nexit 1\n'))
            curl.chmod(0o755)
            env = {**os.environ,'PATH':str(bin_dir)+os.pathsep+os.environ['PATH'], 'FIXTURE_TAR':str(archive)}
            result = subprocess.run(['bash',str(loader),'plan','--non-interactive'],input='terminal-input\n',
                                    text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,timeout=20)
            self.assertFalse((root/'outside').exists())
            return result

    def test_remote_snapshot_runs_and_preserves_stdin_and_arguments(self):
        result=self.execute()
        self.assertEqual(result.returncode,0,result.stdout)
        self.assertIn('BOOTSTRAP_OK:plan --non-interactive:terminal-input',result.stdout)

    def test_corrupted_snapshot_does_not_execute(self):
        result=self.execute(corrupt=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('BOOTSTRAP_OK',result.stdout)

    def test_path_traversal_does_not_extract_or_execute(self):
        result=self.execute(traversal=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('BOOTSTRAP_OK',result.stdout)

    def test_download_failure_does_not_execute(self):
        result=self.execute(failed_download=True)
        self.assertEqual(result.returncode,22)
        self.assertNotIn('BOOTSTRAP_OK',result.stdout)
