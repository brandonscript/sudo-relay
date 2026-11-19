"""Check the built artifact, not just Xcode's requested settings. Never launches."""
from pathlib import Path
import plistlib
import sys

app = Path(sys.argv[1])
info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
assert info['CFBundleName'] == info['CFBundleDisplayName'] == 'sudo-relay'
assert info['CFBundleIconFile'] == 'sudo-relay.icns'
assert (app / 'Contents/MacOS' / info['CFBundleExecutable']).is_file()
source = Path(__file__).resolve().parents[2] / 'assets/icon/sudo-relay.icns'
assert (app / 'Contents/Resources/sudo-relay.icns').read_bytes() == source.read_bytes()
print('Built app name, executable and approved icon verified; nothing launched.')
