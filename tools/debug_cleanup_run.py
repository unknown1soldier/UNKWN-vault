import os, subprocess, tempfile, time
from pathlib import Path
import sys
from typing import Callable, cast
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import unknwn as U
import unknwn_integrity as IG

decode_cleanup_command = cast(
    Callable[[str], str], getattr(U, "_decode_cleanup_command"))
windows_powershell_path = cast(
    Callable[[], Path], getattr(U, "_windows_powershell_path"))

# Create temp dirs similar to the test
root = Path(tempfile.mkdtemp(prefix='unknwn_debug_parent_'))
package = root / 'UNKNWN_release'
package.mkdir(parents=True)
(profile) = Path(tempfile.mkdtemp(prefix='unknwn_debug_profile_'))
home = profile / '.unknwn'
home.mkdir(parents=True)
# Create files
exe = package / 'UNKNWN.exe'
exe.write_bytes(b'fixture executable')
(package / 'nested' / 'deeper').mkdir(parents=True)
(package / 'nested' / 'deeper' / 'payload.dat').write_bytes(b'nested fixture')
# call windows_cleanup_command
os.environ['USERPROFILE'] = str(profile)
# Monkeypatch integrity verification used during cleanup for this isolated test
IG.RELEASE_PUBKEY = b'fake'
IG.verify_dir = lambda path, key: True
# spawn a child process that opens the exe and holds it for 1.5s, like the unit test
child_code = ("import ctypes,sys,time; k=ctypes.windll.kernel32; "
              "k.CreateFileW.restype=ctypes.c_void_p; "
              "h=k.CreateFileW(sys.argv[1],0x80000000,1,None,3,0x80,None); "
              "assert h not in (None,0,ctypes.c_void_p(-1).value); "
              "time.sleep(1.5); k.CloseHandle(h)")
child = subprocess.Popen([sys.executable, '-c', child_code, str(exe)], env=os.environ.copy())
try:
    cmd = U.windows_cleanup_command(package, home, child.pid, restart=False)
except Exception as e:
    child.terminate(); child.wait(timeout=5)
    print('windows_cleanup_command error:', e)
    raise
script = decode_cleanup_command(cmd[-1])
# write script to file and execute
ps = profile / 'debug_cleanup.ps1'
ps.write_text(script, encoding='utf-8')
print('script written to', ps)
# set env for cleanup process
env = os.environ.copy()
env['USERPROFILE'] = str(profile)
# run script
cleanup = subprocess.Popen([windows_powershell_path(), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(ps)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# verify cleanup waited while process holds exe
time.sleep(.35)
print('package exists during hold:', package.exists())
out, err = cleanup.communicate(timeout=120)
print('child pid', child.pid)
child.wait(timeout=5)
print('cleanup exit', cleanup.returncode)
print('stdout:', out.decode(errors='replace'))
print('stderr:', err.decode(errors='replace'))
# print debug log if present
log = profile / 'cleanup-debug.log'
print('debug log exists:', log.exists())
if log.exists():
    print('--- debug log ---')
    print(log.read_text())

print('package exists after:', package.exists())
print('home exists after:', home.exists())
print('root marker exists after:', (root / 'keep-parent.txt').exists())

print('done')
