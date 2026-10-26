import os, subprocess, tempfile, time, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import unknwn as U
import unknwn_integrity as IG

root = Path(tempfile.mkdtemp(prefix='unknwn_debug_parent_'))
package = root / 'UNKNWN_release'
package.mkdir(parents=True)
profile = Path(tempfile.mkdtemp(prefix='unknwn_debug_profile_'))
home = profile / '.unknwn'
home.mkdir(parents=True)
exe = package / 'UNKNWN.exe'
exe.write_bytes(b'fixture executable')
(package / 'nested' / 'deeper').mkdir(parents=True)
(package / 'nested' / 'deeper' / 'payload.dat').write_bytes(b'nested fixture')
os.environ['USERPROFILE'] = str(profile)
# Monkeypatch integrity verification used during cleanup for this isolated test
IG.verify_dir = lambda path, key: True

child_code = ("import ctypes,sys,time; k=ctypes.windll.kernel32; "
              "k.CreateFileW.restype=ctypes.c_void_p; "
              "h=k.CreateFileW(sys.argv[1],0x80000000,1,None,3,0x80,None); "
              "assert h not in (None,0,ctypes.c_void_p(-1).value); "
              "time.sleep(1.5); k.CloseHandle(h)")
child = subprocess.Popen([sys.executable, '-c', child_code, str(exe)], env=os.environ.copy())

try:
    command = U.windows_cleanup_command(package, home, child.pid, restart=False)
except Exception as e:
    child.terminate(); child.wait(timeout=5)
    print('windows_cleanup_command error:', e)
    raise

print('command length', len(subprocess.list2cmdline(command)))
print('command chunk 0..5', command[:6])

cleanup = subprocess.Popen(command, env=os.environ.copy(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# verify cleanup waited while process holds exe
time.sleep(.35)
print('package exists during hold:', package.exists())

out, err = cleanup.communicate(timeout=120)
# write stderr to a file for inspection
stderr_file = Path(__file__).resolve().parent.parent / 'files' / 'cleanup-powershell-stderr.xml'
stderr_file.parent.mkdir(parents=True, exist_ok=True)
with open(stderr_file, 'wb') as f:
    f.write(err)
print('child pid', child.pid)
child.wait(timeout=5)
print('cleanup exit', cleanup.returncode)
print('stdout:', out.decode(errors='replace'))
print('stderr len:', len(err))
print('wrote stderr to', stderr_file)
print('package exists after:', package.exists())
print('home exists after:', home.exists())
print('root marker exists after:', (root / 'keep-parent.txt').exists())
print('done')