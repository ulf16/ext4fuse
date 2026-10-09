#!/bin/sh
# Fsck-certified largedir through macFUSE, including paged directory listings.
set -eu
[ "$(uname -s)" = Darwin ] || exit 1
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/ext4fuse-largedir-mount.XXXXXX")
reader_pid=
reader_device=
cleanup() {
    /sbin/umount "$fixture_dir/mount" 2>/dev/null || true
    if [ -n "$reader_pid" ]; then kill "$reader_pid" 2>/dev/null || true; wait "$reader_pid" 2>/dev/null || true; fi
    if /sbin/mount | grep -F " on $fixture_dir/mount (" >/dev/null; then
        echo "Mount remains active; retaining $fixture_dir" >&2
    else
        if [ -n "$reader_device" ] && ! hdiutil detach "$reader_device" >/dev/null; then
            echo "Device remains attached; retaining $fixture_dir" >&2
            return
        fi
        rm -rf "$fixture_dir"
    fi
}
trap cleanup EXIT HUP INT TERM
python3 - "$fixture_dir" "$(dirname "$0")/largedir-set.c" <<'PY'
import hashlib,os,pathlib,re,shlex,shutil,subprocess,sys
r=pathlib.Path(sys.argv[1]);image=r/'image';host=r/'payload';host.write_bytes(b'large-directory payload')
with image.open('wb') as f:f.truncate(64*1024**2)
mkfs=shutil.which('mke2fs');debugfs=shutil.which('debugfs');fsck=shutil.which('e2fsck');assert mkfs and debugfs and fsck
subprocess.run([mkfs,'-q','-F','-t','ext4','-b','1024','-O','large_dir,metadata_csum_seed',str(image)],check=True,capture_output=True)
names=['file%04d'%i+'x'*100 for i in range(1100)]
commands=r/'commands';commands.write_text('mkdir /many\n'+''.join('write %s /many/%s\n'%(host,n) for n in names))
subprocess.run([debugfs,'-w','-f',str(commands),str(image)],check=True,capture_output=True)
p=subprocess.run([fsck,'-fyD',str(image)],capture_output=True);assert p.returncode in [0,1],p.stdout+p.stderr
stat=subprocess.run([debugfs,'-R','stat /many',str(image)],check=True,capture_output=True,text=True).stdout
number=re.search(r'Inode:\s*(\d+)',stat).group(1)
env=os.environ.copy();prefix=pathlib.Path(mkfs).resolve().parent.parent;env['PKG_CONFIG_PATH']=str(prefix/'lib/pkgconfig')+os.pathsep+env.get('PKG_CONFIG_PATH','')
flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','--static','ext2fs'],env=env,text=True))
subprocess.run(['cc',sys.argv[2],*flags,'-o',str(r/'deepen')],check=True)
subprocess.run([str(r/'deepen'),str(image),number],check=True)
p=subprocess.run([fsck,'-fn',str(image)],capture_output=True);assert p.returncode==0,p.stdout+p.stderr
(r/'before').write_text(hashlib.sha256(image.read_bytes()).hexdigest());(r/'mount').mkdir()
PY
reader_input="$fixture_dir/image"
if [ "${RAW_DEVICE:-0}" = 1 ]; then
    hdiutil attach -readonly -nomount -imagekey diskimage-class=CRawDiskImage -plist "$reader_input" > "$fixture_dir/device.plist"
    reader_device=$(python3 - "$fixture_dir/device.plist" <<'PYDEVICE'
import plistlib,sys
with open(sys.argv[1],'rb') as f:entries=plistlib.load(f)['system-entities']
print(min([e['dev-entry'] for e in entries if 'dev-entry' in e],key=len))
PYDEVICE
)
    reader_input=$(printf '%s' "$reader_device" | sed 's,^/dev/disk,/dev/rdisk,')
fi
"${READER:-./ext4fuse}" "$reader_input" "$fixture_dir/mount" -f -s -o ro,default_permissions > "$fixture_dir/reader.log" 2>&1 &
reader_pid=$!
attempt=0
until [ -d "$fixture_dir/mount/many" ]; do
    attempt=$((attempt+1))
    if [ "$attempt" -ge 40 ] || ! kill -0 "$reader_pid" 2>/dev/null; then cat "$fixture_dir/reader.log" >&2; exit 1; fi
    sleep 0.25
done
python3 - "$fixture_dir" <<'PY'
import errno,hashlib,os,pathlib,sys,time
r=pathlib.Path(sys.argv[1]);d=r/'mount/many';names=['file%04d'%i+'x'*100 for i in range(1100)]
start=time.monotonic();assert set(os.listdir(d))==set(names)
assert {e.name for e in os.scandir(d)}==set(names)
for i in [0,549,1099]:assert (d/names[i]).read_bytes()==b'large-directory payload'
assert not (d/'missing').exists()
try:(d/'new').write_bytes(b'no')
except OSError as e:assert e.errno==errno.EROFS,e
else:raise AssertionError('write succeeded')
assert hashlib.sha256((r/'image').read_bytes()).hexdigest()==(r/'before').read_text()
print('PASS: mounted three-level largedir, complete/paged 1100-name listings, lookup and write rejection (%.3fs)'%(time.monotonic()-start))
PY
