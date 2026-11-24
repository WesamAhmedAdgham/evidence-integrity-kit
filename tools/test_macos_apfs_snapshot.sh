#!/usr/bin/env bash
# Operates only on a fresh disposable APFS image in an ephemeral CI runner.
set -Eeuo pipefail
trap 'rc=$?; echo "APFS fixture failed at line $LINENO (exit $rc): $BASH_COMMAND" >&2' ERR
set -x
base="$(mktemp -d)"
base="$(cd "$base" && pwd -P)"
live="$base/live"
snap="$base/snapshot"
image="$base/evidence.dmg"
mkdir "$live" "$snap"
attached=0
mounted=0
cleanup() {
  if [ "$mounted" = 1 ]; then sudo umount "$snap" || return 1; fi
  if [ "$attached" = 1 ]; then hdiutil detach "$live" || return 1; fi
  rm -rf -- "$base"
}
trap cleanup EXIT
cat > "$base/abi.c" <<'EOF'
#include <sys/mount.h>
#include <stddef.h>
_Static_assert(sizeof(struct statfs)==2168,"statfs ABI");
_Static_assert(offsetof(struct statfs,f_flags)==64,"flags ABI");
_Static_assert(offsetof(struct statfs,f_mntfromname)==1112,"source ABI");
_Static_assert(MNT_RDONLY==1 && MNT_NODEV==16 && MNT_LOCAL==4096 && MNT_SNAPSHOT==0x40000000,"flags ABI");
int main(void) { return 0; }
EOF
cc "$base/abi.c" -o "$base/abi"
"$base/abi"
# Blank images use -type, not the source-conversion -format option.
hdiutil create -size 256m -fs APFS -volname EIKFixture -type UDIF "$image"
hdiutil attach -plist -nobrowse -owners on -mountpoint "$live" "$image" > "$base/attach.plist"
attached=1
device="$(python -c 'import plistlib,sys; data=plistlib.load(open(sys.argv[1],"rb")); print(next(e["dev-entry"] for e in data["system-entities"] if e.get("mount-point")==sys.argv[2]))' "$base/attach.plist" "$live")"
case "$device" in /dev/disk[0-9]*s[0-9]*) ;; *) echo "Unexpected fixture device"; exit 1;; esac
sudo mkdir "$live/nested"
sudo chmod 777 "$live/nested"
printf AAAA | sudo tee "$live/nested/a" >/dev/null
printf BBBB | sudo tee "$live/b" >/dev/null
sudo chmod 666 "$live/nested/a" "$live/b"
sudo ln -s nested/a "$live/alias"
# Verify actual ordinary-volume rejection before the entitlement-dependent
# positive fixture. These negative checks never satisfy the positive gate.
python tools/check_apfs_fixture.py "$live" "$live" "eik-fixture@$device" --ordinary-live
hdiutil detach "$live"
attached=0
mkdir -p "$live"
hdiutil attach -readonly -nobrowse -owners on -mountpoint "$live" "$image" >/dev/null
attached=1
python tools/check_apfs_fixture.py "$live" "$live" "eik-fixture@$device" --ordinary-readonly
hdiutil detach "$live"
attached=0
mkdir -p "$live"
hdiutil attach -plist -nobrowse -owners on -mountpoint "$live" "$image" > "$base/attach.plist"
attached=1
device="$(python -c 'import plistlib,sys; data=plistlib.load(open(sys.argv[1],"rb")); print(next(e["dev-entry"] for e in data["system-entities"] if e.get("mount-point")==sys.argv[2]))' "$base/attach.plist" "$live")"
case "$device" in /dev/disk[0-9]*s[0-9]*) ;; *) echo "Unexpected fixture device"; exit 1;; esac
python_bin="$(command -v python)"
sudo "$python_bin" -c '
import ctypes as c, errno, os, sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY)
try:
    f=c.CDLL(None,use_errno=True).fs_snapshot_create
    f.argtypes=[c.c_int,c.c_char_p,c.c_uint32]; f.restype=c.c_int
    if f(fd,b"eik-fixture",0):
        error=c.get_errno()
        if error in (errno.EPERM, errno.EACCES):
            print("APFS positive fixture BLOCKED: snapshot creation permission denied; "
                  "macOS requires a separately authorized snapshot entitlement. "
                  "Native positive gate remains failed.", file=sys.stderr)
        raise OSError(error,os.strerror(error))
finally: os.close(fd)
' "$live"
sudo mount_apfs -o rdonly,nobrowse,nodev,nosuid -s eik-fixture "$device" "$snap"
mounted=1
expected="eik-fixture@$device"
python tools/check_apfs_fixture.py "$snap" "$live" "$expected"
python tools/check_snapshot_signed.py --macos-apfs-snapshot "$expected" "$snap"
sudo umount "$snap"
mounted=0
hdiutil detach "$live"
attached=0
