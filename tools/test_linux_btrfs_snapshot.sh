#!/usr/bin/env bash
# Only a fresh synthetic loopback image is formatted. No user/system disk.
set -euo pipefail
base="$(mktemp -d)"
mnt="$base/mount"
robind="$base/robind"
image="$base/evidence.img"
mkdir "$mnt" "$robind"
cleanup() {
  if mountpoint -q "$mnt/snapshot/nested"; then sudo umount "$mnt/snapshot/nested" || return 1; fi
  if mountpoint -q "$robind"; then sudo umount "$robind" || return 1; fi
  if mountpoint -q "$mnt"; then sudo umount "$mnt" || return 1; fi
  rm -rf -- "$base"
}
trap cleanup EXIT
truncate -s 256M "$image"
mkfs.btrfs -q "$image"
sudo mount -t btrfs -o loop,nodev,nosuid,noexec "$image" "$mnt"
sudo btrfs subvolume create "$mnt/source"
sudo mkdir "$mnt/source/nested"
sudo chmod 777 "$mnt/source/nested"
printf AAAA | sudo tee "$mnt/source/nested/a" >/dev/null
printf BBBB | sudo tee "$mnt/source/b" >/dev/null
sudo chmod 666 "$mnt/source/nested/a" "$mnt/source/b"
sudo ln -s nested/a "$mnt/source/alias"
sudo btrfs subvolume snapshot -r "$mnt/source" "$mnt/snapshot"
sudo btrfs subvolume snapshot "$mnt/source" "$mnt/mutable"
expected="$(sudo btrfs subvolume show "$mnt/snapshot" | awk '$1=="UUID:"{print $2}')"
other="$(sudo btrfs subvolume show "$mnt/mutable" | awk '$1=="UUID:"{print $2}')"
sudo mount --bind "$mnt/mutable" "$robind"
sudo mount -o remount,bind,ro "$robind"
python tools/check_btrfs_fixture.py "$mnt/snapshot" "$mnt/source" "$robind" "$expected" "$other"
python tools/check_snapshot_signed.py --linux-btrfs-snapshot "$expected" "$mnt/snapshot"
sudo mount --bind "$mnt/source/nested" "$mnt/snapshot/nested"
python tools/check_btrfs_fixture.py --mount-crossing "$mnt/snapshot" "$expected"
