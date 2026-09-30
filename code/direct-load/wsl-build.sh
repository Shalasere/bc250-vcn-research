#!/bin/bash
# WSL/Ubuntu cross-build recipe for BC-250's amdgpu.ko.
#
# Why WSL: on-board builds take ~10 min. WSL on a Ryzen desktop takes ~65 sec
# for the same 691 MB debug amdgpu.ko. Enables tight iteration when working on
# the vcn_v2_0 code.
#
# Prerequisites:
#   - Ubuntu 24.04 WSL (or similar) with sudo
#   - `gh` CLI authenticated (for cloning AUR mirror if you don't have sources)
#   - Access to the BC-250 board via ssh (to rsync kernel-devel headers)
#
# Toolchain quirks solved:
#   - Ubuntu 24.04 default clang 18 cannot build CachyOS 7.2.7 kernel modules
#     (needs -fexperimental-late-parse-attributes, added in clang 19).
#     Fix: install clang-20 from Ubuntu apt.
#   - CachyOS 7.2.7's shipped objtool binary needs libsframe.so.3 (binutils
#     2.43+). Ubuntu 24.04 has 2.42 / libsframe1. Fix: rsync the board's
#     /usr/lib/libsframe.so.3 next to objtool + LD_LIBRARY_PATH.
#   - CachyOS 7.2.7 requires pahole 1.27+ for BTF (needs decl_tag/type_tag/
#     optimized_func/consistent_func/decl_tag_kfuncs options). Ubuntu 24.04
#     has pahole 1.25. Fix: rsync the board's pahole 1.32 + its libdwarves*
#     libs, use via PAHOLE= + LD_LIBRARY_PATH.
#
# Set once:
#   - BOARD_HOST / BOARD_USER / BOARD_PASS (or use ssh key)
#   - KBUILD_ROOT (default /home/apple/bc250-kbuild)

set -eu

: ${BOARD_USER:=shalasere}
: ${BOARD_HOST:=10.0.0.104}
: ${KBUILD_ROOT:=/home/apple/bc250-kbuild}
: ${VCN_DIRECT_SRC_DIR:=$(pwd)}  # dir containing amdgpu_drv.c etc.

KDIR=$KBUILD_ROOT/kdev
BUILD=$KBUILD_ROOT/build
TOOLCHAIN=$KBUILD_ROOT/toolchain
mkdir -p $KBUILD_ROOT $BUILD $TOOLCHAIN

# ----- 1. Install Ubuntu-side toolchain (idempotent) -----
if ! command -v clang-20 >/dev/null; then
  echo "installing clang-20 + lld-20 + llvm-20 + kmod + dwarves"
  sudo apt-get install -y clang-20 lld-20 llvm-20 kmod dwarves
fi

# ----- 2. Rsync kernel-devel headers from board (one-shot per kernel bump) -----
if [ ! -f $KDIR/Makefile ]; then
  echo "rsync kernel-devel from board"
  rsync -avL -e "ssh -o StrictHostKeyChecking=accept-new" \
    $BOARD_USER@$BOARD_HOST:/usr/lib/modules/7.2.7-1.212-cachyos-bc250/build/ \
    $KDIR/
fi

# ----- 3. Rsync board's objtool libs + pahole (needed once) -----
if [ ! -f $TOOLCHAIN/pahole/pahole ]; then
  echo "rsync pahole 1.32 + libdwarves from board"
  mkdir -p $TOOLCHAIN/pahole
  scp -o StrictHostKeyChecking=accept-new $BOARD_USER@$BOARD_HOST:/usr/bin/pahole $TOOLCHAIN/pahole/
  scp -o StrictHostKeyChecking=accept-new $BOARD_USER@$BOARD_HOST:'/usr/lib/libdwarves*.so.1' $TOOLCHAIN/pahole/
fi

if [ ! -f $KDIR/tools/objtool/libsframe.so.3 ]; then
  echo "rsync libsframe.so.3 from board into objtool dir"
  scp -o StrictHostKeyChecking=accept-new $BOARD_USER@$BOARD_HOST:'/usr/lib/libsframe.so*' $KDIR/tools/objtool/
fi

# ----- 4. Assemble the tree (once, unless FORCE_ASSEMBLE=1) -----
if [ ! -d $BUILD/cachyos-7.2.7-1 ] || [ "${FORCE_ASSEMBLE:-0}" = "1" ]; then
  echo "assembling tree — need pristine 7.2.7 tar + 18 BC-250 patches from linux-cachyos-bc250"
  # (Your source of pristine tar and patches is up to you — grab from board:
  #  $BOARD_HOST:/home/shalasere/vcnbuild/src/cachyos-7.2.7-1.tar.gz
  #  $BOARD_HOST:/home/shalasere/vcnbuild/linux-cachyos-bc250/patches/linux-cachyos-rc/*.patch
  #  or from AUR/upstream.)
  echo "  see comments in this script for source paths"
  exit 3
fi

# ----- 5. Overlay our direct-load source files -----
echo "overlaying direct-load source files from $VCN_DIRECT_SRC_DIR"
cp $VCN_DIRECT_SRC_DIR/amdgpu_drv.c    $BUILD/cachyos-7.2.7-1/drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c
cp $VCN_DIRECT_SRC_DIR/amdgpu.h        $BUILD/cachyos-7.2.7-1/drivers/gpu/drm/amd/amdgpu/amdgpu.h
cp $VCN_DIRECT_SRC_DIR/amdgpu_vcn.c    $BUILD/cachyos-7.2.7-1/drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.c
cp $VCN_DIRECT_SRC_DIR/vcn_v2_0.c      $BUILD/cachyos-7.2.7-1/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c
cp $VCN_DIRECT_SRC_DIR/amdgpu_trace.h  $BUILD/cachyos-7.2.7-1/drivers/gpu/drm/amd/amdgpu/amdgpu_trace.h

# ----- 6. Apply discovery hunk (idempotent) -----
python3 <<'PY'
p = "$BUILD/cachyos-7.2.7-1/drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c"
import os
p = os.path.expandvars(p)
with open(p) as f: src = f.read()
old = "\t\tcase IP_VERSION(2, 0, 3):\n\t\t\tbreak;\n\t\tcase IP_VERSION(2, 5, 0):"
new = ("\t\tcase IP_VERSION(2, 0, 3):\n"
       "\t\t\tamdgpu_device_ip_block_add(adev, &vcn_v2_0_ip_block);\n"
       "\t\t\tbreak;\n"
       "\t\tcase IP_VERSION(2, 5, 0):")
if old in src:
    open(p, 'w').write(src.replace(old, new, 1))
    print("  discovery hunk applied")
else:
    print("  discovery hunk already present (or anchor changed)")
PY

# ----- 7. Build -----
M=$BUILD/cachyos-7.2.7-1/drivers/gpu/drm/amd/amdgpu
cd $BUILD/cachyos-7.2.7-1
export LD_LIBRARY_PATH="$KDIR/tools/objtool:$TOOLCHAIN/pahole${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
JOBS=$(( $(nproc) > 24 ? 24 : $(nproc) ))
time make -C $KDIR M=$M \
  LLVM=1 CC=clang-20 LD=ld.lld-20 AR=llvm-ar-20 NM=llvm-nm-20 \
  STRIP=llvm-strip-20 OBJCOPY=llvm-objcopy-20 OBJDUMP=llvm-objdump-20 \
  READELF=llvm-readelf-20 HOSTCC=clang-20 HOSTCXX=clang++-20 HOSTLD=ld.lld-20 \
  PAHOLE=$TOOLCHAIN/pahole/pahole \
  KCFLAGS=-mtune=znver2 -j$JOBS modules

echo ""
echo "=== BUILD OK ==="
modinfo -F vermagic $M/amdgpu.ko
modinfo -F parm $M/amdgpu.ko | grep vcn_direct
ls -la $M/amdgpu.ko

# ----- 8. (optional) push to board -----
if [ "${PUSH:-0}" = "1" ]; then
  echo "scp to board"
  scp $M/amdgpu.ko $BOARD_USER@$BOARD_HOST:/tmp/amdgpu.ko
  echo "  now on board: sudo cp /tmp/amdgpu.ko <your-target-path>"
fi
