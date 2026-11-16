#!/usr/bin/env bash
# Build Debian/Ubuntu/Kali .deb package for impacket-rs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

VERSION="$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -n 1 | cut -d'"' -f4)"
ARCH="amd64"
DEB_NAME="impacket-rs_${VERSION}_${ARCH}"
BUILD_ROOT="/tmp/${DEB_NAME}"

echo "[*] Building impacket-rs release binary (x86_64-unknown-linux-musl)..."
cargo build --release --locked --target x86_64-unknown-linux-musl || cargo build --release --locked

TARGET_BIN="target/x86_64-unknown-linux-musl/release/impacket-rs"
if [ ! -f "${TARGET_BIN}" ]; then
    TARGET_BIN="target/release/impacket-rs"
fi

echo "[*] Assembling package tree at ${BUILD_ROOT}..."
rm -rf "${BUILD_ROOT}"
mkdir -p "${BUILD_ROOT}/DEBIAN"
mkdir -p "${BUILD_ROOT}/usr/bin"
mkdir -p "${BUILD_ROOT}/usr/include"
mkdir -p "${BUILD_ROOT}/usr/share/doc/impacket-rs"

install -m 755 "${TARGET_BIN}" "${BUILD_ROOT}/usr/bin/impacket-rs"
install -m 644 crates/impacket-cabi/include/impacket.h "${BUILD_ROOT}/usr/include/impacket.h"
install -m 644 packaging/debian/copyright "${BUILD_ROOT}/usr/share/doc/impacket-rs/copyright"

BIN_SIZE_KB=$(du -k "${TARGET_BIN}" | cut -f1)

sed "s/@VERSION@/${VERSION}/g" "${SCRIPT_DIR}/debian/control.template" > "${BUILD_ROOT}/DEBIAN/control"
echo "Installed-Size: ${BIN_SIZE_KB}" >> "${BUILD_ROOT}/DEBIAN/control"

echo "[*] Generating ${DEB_NAME}.deb..."
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "${BUILD_ROOT}" "${ROOT_DIR}/${DEB_NAME}.deb"
else
    python3 -c "
import os, sys, tarfile, io, time

root = '${BUILD_ROOT}'
output = '${ROOT_DIR}/${DEB_NAME}.deb'

def make_ar(name, size, mode=0o100644):
    m = int(time.time())
    return f'{name:<16}{m:<12}{0:<6}{0:<6}{mode:<8o}{size:<10}{chr(0x60)}\n'.encode('ascii')

c_buf = io.BytesIO()
with tarfile.open(fileobj=c_buf, mode='w:gz', format=tarfile.GNU_FORMAT) as t:
    t.add(os.path.join(root, 'DEBIAN/control'), arcname='./control')
c_tar = c_buf.getvalue()

d_buf = io.BytesIO()
with tarfile.open(fileobj=d_buf, mode='w:gz', format=tarfile.GNU_FORMAT) as t:
    for d, _, files in os.walk(root):
        if 'DEBIAN' in d: continue
        rel_d = './' + os.path.relpath(d, root)
        if rel_d != './':
            ti = tarfile.TarInfo(name=rel_d)
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            t.addfile(ti)
        for f in files:
            full = os.path.join(d, f)
            rel = './' + os.path.relpath(full, root)
            t.add(full, arcname=rel)
d_tar = d_buf.getvalue()

with open(output, 'wb') as f:
    f.write(b'!<arch>\n')
    f.write(make_ar('debian-binary', 4))
    f.write(b'2.0\n')
    f.write(make_ar('control.tar.gz', len(c_tar)))
    f.write(c_tar)
    if len(c_tar) % 2 != 0: f.write(b'\n')
    f.write(make_ar('data.tar.gz', len(d_tar)))
    f.write(d_tar)
    if len(d_tar) % 2 != 0: f.write(b'\n')
"
fi

rm -rf "${BUILD_ROOT}"
echo "[+] Debian package created at: ${ROOT_DIR}/${DEB_NAME}.deb"
