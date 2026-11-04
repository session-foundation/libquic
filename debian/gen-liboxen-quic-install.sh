#!/bin/bash

set -e

UPSTREAM_VER="$1"
LIB_VER="${UPSTREAM_VER/[^0-9.]*/}"
LIB_VER="${LIB_VER%.[0-9]*}"

rm -f debian/liboxen-quic*[0-9].install

for lib in -utils -event ""; do
    pkg="liboxen-quic$lib$LIB_VER"
    if ! grep -q "^Package: $pkg\$" debian/control; then
        echo -e "\nError: debian/control doesn't contain the correct $pkg version; you should run:\n\n    ./debian/update-lib-version.sh\n"
        exit 1
    fi
    echo "usr/lib/*/liboxenquic$lib.so.$LIB_VER" >"debian/$pkg.install"
done
