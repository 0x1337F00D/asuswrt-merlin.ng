#!/usr/bin/env bash
set -euo pipefail
umask 077
export TMPDIR=${TMPDIR:-/tmp}
[[ $(findmnt -n -o FSTYPE -T "$TMPDIR") == tmpfs ]]
tests=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
trial=$(mktemp -d "$TMPDIR/maclist-adapter-test.XXXXXX")
compiler=${HOST_CC:-cc}
"$compiler" -std=c11 -Wall -Wextra -Werror -fPIC -shared -DV4_PROVIDER \
    "$tests/bsd-maclist-adapter-fixture.c" -o "$trial/libmaclist-v4.so"
"$compiler" -std=c11 -Wall -Wextra -Werror -fPIC -shared \
    "$tests/../diagnostics/compat/bsd-maclist-v3.c" -ldl -o "$trial/adapter.so"
"$compiler" -std=c11 -Wall -Wextra -Werror "$tests/bsd-maclist-adapter-fixture.c" \
    -L"$trial" -lmaclist-v4 -o "$trial/probe"
LD_LIBRARY_PATH="$trial" LD_PRELOAD="$trial/adapter.so" "$trial/probe"
