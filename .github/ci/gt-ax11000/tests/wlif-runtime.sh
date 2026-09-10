#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixture_dir="$(mktemp -d /tmp/gt-wlif-runtime.XXXXXX)"
# Keep this fixture independent of a router checkout. Extract the exact
# added C runner from the overlay, not a test-side copy of its algorithm.
perl -0777 -e '
  open my $p, "<", $ARGV[0] or die $!; local $/; my $patch = <$p>;
  $patch =~ /\+\#ifndef WLIF_CLI_TIMEOUT_MS\n(.*?)\+\#endif\t\/\* WLIF_ARGV_EXEC \*\//s or die "runner missing";
  my $runner = "+#ifndef WLIF_CLI_TIMEOUT_MS\n" . $1;
  $runner =~ s/^\+//mg;
  $patch =~ /\+\#ifndef _GNU_SOURCE\n\+\#define _GNU_SOURCE\n\+\#endif/ or die "feature macro missing";
  my $features = $&; $features =~ s/^\+//mg; print "$features\n";
  print "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <unistd.h>\n#include <errno.h>\n#include <sys/types.h>\n#include <sys/wait.h>\n#include <fcntl.h>\n#include <poll.h>\n#include <time.h>\n#include <signal.h>\n#include <sys/syscall.h>\n#include <limits.h>\n";
  print $runner;
  open my $f, "<", $ARGV[1] or die $!; print <$f>;
' "$root/../patches/wlif-shell-hardening.patch" "$root/wlif-runtime.c" |
  "${WLIF_RUNTIME_CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -O2 \
    -DWLIF_CLI_TIMEOUT_MS=200 -DWLIF_CLI_DIRS="\"$fixture_dir\"" \
    -DWLIF_TEST_DIR="\"$fixture_dir\"" -x c - -o "$fixture_dir/wlif-runtime"
if [ "${WLIF_RUNTIME_COMPILE_ONLY:-0}" != 1 ]; then
  "$fixture_dir/wlif-runtime"
fi
echo "Fixture retained in $fixture_dir"
