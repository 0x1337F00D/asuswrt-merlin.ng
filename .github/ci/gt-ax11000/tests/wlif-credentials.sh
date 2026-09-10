#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixture_dir="$(mktemp -d /tmp/gt-wlif-credentials.XXXXXX)"
mkdir -p "$fixture_dir/release/src/router/shared"
if [ "$#" -gt 0 ]; then
  cp "$1" "$fixture_dir/release/src/router/shared/wlif_utils_ax.c"
else
  # Sparse CI checkouts need only this locked repository blob, not the
  # vendor tree. Materialize it into the private RAM fixture, never checkout.
  git -C "$root" show HEAD:release/src/router/shared/wlif_utils_ax.c \
    > "$fixture_dir/release/src/router/shared/wlif_utils_ax.c"
fi
(
  cd "$fixture_dir"
  git apply --recount --include=release/src/router/shared/wlif_utils_ax.c \
    "$root/../patches/wlif-shell-hardening.patch"
)
archive="${CARGO_TARGET_DIR:-/tmp/gt-tier1-review-wlif-target}/release/libwlif_policy.a"
test -s "$archive"
perl -0777 -e '
  open my $f, "<", $ARGV[0] or die $!; local $/; my $fixture = <$f>;
  open my $v, "<", $ARGV[1] or die $!; my $vendor = <$v>;
  $vendor =~ /(static int\nwl_wlif_supplicant_cmd\(.*?)(?=\n#endif \/\* WIFI7_SDK_20250506 \|\| WIFI8_SDK_20251126 \*\/)/s or die "actual functions missing";
  my $functions = $1;
  $fixture =~ s@/\* INSERT_ACTUAL_VENDOR_FUNCTIONS \*/@$functions@ or die "fixture marker missing";
  print $fixture;
' "$root/wlif-credentials.c" "$fixture_dir/release/src/router/shared/wlif_utils_ax.c" |
  cc -std=gnu11 -Wall -Wextra -Werror -O2 -x c - -x none "$archive" \
    -ldl -lpthread -lm -lrt -lutil -o "$fixture_dir/wlif-credentials"
"$fixture_dir/wlif-credentials"
echo "Fixture retained in $fixture_dir"
