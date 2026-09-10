#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixture_dir="$(mktemp -d /tmp/gt-httpd-request-reader.XXXXXX)"
mkdir -p "$fixture_dir/release/src/router/httpd"
# Materialize tracked source blobs into the private fixture, including in
# sparse CI checkouts. Do not edit the checkout or copy the reader by hand.
for name in httpd.c httpd.h; do
  git -C "$root" show "HEAD:release/src/router/httpd/$name" \
    > "$fixture_dir/release/src/router/httpd/$name"
done
(
  cd "$fixture_dir"
  git apply --recount --include=release/src/router/httpd/httpd.h \
    "$root/../patches/rust-components.patch"
  git apply --recount "$root/../patches/httpd-httparse.patch"
)
archive="${HTTPD_REQUEST_ARCHIVE:-${CARGO_TARGET_DIR:-/tmp/asuswrt-rust-c-abi-target}/release/libhttpd_parsers.a}"
test -s "$archive"
perl -0777 -e '
  open my $f, "<", $ARGV[0] or die $!; local $/; my $fixture = <$f>;
  open my $c, "<", $ARGV[1] or die $!; my $source = <$c>;
  open my $h, "<", $ARGV[2] or die $!; my $header = <$h>;
  $source =~ /(enum request_read_result \{.*?)(?=\nstatic void\nhandle_request\(void\))/s or die "actual reader missing";
  my $reader = $1;
  $header =~ /(#define RUST_HTTPD_REQUEST_BLOCK_MAX.*?extern size_t rust_httpd_request_struct_size\(void\);)/s or die "actual ABI missing";
  my $abi = $1;
  $fixture =~ s@/\* INSERT_ACTUAL_HTTP_REQUEST_ABI \*/@$abi@ or die "ABI marker missing";
  $fixture =~ s@/\* INSERT_ACTUAL_HTTP_REQUEST_READER \*/@$reader@ or die "reader marker missing";
  print $fixture;
' "$root/httpd-request-reader.c" \
  "$fixture_dir/release/src/router/httpd/httpd.c" \
  "$fixture_dir/release/src/router/httpd/httpd.h" |
  "${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -O2 -x c - -x none "$archive" \
    -ldl -lpthread -lm -lrt -lutil -o "$fixture_dir/httpd-request-reader"
if [ -n "${HTTPD_REQUEST_RUNNER:-}" ]; then
  "$HTTPD_REQUEST_RUNNER" "$fixture_dir/httpd-request-reader"
else
  "$fixture_dir/httpd-request-reader"
fi
echo "Fixture retained in $fixture_dir"
