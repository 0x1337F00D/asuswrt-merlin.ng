#!/usr/bin/env python3
"""Execute the actual patched httpd start_ssl with bounded synthetic stubs.
Pass a prepared source root; --expect-vendor demonstrates the old overwrite.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(sys.argv[1]) / 'release/src/router/httpd/httpd.c'
text = source.read_text()
function = text[text.index('void start_ssl(int http_port)'):]
function = function[:function.index('\n}\n')+3]
prefix = r'''
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <stddef.h>
#define RUST_MSSL_PRESERVE_CREDENTIALS
#define HTTPS_CA_JFFS "saved"
#define HTTPD_ROOTCA_CERT "rootcert"
#define HTTPD_ROOTCA_KEY "rootkey"
#define HTTPD_CERT "cert"
#define HTTPD_KEY "key"
static int exists, matches, init_ok, erased, generated, unlocked, explicit_gen;
static jmp_buf stopped;
static void test_exit(int code) { longjmp(stopped, code); }
#define exit test_exit
static int file_lock(const char *s) { (void)s; return 1; }
static void file_unlock(int n) { (void)n; unlocked++; }
static void sleep(int n) { (void)n; }
static int f_exists(const char *s) { return (!strcmp(s,"cert") || !strcmp(s,"key")) && exists; }
static int nvram_match(const char *k,const char *v) { (void)v; return !strcmp(k,"https_crt_gen") && explicit_gen; }
static void nvram_unset(const char *k) { (void)k; }
static const char *nvram_get(const char *k) { (void)k; return NULL; }
static int restore_cert(void) { return 0; }
static void erase_cert(void) { erased++; exists=0; }
static void save_cert(void) {}
static void logmessage(const char *s,const char *f,...) { (void)s; (void)f; }
static int mssl_cert_key_match(const char *c,const char *k) { (void)c;(void)k;return matches; }
static int mssl_init(const char *c,const char *k) { (void)c;(void)k;return init_ok; }
static int f_read(const char *p,void *b,size_t n) { (void)p;memset(b,0,n);return (int)n; }
static void generate(const char *s) { (void)s;generated++;exists=1;matches=1; }
#define GENCERT_SH(s) generate(s)
'''
suffix = r'''
int main(void) {
  /* Existing unsupported keys must remain intact. */
  exists=1; matches=0; init_ok=0;
  int status=setjmp(stopped); if (!status) start_ssl(8443);
  if (status!=1 || erased || generated || unlocked!=1) return 11;
  /* A provider/runtime error is not permission to generate new keys. */
  exists=1; matches=1; init_ok=0; unlocked=0;
  status=setjmp(stopped); if (!status) start_ssl(8443);
  if (status!=1 || erased || generated || unlocked!=1) return 12;
  /* Empty factory state still receives a generated certificate. */
  exists=0; matches=0; init_ok=1; unlocked=0;
  status=setjmp(stopped); if (!status) start_ssl(8443);
  if (status || generated!=1 || unlocked!=1) return 13;
  /* Explicit user-requested regeneration remains supported. */
  explicit_gen=1; exists=1; matches=1; generated=0; unlocked=0;
  status=setjmp(stopped); if (!status) start_ssl(8443);
  if (status || generated!=1 || unlocked!=1) return 14;
  puts("HTTPD_CREDENTIAL_PRESERVATION=PASS cases=4"); return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='alpha4-cert-', dir='/tmp') as folder:
    root = Path(folder)
    (root/'test.c').write_text(prefix+function+suffix)
    subprocess.run(['cc','-Wall','-Wextra','-Werror',str(root/'test.c'),'-o',str(root/'test')],check=True)
    result = subprocess.run([str(root/'test')],timeout=5)
    if '--expect-vendor' in sys.argv:
        if result.returncode != 11:
            raise SystemExit('vendor negative control did not fail preservation')
        print('VENDOR_NEGATIVE_CONTROL=PASS (old code overwrites existing keys)')
    elif result.returncode:
        raise SystemExit(result.returncode)
