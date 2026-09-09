/* Trial-only, process-scoped adapter for the SHA-pinned GT-AX11000 bsd blob.
 * Its call at 0x245dc passes (idx, buffer, 4096). Current libshared expects
 * (idx, vidx, buffer, size). Never globally preload this into mixed consumers.
 * This does not replace/harden the underlying C MAC-list parser.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>

void retrieve_static_maclist_from_nvram(int idx, void *buffer, int size)
{
    typedef void (*v4_fn)(int, int, void *, int);
    v4_fn next;
    /* Fail the supervised trial on an unexpected ABI, never fabricate an
     * empty ACL on lookup/argument failure. No heuristic ABI autodetection. */
    if (idx < 0 || idx > 2 || !buffer || ((uintptr_t)buffer & 3) || size != 4096)
        abort();
    next = (v4_fn)dlsym(RTLD_NEXT, "retrieve_static_maclist_from_nvram");
    if (!next) abort();
    next(idx, 0, buffer, size);
}
