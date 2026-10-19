/* sys/shm.h - POSIX shared memory over the Win32 fork-tree overlay.
 *
 * On real POSIX systems this header exposes System V shmget()/shmat().
 * Here we forward to the native header when available, and on Windows
 * provide a small, useful subset built on compat/winproc.h's shared
 * mapping table:
 *
 *   px_shm_open(name, size)  create/attach a NAMED shared region that
 *                            any process in the fork tree (or any process
 *                            that knows the name) can attach to at the
 *                            SAME virtual address -- writes are instantly
 *                            visible in every attacher.  This is strictly
 *                            stronger than Cygwin: cygwin's fork() clones
 *                            memory privately, so post-fork writes never
 *                            cross; our children inherit the parent's
 *                            mappings by identity (name + fixed VA +
 *                            physical pages), and grandchildren inherit
 *                            both the parent's and the child's regions.
 *
 *   px_shm_close(addr)       detach (shmdt-like).
 *
 * Also <unistd.h> maps mmap(MAP_SHARED|MAP_ANONYMOUS)/munmap onto the
 * same machinery for the classic "shared heap across fork()" pattern:
 *
 *   int *counter = px_shm_open("app.counter", sizeof(int));
 *   if (fork() == 0) { (*counter)++; exit(0); }
 *   wait(...);  // counter == 1 in the parent, guaranteed.
 *
 * Limitations: sizes are rounded up to 64 KiB granularity; at most 64
 * live regions per process tree; regions do not survive exec() (POSIX
 * semantics for MAP_SHARED anonymous memory).
 * License: MIT
 */
#ifndef PX_SYS_SHM_H
#define PX_SYS_SHM_H

#ifdef _WIN32

#include "../compat/winproc.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Create-or-attach a named shared region of `size` bytes.  The first
 * caller with a given name creates it; later callers (in this process,
 * or in any fork descendant, or in an unrelated process that passes the
 * same seed via PX_SHM_SEED) attach the existing one and receive the
 * identical pointer value.  Returns NULL on failure (errno set). */
static void *px_shm_open(const char *name, size_t size)
{
    if (!name || !*name) { errno = EINVAL; return NULL; }
    return px_shm_attach(size, name);
}

/* Detach a region returned by px_shm_open / mmap(MAP_SHARED). */
static int px_shm_close(void *addr)
{
    return px_shm_detach(addr);
}

#ifdef __cplusplus
}
#endif

#else /* !_WIN32: native System V shm + mmap already exist */

#include <sys/shm.h>
#include <sys/mman.h>

#endif

#endif /* PX_SYS_SHM_H */
