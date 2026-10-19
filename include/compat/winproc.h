/* compat/winproc.h - INTERNAL fork()/exec() helpers for <unistd.h> & <sys/wait.h>.
 *
 * Windows has no native fork(); we emulate the POSIX process model:
 *
 *   fork():      spawns a fresh copy of the current executable via
 *                CreateProcessW (argv rebuilt from __argc/__wargv; cwd,
 *                std handles and this library's fds are inherited).  The
 *                child blocks on a handshake event ("..._r", ready) until
 *                the parent's fork() has returned, so the classic
 *                    pid = fork();
 *                    if (pid == 0) { ... } else { ... }
 *                control flow is preserved across the process boundary.
 *
 *                SHARED MEMORY (beyond Cygwin): every mapping created
 *                through px_shm_attach()/px_shm_open() below lives in an
 *                NT section (CreateFileMappingA with INVALID_HANDLE_VALUE),
 *                is exported to fork children as a NAMED global mapping
 *                ("pxshm_<ppid>_<seq>") plus its fixed preferred address,
 *                and is re-materialised in the child at the IDENTICAL
 *                virtual address with identical contents -- both processes
 *                read/write the same physical pages, exactly like
 *                MAP_SHARED anonymous mmap on POSIX.  Because children
 *                inherit their parent's mappings AND may add their own
 *                (which grandchildren then inherit), the whole fork tree
 *                shares one coherent address space overlay.  Cygwin cannot
 *                do this: it clones memory privately per-process (forked
 *                writes are invisible to the parent) and its cygserver
 *                shared-memory extension still maps at arbitrary addresses
 *                with no fork-tree propagation.  What we deliberately do
 *                NOT clone is private CRT heap/stack/global data -- see
 *                <sys/shm.h> for the semantics table and limitations.
 *
 *                A subtlety: the child must NOT block before its first call
 *                into this compat layer, because then the parent would
 *                deadlock waiting for the child's ack.  Instead the wait is
 *                deferred to px_fork_lazy_handshake(), invoked by every
 *                public wrapper in <unistd.h>; in well-formed fork() code
 *                it fires right after `if (pid == 0)`.  Side effects that
 *                run before the branch (global constructors, stdio buffering)
 *                execute twice -- a documented limitation of fork-on-Windows.
 *
 *   exec*:       CreateProcessW + WaitForSingleObject + exit().  Our fd
 *                table rides into the child via the PX_FD_TABLE environment
 *                variable, so descriptors opened without FD_CLOEXEC survive
 *                the exec, like on POSIX.  Shared mappings are dropped
 *                across exec (POSIX semantics: only MAP_SHARED file-backed
 *                mappings listed in the spec survive; we keep the simpler
 *                anonymous case correct).
 *
 * Not part of the public API; included by <unistd.h>, <sys/wait.h> and
 * <sys/shm.h>.
 * License: MIT
 */
#ifndef PX_COMPAT_WINPROC_H
#define PX_COMPAT_WINPROC_H

#ifdef _WIN32

#include "compat/posix_defs.h"
#include "compat/winfd.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* pid <-> process HANDLE table (consumed by sys/wait.h)               */
/* ------------------------------------------------------------------ */
#define PX_MAX_PROCS 256

typedef struct {
    int    used;
    pid_t  pid;
    HANDLE proc;
    HANDLE thread;
} px_proc_slot;

static px_proc_slot px_procs[PX_MAX_PROCS];
static CRITICAL_SECTION px_procs_cs;
static volatile LONG px_procs_cs_stage = 0; /* 0=new, 1=initing, 2=ready */

static void px_procs_lock(void)
{
    if (InterlockedCompareExchange(&px_procs_cs_stage, 1, 0) == 0) {
        InitializeCriticalSection(&px_procs_cs);
        InterlockedExchange(&px_procs_cs_stage, 2);
    } else {
        while (px_procs_cs_stage != 2) Sleep(0);
    }
    EnterCriticalSection(&px_procs_cs);
}
static void px_procs_unlock(void)
{
    LeaveCriticalSection(&px_procs_cs);
}

static void px_proc_add(pid_t pid, HANDLE proc, HANDLE thread)
{
    int i;
    px_procs_lock();
    for (i = 0; i < PX_MAX_PROCS; i++) {
        if (!px_procs[i].used) {
            px_procs[i].used   = 1;
            px_procs[i].pid    = pid;
            px_procs[i].proc   = proc;
            px_procs[i].thread = thread;
            break;
        }
    }
    px_procs_unlock();
}

/* look up a tracked child's process handle. keep=0 removes the slot. */
static HANDLE px_proc_handle(pid_t pid, int keep)
{
    HANDLE h = NULL;
    int i;
    px_procs_lock();
    for (i = 0; i < PX_MAX_PROCS; i++) {
        if (px_procs[i].used && px_procs[i].pid == pid) {
            h = px_procs[i].proc;
            if (!keep) {
                px_procs[i].used = 0;
                px_procs[i].proc = NULL;
                px_procs[i].thread = NULL;
            }
            break;
        }
    }
    px_procs_unlock();
    return h;
}

/* forget all tracked children (called on exec: they become orphans) */
static void px_proc_forget_all(void)
{
    int i;
    px_procs_lock();
    for (i = 0; i < PX_MAX_PROCS; i++) px_procs[i].used = 0;
    px_procs_unlock();
}

/* ------------------------------------------------------------------ */
/* CRT fd-table export/import (fd inheritance across fork/exec)        */
/*                                                                     */
/* Compat fds are either plain CRT file descriptors or CRT fds wrapping */
/* Winsock sockets (see winfd.h px_pipe).  We serialise the open ones   */
/* as "fd.kind.handle" triples joined by ';' in an env var; the child   */
/* re-attaches them with _open_osfhandle() at exactly the same numbers. */
/* Handles duplicated into the child by CreateProcess(bInheritHandles=  */
/* TRUE) keep the same numeric value there, which is what makes this    */
/* work.  Only non-CLOEXEC fds are exported (POSIX exec semantics).     */
/* The cloexec bookkeeping itself lives in compat/winfd.h               */
/* (px_fdinfo / px_fdinfo_set / px_fdinfo_cloexec).                     */
/* NOTE: '.' separators and digits-only fields because Windows stores   */
/* environment variable *names* upper-cased; keep values case-free too  */
/* so nothing can be mangled in round-trips through cmd.exe.            */
/* ------------------------------------------------------------------ */
#define PX_FDTABLE_ENV  "PX_FD_TABLE"
#define PX_FORK_CHILD_ENV "PX_FORK_CHILD"
#define PX_FORK_PPID_ENV  "PX_FORK_PPID"
#define PX_SHMTABLE_ENV   "PX_SHM_TABLE"

/* ------------------------------------------------------------------ */
/* shared-memory table (fork-tree address-space overlay)               */
/*                                                                     */
/* Each entry is one anonymous NT section created at a FIXED preferred */
/* virtual address (MEM_RESERVE first, then MapViewOfFileEx at exactly  */
/* that address).  fork() exports every live entry to the child as      */
/* "name.size.addr"; the child opens the same named mapping and maps    */
/* it at the same address, so parent and child share identical physical */
/* pages at identical pointers -- writes are visible in both processes  */
/* immediately.  Children may create further mappings which their own   */
/* forks inherit: the whole process tree overlays one shared address    */
/* range.  This goes beyond Cygwin, whose fork clones memory privately   */
/* (post-fork writes never cross) and whose cygserver shm keeps no      */
/* fixed-address fork-tree propagation.                                 */
/*                                                                     */
/* name format: auto-created regions get "pxshm_<originpid>_<seq>" --
 * unique across the tree because originpid identifies the process where
 * the mapping was born.  Named regions (px_shm_open) keep their own key
 * in slot.key and are re-attachable by that key; their NT object name is
 * "pxshm_k<fnv(key)>".  Values stay digits + '_' so cmd.exe cannot
 * mangle them.                                                      */
#define PX_MAX_SHMS 64

typedef struct {
    int     used;
    char    name[64];          /* NT global file-mapping object name */
    char    key[64];           /* user-visible key ("" = auto region) */
    void   *addr;              /* fixed preferred base address */
    size_t  size;
    HANDLE  hmap;              /* our section handle */
    int     owner;             /* 1: creator -> also publishes PX_SHM_SEED */
} px_shm_slot;

static px_shm_slot px_shms[PX_MAX_SHMS];
static CRITICAL_SECTION px_shm_cs;
static volatile LONG px_shm_cs_stage = 0;
static volatile LONG px_shm_seq = 0;

static void px_shm_lock(void)
{
    if (InterlockedCompareExchange(&px_shm_cs_stage, 1, 0) == 0) {
        InitializeCriticalSection(&px_shm_cs);
        InterlockedExchange(&px_shm_cs_stage, 2);
    } else {
        while (px_shm_cs_stage != 2) Sleep(0);
    }
    EnterCriticalSection(&px_shm_cs);
}
static void px_shm_unlock(void)
{
    LeaveCriticalSection(&px_shm_cs);
}

/* build the PX_SHM_TABLE string ("name.key.size.addr;..\").  The table
 * is exported through fork(); key may be empty (auto region).  Values
 * use only [A-Za-z0-9_.] so they survive env round-trips. */
static char *px_shmtable_encode(void)
{
    static char buf[8192];
    size_t used = 0;
    int i, n = 0;
    buf[0] = '\0';
    px_shm_lock();
    for (i = 0; i < PX_MAX_SHMS; i++) {
        char tmp[256];
        int m;
        if (!px_shms[i].used) continue;
        m = snprintf(tmp, sizeof(tmp), "%s%s.%s.%u.%llu",
                     n ? ";" : "", px_shms[i].name, px_shms[i].key,
                     (unsigned)px_shms[i].size,
                     (unsigned long long)(uintptr_t)px_shms[i].addr);
        if (m <= 0 || used + (size_t)m >= sizeof(buf) - 1) break;
        memcpy(buf + used, tmp, (size_t)m);
        used += (size_t)m;
        buf[used] = '\0';
        n++;
    }
    px_shm_unlock();
    return buf;
}

/* re-materialise the parent's shared mappings at identical addresses.
 * Called exactly once, in the child, during the fork handshake. */
static void px_shmtable_import(void)
{
    const char *env = getenv(PX_SHMTABLE_ENV);
    char copy[8192];
    char *p, *save = NULL;
    if (!env || !*env) return;
    snprintf(copy, sizeof(copy), "%s", env);
    for (p = strtok_s(copy, ";", &save); p; p = strtok_s(NULL, ";", &save)) {
        char name[64] = "";
        char key[64]  = "";
        unsigned long long sz = 0, ad = 0;
        HANDLE h;
        void *got;
        int slot, i, nflds;
        char *f[4], *q, *lim;
        /* split into up to 4 '.'-separated fields */
        nflds = 0;
        q = p; lim = p + strlen(p);
        while (q <= lim && nflds < 4) {
            char *dot = strchr(q, '.');
            f[nflds++] = q;
            if (!dot) { q = lim + 1; break; }
            *dot = '\0';
            q = dot + 1;
        }
        if (nflds != 4) continue;
        if (strlen(f[0]) >= sizeof(name)) continue;
        if (strlen(f[1]) >= sizeof(key))  continue;
        snprintf(name, sizeof(name), "%s", f[0]);
        snprintf(key,  sizeof(key),  "%s", f[1]);
        sz = strtoull(f[2], NULL, 10);
        ad = strtoull(f[3], NULL, 10);
        if (!sz || !ad) continue;

        /* reserve our slot FIRST, then open+map: on failure we unmap,
           free the reservation and leave the slot unused so a later
           local creation can reuse it. */
        px_shm_lock();
        slot = -1;
        for (i = 0; i < PX_MAX_SHMS; i++) {
            if (px_shms[i].used && strcmp(px_shms[i].name, name) == 0)
                { slot = -2; break; }            /* already imported */
            if (slot < 0 && !px_shms[i].used) slot = i;
        }
        if (slot == -2) { px_shm_unlock(); continue; }
        if (slot >= 0) {
            px_shms[slot].used = 1;
            snprintf(px_shms[slot].name, sizeof(px_shms[slot].name),
                     "%s", name);
            snprintf(px_shms[slot].key, sizeof(px_shms[slot].key),
                     "%s", key);
            px_shms[slot].size  = (size_t)sz;
            px_shms[slot].addr  = (void *)(uintptr_t)ad;
            px_shms[slot].hmap  = NULL;
            px_shms[slot].owner = 0;
        }
        px_shm_unlock();
        if (slot < 0) continue;                 /* table full */

        h = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
        if (!h) goto fail;                      /* parent died / bad name */
        got = MapViewOfFileEx(h, FILE_MAP_WRITE, 0, 0, sz,
                              (void *)(uintptr_t)ad);
        if (!got) { CloseHandle(h); goto fail; }
        px_shms[slot].hmap = h;
        continue;
    fail:
        UnmapViewOfFile((void *)(uintptr_t)ad); /* releases reservation */
        px_shm_lock();
        px_shms[slot].used = 0;
        px_shm_unlock();
    }
    _putenv_s(PX_SHMTABLE_ENV, ""); /* grandchildren get a fresh snapshot */
}

/* drop all shared mappings (exec: POSIX tears down MAP_SHARED anon maps;
 * the sections themselves die with the last reference) */
static void px_shmtable_forget_all(void)
{
    int i;
    px_shm_lock();
    for (i = 0; i < PX_MAX_SHMS; i++) {
        if (!px_shms[i].used) continue;
        if (px_shms[i].hmap) {
            UnmapViewOfFile(px_shms[i].addr);
            CloseHandle(px_shms[i].hmap);
        }
        memset(&px_shms[i], 0, sizeof(px_shms[i]));
    }
    px_shm_unlock();
    _putenv_s(PX_SHMTABLE_ENV, "");
}

/* FNV-1a 64 over a NUL-terminated string */
static unsigned long long px_fnv64(const char *s)
{
    unsigned long long hv = 1469598103934665603ULL;
    const unsigned char *b = (const unsigned char *)s;
    for (; *b; b++) { hv ^= *b; hv *= 1099511628211ULL; }
    return hv;
}

/* Create/attach a shared mapping of `size` bytes at a deterministic,
 * collision-resistant fixed address.  If `key` is non-NULL this is a
 * NAMED region: the first call with that key creates it, later calls
 * (same process or any fork descendant that inherited it) re-attach at
 * the identical pointer; the NT object name and the preferred VA are
 * both derived from the key hash so they are stable across the tree.
 * With key==NULL an anonymous region is created instead; its address
 * comes from our per-tree seed (PX_SHM_SEED env var, published to all
 * fork children), like System V's SHMMIN window.
 * Returns the shared pointer or NULL (errno set).  Thread-safe. */
static void *px_shm_attach(size_t size, const char *key)
{
    char name[64];
    char seedbuf[32];
    const char *seed;
    uintptr_t base;
    int i, slot = -1;
    HANDLE h = NULL;
    void *addr = NULL, *got;
    long seq;
    unsigned long long hv;

    if (size == 0) { errno = EINVAL; return NULL; }
    size = (size + 0xffff) & ~(size_t)0xffff;   /* round to 64 KiB align */

    /* ---- derive NT object name + address seed ---- */
    if (key && *key) {
        hv = px_fnv64(key);
        snprintf(name, sizeof(name), "pxshm_k%llu", hv);
        seed = name;                    /* VA follows the key: stable */
    } else {
        key = NULL;                     /* normalise "" -> anonymous */
        seq = InterlockedIncrement(&px_shm_seq);
        snprintf(name, sizeof(name), "pxshm_%lu_%ld",
                 (unsigned long)GetCurrentProcessId(), seq);
        seed = getenv("PX_SHM_SEED");
        if (!seed || !*seed) {
            unsigned long long s = GetTickCount64() ^
                ((unsigned long long)(uintptr_t)&seq << 16) ^
                ((unsigned long long)GetCurrentProcessId() << 32);
            snprintf(seedbuf, sizeof(seedbuf), "%llu", s);
            seed = seedbuf;
            { char x[96]; snprintf(x, sizeof(x), "PX_SHM_SEED=%s", seedbuf);
              _putenv(x); }   /* publish: fork children share our window */
        }
    }

    /* ---- look up / reserve a table slot ---- */
    px_shm_lock();
    for (i = 0; i < PX_MAX_SHMS; i++) {
        if (px_shms[i].used && strcmp(px_shms[i].name, name) == 0) {
            void *a = px_shms[i].addr;          /* already attached here */
            px_shm_unlock();
            return a;
        }
    }
    for (i = 0; i < PX_MAX_SHMS; i++)
        if (!px_shms[i].used) { slot = i; break; }
    px_shm_unlock();
    if (slot < 0) { errno = ENOSPC; return NULL; }

    /* deterministic preferred base: hash(seed) into the 0x5F12_0000 ..
       0x5FFF_FFFF user hole, 64 KiB aligned.  For named regions the hash
       depends only on the key, so every attacher computes the same VA;
       for anonymous ones it also mixes in seq.  With ASLR this VA is free
       in practice; MEM_RESERVE first makes any clash explicit instead of
       silently relocating (relocation would break the identical-pointer
       guarantee). */
    if (key) hv = px_fnv64(seed);
    else     hv = px_fnv64(seed) ^
                     ((unsigned long long)seq * 0x9E3779B97F4A7C15ULL);
    {
        base = (0x5F120000ULL + (hv % 0x00ED0000ULL)) & ~0xffffULL;
        if (base + size > 0x60000000ULL)
            base = 0x5F120000ULL +
                   ((base + 0x20000 - 0x60000000ULL) & 0x00ED0000ULL);
    }

    /* reserve the exact range so MapViewOfFileEx cannot be relocated */
    addr = VirtualAlloc((void *)base, size, MEM_RESERVE, PAGE_NOACCESS);
    if (!addr || (uintptr_t)addr != base) {
        if (addr) VirtualFree(addr, 0, MEM_RELEASE);
        errno = ENOMEM;
        return NULL;
    }

    /* create-or-open the section (named regions: first creator wins,
       later callers attach the very same physical pages) */
    h = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                           (DWORD)((unsigned long long)size >> 32),
                           (DWORD)(size & 0xffffffffUL), name);
    if (!h) { UnmapViewOfFile(addr); px_set_errno_from_win(); errno = ENOMEM; }
    if (h) {
        got = MapViewOfFileEx(h, FILE_MAP_WRITE, 0, 0, size, addr);
        if (!got) { CloseHandle(h); UnmapViewOfFile(addr); errno = ENOMEM; }
        else {
            /* register (double-check the name race) */
            int dup = 0;
            px_shm_lock();
            for (i = 0; i < PX_MAX_SHMS; i++)
                if (px_shms[i].used &&
                    strcmp(px_shms[i].name, name) == 0) dup = 1;
            if (!dup) {
                px_shms[slot].used   = 1;
                snprintf(px_shms[slot].name, sizeof(px_shms[slot].name),
                         "%s", name);
                snprintf(px_shms[slot].key, sizeof(px_shms[slot].key),
                         "%s", key ? key : "");
                px_shms[slot].addr   = addr;
                px_shms[slot].size   = size;
                px_shms[slot].hmap   = h;
                px_shms[slot].owner  = (key == NULL);
            }
            px_shm_unlock();
            if (dup) {
                UnmapViewOfFile(got); CloseHandle(h);
                errno = EEXIST;
                return NULL;
            }
            return addr;
        }
    }
    return NULL;
}

/* detach a mapping obtained from px_shm_attach (POSIX shmdt-like) */
static int px_shm_detach(void *addr)
{
    int i, rc = -1;
    px_shm_lock();
    for (i = 0; i < PX_MAX_SHMS; i++) {
        if (px_shms[i].used && px_shms[i].addr == addr) {
            UnmapViewOfFile(addr);
            CloseHandle(px_shms[i].hmap);
            memset(&px_shms[i], 0, sizeof(px_shms[i]));
            rc = 0;
            break;
        }
    }
    px_shm_unlock();
    if (rc != 0) errno = EINVAL;
    return rc;
}

/* build the PX_FD_TABLE string ("fd.k.h;fd.k.h;..") */
static char *px_fdtable_encode(const int *fds, int nfds)
{
    static char buf[4096];
    size_t used = 0;
    int i, n = 0;
    buf[0] = '\0';
    for (i = 0; i < nfds; i++) {
        int fd = fds[i];
        intptr_t h;
        char tmp[80];
        int m;
        if (fd < 0 || fd >= 256) continue;
        h = _get_osfhandle(fd);
        if (h == -1) continue;                     /* not open */
        if (px_fdinfo_cloexec(fd)) continue;       /* CLOEXEC: drop */
        m = snprintf(tmp, sizeof(tmp), "%s%d.%d.%lld",
                     n ? ";" : "", fd, px_fd_is_socket(fd) ? 1 : 0,
                     (long long)h);
        if (m <= 0 || used + (size_t)m >= sizeof(buf) - 1) break;
        memcpy(buf + used, tmp, (size_t)m);
        used += (size_t)m;
        buf[used] = '\0';
        n++;
    }
    return buf;
}

/* parse PX_FD_TABLE (if present) and re-attach the exported fds */
static void px_fdtable_import(void)
{
    const char *env = getenv(PX_FDTABLE_ENV);
    char copy[4096];
    char *p, *save = NULL;
    if (!env || !*env) return;
    snprintf(copy, sizeof(copy), "%s", env);
    for (p = strtok_s(copy, ";", &save); p; p = strtok_s(NULL, ";", &save)) {
        int fd = -1, kind = 0;
        long long hh = -1;
        char *c1 = strchr(p, '.'), *c2;
        if (!c1) continue;
        c2 = strchr(c1 + 1, '.');
        if (!c2) continue;
        fd = atoi(p);
        kind = atoi(c1 + 1);
        hh = atoll(c2 + 1);
        (void)kind;
        if (fd < 0 || fd > 255 || hh <= 0) continue;
        if (_get_osfhandle(fd) != -1) continue;    /* already open */
        {
            int flags = (fd == 0) ? _O_RDONLY
                        : (fd == 1 || fd == 2) ? _O_WRONLY
                        : _O_RDWR;
            int got = _open_osfhandle((intptr_t)hh, flags);
            if (got != fd && got != -1) _close(got); /* best effort */
        }
        px_fdinfo_set(fd, 0);
    }
}

/* snapshot all open, non-CLOEXEC compat fds into arr[] */
static int px_fdtable_snapshot(int *arr, int maxn)
{
    int n = 0, fd;
    for (fd = 0; fd < 256 && n < maxn; fd++) {
        if (_get_osfhandle(fd) == -1) continue;    /* closed */
        if (px_fdinfo_cloexec(fd)) continue;
        arr[n++] = fd;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* command-line building / current argv                                */
/* ------------------------------------------------------------------ */
/* append one quoted field per MSVC CommandLineToArgv rules */
static char *px_append_arg(char *p, size_t *left, const char *s)
{
    int needq = (strpbrk(s, " \t\"\\") != NULL || s[0] == '\0');
    if (needq) {
        int slashes = 0;
        if (*left < 3) return p;
        *p++ = '"'; (*left)--;
        for (; *s; s++) {
            if (*s == '\\') { slashes++; continue; }
            if (*s == '"') {
                int k;
                for (k = 0; k < slashes * 2 + 1 && *left > 1; k++) { *p++ = '\\'; (*left)--; }
                slashes = 0;
                if (*left > 1) { *p++ = '"'; (*left)--; }
            } else {
                int k;
                for (k = 0; k < slashes && *left > 1; k++) { *p++ = '\\'; (*left)--; }
                slashes = 0;
                if (*left > 1) { *p++ = *s; (*left)--; }
            }
        }
        { int k; for (k = 0; k < slashes * 2 && *left > 1; k++) { *p++ = '\\'; (*left)--; } }
        if (*left > 1) { *p++ = '"'; (*left)--; }
    } else {
        size_t l = strlen(s);
        if (l > *left - 1) l = *left - 1;
        memcpy(p, s, l);
        p += l;
        *left -= l;
    }
    *p = '\0';
    return p;
}

/* current CRT argv (__wargv -> UTF-8); caller frees strings + array */
static char **px_current_argv_utf8(void)
{
    char **v;
    int i;
    v = (char **)malloc(((size_t)__argc + 1) * sizeof(char *));
    if (!v) return NULL;
    for (i = 0; i < __argc; i++) {
        int need = WideCharToMultiByte(CP_UTF8, 0, __wargv[i], -1,
                                       NULL, 0, NULL, NULL);
        char *s = (char *)malloc((size_t)(need > 0 ? need : 1));
        if (!s) { v[i] = NULL; continue; }
        WideCharToMultiByte(CP_UTF8, 0, __wargv[i], -1, s, need, NULL, NULL);
        v[i] = s;
    }
    v[__argc] = NULL;
    return v;
}

/* ------------------------------------------------------------------ */
/* environment-block merging                                           */
/*                                                                     */
/* GetEnvironmentStringsW gives the exact wide block (including the    */
/* hidden "=C:" style pseudo-variables the CRT relies on).  We splice  */
/* extra NAME=value rows in (replacing existing ones) and hand the     */
/* result to CreateProcessW with CREATE_UNICODE_ENVIRONMENT.           */
/* ------------------------------------------------------------------ */
static WCHAR *px_env_block_merged(char *const extra_env[])
{
    WCHAR *raw = GetEnvironmentStringsW();
    WCHAR *blk = NULL, *w, *q;
    size_t bytes = 0;
    size_t nextra = 0, xj;
    WCHAR *xe[64];
    int have_extra = (extra_env != NULL);

    if (!raw) return NULL;

    /* convert extra rows (UTF-8 -> wide) */
    if (have_extra) {
        for (xj = 0; extra_env[xj] && nextra < 60; xj++) {
            int need = MultiByteToWideChar(CP_UTF8, 0, extra_env[xj], -1, NULL, 0);
            WCHAR *dst;
            if (need <= 0) continue;
            dst = (WCHAR *)malloc((size_t)need * sizeof(WCHAR));
            if (!dst) continue;
            MultiByteToWideChar(CP_UTF8, 0, extra_env[xj], -1, dst, need);
            xe[nextra++] = dst;
        }
    }

    /* measure raw block minus overridden rows, plus extras */
    for (q = raw; *q; q += wcslen(q) + 1) {
        int skip = 0;
        size_t l = wcslen(q);
        for (xj = 0; xj < nextra; xj++) {
            const WCHAR *e = xe[xj];
            const WCHAR *eq = wcschr(e, L'=');
            size_t keylen = eq ? (size_t)(eq - e) : 0;
            if (keylen && l > keylen && q[keylen] == L'=' &&
                wcsncmp(q, e, keylen) == 0) { skip = 1; break; }
        }
        if (!skip) bytes += (l + 1) * sizeof(WCHAR);
    }
    for (xj = 0; xj < nextra; xj++)
        bytes += (wcslen(xe[xj]) + 1) * sizeof(WCHAR);
    bytes += sizeof(WCHAR); /* final NUL */

    blk = (WCHAR *)malloc(bytes);
    if (blk) {
        w = blk;
        for (q = raw; *q; q += wcslen(q) + 1) {
            int skip = 0;
            size_t l = wcslen(q);
            for (xj = 0; xj < nextra; xj++) {
                const WCHAR *e = xe[xj];
                const WCHAR *eq = wcschr(e, L'=');
                size_t keylen = eq ? (size_t)(eq - e) : 0;
                if (keylen && l > keylen && q[keylen] == L'=' &&
                    wcsncmp(q, e, keylen) == 0) { skip = 1; break; }
            }
            if (!skip) { memcpy(w, q, (l + 1) * sizeof(WCHAR)); w += l + 1; }
        }
        for (xj = 0; xj < nextra; xj++) {
            size_t l = wcslen(xe[xj]);
            memcpy(w, xe[xj], (l + 1) * sizeof(WCHAR));
            w += l + 1;
        }
        *w = L'\0';
    }
    for (xj = 0; xj < nextra; xj++) free(xe[xj]);

    FreeEnvironmentStringsW(raw);
    return blk;
}

/* ------------------------------------------------------------------ */
/* low-level spawn                                                     */
/* ------------------------------------------------------------------ */
/* CreateProcessW wrapper: inherits std handles + our fd table.
 * app_path may be NULL (then the image comes from the command line).
 * cmdline_utf8: full command line.  extra_env: NULL-terminated UTF-8
 * "NAME=value" rows merged into the child environment (or NULL).
 * Returns 0 on success (resumed child), -1 on failure (errno set). */
static int px_spawn(const WCHAR *app_path, const char *cmdline_utf8,
                    char *const extra_env[], int new_console,
                    PROCESS_INFORMATION *pi)
{
    STARTUPINFOW si;
    WCHAR *wcmd = NULL;
    WCHAR *envblk = NULL;
    DWORD flags;
    BOOL ok;
    int fds[256], nfds, i;
    int need;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError  = GetStdHandle(STD_ERROR_HANDLE);
    if (!si.hStdInput)  si.hStdInput  = INVALID_HANDLE_VALUE;
    if (!si.hStdOutput) si.hStdOutput = INVALID_HANDLE_VALUE;
    if (!si.hStdError)  si.hStdError  = INVALID_HANDLE_VALUE;

    /* make every exported fd's handle explicitly inheritable */
    nfds = px_fdtable_snapshot(fds, 256);
    for (i = 0; i < nfds; i++) {
        HANDLE h = (HANDLE)(intptr_t)_get_osfhandle(fds[i]);
        SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    }

    need = MultiByteToWideChar(CP_UTF8, 0, cmdline_utf8, -1, NULL, 0);
    if (need <= 0) goto fail_enomem;
    wcmd = (WCHAR *)malloc((size_t)need * sizeof(WCHAR));
    if (!wcmd) goto fail_enomem;
    MultiByteToWideChar(CP_UTF8, 0, cmdline_utf8, -1, wcmd, need);

    envblk = px_env_block_merged(extra_env);

    flags = CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP |
            (envblk ? CREATE_UNICODE_ENVIRONMENT : 0) |
            (new_console ? CREATE_NEW_CONSOLE : 0);

    /* lpCurrentDirectory = NULL -> child inherits our cwd */
    ok = CreateProcessW(app_path, wcmd, NULL, NULL, TRUE, flags,
                        envblk, NULL, &si, pi);

    if (envblk) free(envblk);
    free(wcmd);
    wcmd = NULL;

    /* restore default non-inheritable state for our own fds */
    for (i = 0; i < nfds; i++) {
        HANDLE h = (HANDLE)(intptr_t)_get_osfhandle(fds[i]);
        SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
    }

    if (!ok) { px_set_errno_from_win(); return -1; }
    ResumeThread(pi->hThread);
    return 0;

fail_enomem:
    for (i = 0; i < nfds; i++) {
        HANDLE h = (HANDLE)(intptr_t)_get_osfhandle(fds[i]);
        SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);
    }
    if (wcmd) free(wcmd);
    errno = ENOMEM;
    return -1;
}

/* ------------------------------------------------------------------ */
/* fork() emulation                                                    */
/* ------------------------------------------------------------------ */
/* Handshake events (names passed to the child via PX_FORK_CHILD):
 *   "<tag>_r" ready : set by the parent just before its fork() returns;
 *                     the child waits on it so its fork() only returns 0
 *                     after the parent's fork() returned pid.
 *   "<tag>_a" ack   : set by the child as soon as it is alive (armed);
 *                     the parent waits on it inside fork(), which keeps
 *                     fork() deadlock-free even if the child never calls
 *                     into this compat layer again. */
static long          px_fork_state = 0; /* 0 unknown, 1 pending-child, 2 none/done */
static char          px_fork_ev_ready[128];
static char          px_fork_ev_ack[128];
static volatile LONG px_fork_seq = 0;

/* full path of the current executable (wide) */
static int px_self_path_w(WCHAR *out, size_t cap)
{
    DWORD n = GetModuleFileNameW(NULL, out, (DWORD)cap);
    return (n > 0 && n < cap) ? 0 : -1;
}

/* one-time per process: were we born from px_fork()?  If yes, parse the
 * handshake event names, acknowledge our existence to the waiting parent
 * (so its fork() can return without depending on us), and remember that
 * we still must wait for the parent's "ready" event before our own
 * emulated fork() returns 0.  Cheap (~one getenv + compare) to call
 * from every wrapper. */
static void px_fork_arm_if_child(void)
{
    const char *v;
    HANDLE a;
    if (px_fork_state != 0) return;
    v = getenv(PX_FORK_CHILD_ENV);
    if (v && *v) {
        sscanf(v, "%127[^;];%127s", px_fork_ev_ready, px_fork_ev_ack);
        px_fork_state = 1;
        a = CreateEventA(NULL, TRUE, FALSE, px_fork_ev_ack);
        if (a) { SetEvent(a); CloseHandle(a); }
        _putenv_s(PX_FORK_CHILD_ENV, ""); /* keep grandchildren clean */
    } else {
        px_fork_state = 2; /* ordinary process: nothing pending */
    }
}

/* performed at most once, lazily, right before the child's first real
 * compat-layer operation: import inherited fds, re-materialise the
 * parent's shared mappings at identical addresses, then block until the
 * parent's fork() has returned. */
static void px_fork_child_handshake(void)
{
    HANDLE r;
    if (InterlockedCompareExchange(&px_fork_state, 2, 1) != 1) return;
    px_fdtable_import();              /* pick up inherited pipe/socket fds */
    px_shmtable_import();             /* same shm pointers as the parent */
    r = OpenEventA(EVENT_SYNCHRONIZE, FALSE, px_fork_ev_ready);
    if (r) { WaitForSingleObject(r, INFINITE); CloseHandle(r); }
}

/* hook called by the public wrappers in unistd.h before doing real work */
static void px_fork_lazy_handshake(void)
{
    px_fork_arm_if_child();
    if (px_fork_state == 1) px_fork_child_handshake();
}

static pid_t px_fork(void)
{
    long seq;
    char tag[96];
    char names[2][160];
    HANDLE ev_ready = NULL, ev_ack = NULL;
    PROCESS_INFORMATION pi;
    char *cmdline = NULL;
    char xchild[352], xppid[64], xshm[sizeof(PX_SHMTABLE_ENV) + 8192];
    char *extra[4];
    WCHAR self[MAX_PATH * 2];
    int rc, i;

    /* one-time: detect that *we* are a forked child and finish any
       pending handshake before doing anything else */
    px_fork_arm_if_child();
    px_fork_lazy_handshake();

    seq = InterlockedIncrement(&px_fork_seq);
    snprintf(tag, sizeof(tag), "%lu_%ld",
             (unsigned long)GetCurrentProcessId(), seq);
    snprintf(names[0], sizeof(names[0]), "pxfork_%s_r", tag);
    snprintf(names[1], sizeof(names[1]), "pxfork_%s_a", tag);

    ev_ready = CreateEventA(NULL, TRUE, FALSE, names[0]);
    ev_ack   = CreateEventA(NULL, TRUE, FALSE, names[1]);
    if (!ev_ready || !ev_ack) {
        if (ev_ready) CloseHandle(ev_ready);
        if (ev_ack)   CloseHandle(ev_ack);
        px_set_errno_from_win();
        return -1;
    }

    /* rebuild "<self-exe> <original args...>" as a UTF-8 command line */
    if (px_self_path_w(self, sizeof(self) / sizeof(self[0])) != 0) {
        CloseHandle(ev_ready); CloseHandle(ev_ack);
        px_set_errno_from_win();
        return -1;
    }
    {
        int n0 = WideCharToMultiByte(CP_UTF8, 0, self, -1, NULL, 0, NULL, NULL);
        size_t total = (size_t)(n0 > 0 ? n0 : 1) + 8;
        char *p;
        size_t left;
        for (i = 1; i < __argc; i++) {
            int need = WideCharToMultiByte(CP_UTF8, 0, __wargv[i], -1,
                                           NULL, 0, NULL, NULL);
            total += (size_t)(need > 0 ? need : 1) * 4 + 4;
        }
        cmdline = (char *)malloc(total + 1);
        if (!cmdline) {
            CloseHandle(ev_ready); CloseHandle(ev_ack);
            errno = ENOMEM;
            return -1;
        }
        p = cmdline;
        left = total;
        *p++ = '"'; left--;
        {
            int got = WideCharToMultiByte(CP_UTF8, 0, self, -1, p,
                                          (int)(left > 2000 ? 2000 : left),
                                          NULL, NULL);
            if (got > 0) p += strlen(p);
        }
        *p++ = '"'; left = total - (size_t)(p - cmdline) - 1;
        for (i = 1; i < __argc; i++) {
            char *u8 = NULL;
            int need = WideCharToMultiByte(CP_UTF8, 0, __wargv[i], -1,
                                           NULL, 0, NULL, NULL);
            if (need > 0) {
                u8 = (char *)malloc((size_t)need);
                if (u8)
                    WideCharToMultiByte(CP_UTF8, 0, __wargv[i], -1,
                                        u8, need, NULL, NULL);
            }
            *p++ = ' '; left--;
            p = px_append_arg(p, &left, u8 ? u8 : "");
            if (u8) free(u8);
        }
        *p = '\0';
    }

    snprintf(xchild, sizeof(xchild), "%s=%s;%s",
             PX_FORK_CHILD_ENV, names[0], names[1]);
    snprintf(xppid,  sizeof(xppid),  "%s=%d",
             PX_FORK_PPID_ENV, (int)_getpid());
    /* snapshot the shared mappings NOW: the child re-maps them at the
       identical virtual addresses inside its fork handshake */
    snprintf(xshm, sizeof(xshm), "%s=%s", PX_SHMTABLE_ENV, px_shmtable_encode());
    extra[0] = xchild; extra[1] = xppid; extra[2] = xshm; extra[3] = NULL;

    rc = px_spawn(NULL, cmdline, extra, 0, &pi);
    free(cmdline);
    if (rc != 0) {
        CloseHandle(ev_ready); CloseHandle(ev_ack);
        return -1;
    }

    /* register the child, release it, wait for its ack */
    px_proc_add((pid_t)pi.dwProcessId, pi.hProcess, pi.hThread);
    SetEvent(ev_ready);
    {
        HANDLE waits[2];
        DWORD r;
        waits[0] = ev_ack;
        waits[1] = pi.hProcess;
        r = WaitForMultipleObjects(2, waits, FALSE, 30000);
        if (r == WAIT_TIMEOUT) {
            /* child never reached its arm point: keep it alive but stop
               waiting for the ack (it may still run as a plain copy) */
        } else if (r != WAIT_OBJECT_0) {
            /* the process died before acknowledging: reap it and report
               an error so the parent can react like on POSIX fork() */
            px_proc_handle((pid_t)pi.dwProcessId, 0);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            CloseHandle(ev_ready); CloseHandle(ev_ack);
            errno = EAGAIN;
            return -1;
        }
    }
    CloseHandle(ev_ready);
    CloseHandle(ev_ack);
    return (pid_t)pi.dwProcessId;
}

/* ------------------------------------------------------------------ */
/* exec family                                                         */
/* ------------------------------------------------------------------ */
/* Build a UTF-8 command line from program path + argv[1..]. */
static char *px_build_exec_cmdline(const char *prog, char *const argv[])
{
    size_t total = strlen(prog) + 8;
    size_t left;
    char *cmdline, *p;
    int i;
    for (i = 1; argv[i]; i++) total += strlen(argv[i]) * 4 + 4;
    cmdline = (char *)malloc(total + 1);
    if (!cmdline) return NULL;
    p = cmdline;
    *p++ = '"';
    strcpy(p, prog); p += strlen(prog);
    *p++ = '"';
    left = total - (size_t)(p - cmdline) - 1;
    for (i = 1; argv[i]; i++) {
        *p++ = ' '; left--;
        p = px_append_arg(p, &left, argv[i]);
    }
    *p = '\0';
    return cmdline;
}

/* Try CreateProcessW with an explicit app name; on failure fall back to
   letting Windows parse the command line itself (app_path = NULL). */
static int px_spawn_executable(const char *full_utf8, const WCHAR *wfull,
                               char *const cmdline, char *const rows[],
                               PROCESS_INFORMATION *pi)
{
    int rc = px_spawn(wfull, cmdline, rows, 0, pi);
    if (rc != 0) {
        char *plain = NULL;
        size_t l = strlen(full_utf8);
        plain = (char *)malloc(l + 3);
        if (plain) {
            plain[0] = '"';
            memcpy(plain + 1, full_utf8, l);
            plain[l + 1] = '"';
            plain[l + 2] = '\0';
            rc = px_spawn(NULL, plain, rows, 0, pi);
            free(plain);
        }
    }
    return rc;
}

static int px_exec_common(const char *path, char *const argv[],
                          char *const envp[], int search_path)
{
    PROCESS_INFORMATION pi;
    char *cmdline = NULL;
    char full[4096];
    WCHAR wfull[MAX_PATH * 2];
    int i, rc, need;
    char **rows = NULL; /* envp spliced as extra rows (NULL = inherit) */

    if (!path || !argv) { errno = EFAULT; return -1; }

    /* ---- resolve program path ---- */
    full[0] = '\0';
    if (search_path && !strchr(path, '/') && !strchr(path, '\\')) {
        DWORD n = SearchPathA(NULL, path, ".exe", sizeof(full), full);
        if (n == 0 || n >= sizeof(full)) {
            /* not found on PATH: pass through and let CreateProcess fail */
            snprintf(full, sizeof(full), "%s", path);
        }
    } else {
        snprintf(full, sizeof(full), "%s", path);
    }
    need = MultiByteToWideChar(CP_UTF8, 0, full, -1, wfull,
                               (int)(sizeof(wfull) / sizeof(wfull[0])));
    if (need <= 0) { errno = ENAMETOOLONG; return -1; }

    /* ---- command line: program + argv[1..] (argv[0] is per POSIX
           merely the logical name; the image comes from `path`) ---- */
    cmdline = px_build_exec_cmdline(full, argv);
    if (!cmdline) return -1;

    /* ---- environment: envp==NULL -> inherit current; else splice the
           supplied NAME=value rows over the current block.  (Windows has
           no way to hand a child a *strictly* envp-only environment while
           keeping the CRT's hidden pseudo-vars working.) ---- */
    if (envp) {
        int n = 0;
        for (i = 0; envp[i]; i++) n++;
        rows = (char **)malloc(((size_t)n + 1) * sizeof(char *));
        if (!rows) { free(cmdline); errno = ENOMEM; return -1; }
        for (i = 0; i < n; i++) rows[i] = envp[i];
        rows[n] = NULL;
    }

    rc = px_spawn_executable(full, wfull, cmdline, rows, &pi);
    free(cmdline);
    if (rows) free(rows);
    if (rc != 0) return -1;

    /* exec replaces us: finish any pending fork handshake state, apply
       close-on-exec to our own table, forget (now orphaned) children,
       wait for the new program, propagate its exit status */
    px_fork_arm_if_child();
    px_fork_lazy_handshake();
    for (i = 3; i < 256; i++)
        if (_get_osfhandle(i) != -1 && px_fdinfo_cloexec(i)) _close(i);
    px_proc_forget_all();
    px_shmtable_forget_all(); /* POSIX: shared anon mappings do not survive exec */
    WaitForSingleObject(pi.hProcess, INFINITE);
    {
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        exit((int)code);
    }
    return -1; /* not reached */
}

/* collect varargs (up to the NULL terminator) into a fresh argv array */
static char **px_vararg_argv(const char *arg0, va_list ap)
{
    char **av;
    int n = 0, cap = 16;
    av = (char **)malloc((size_t)cap * sizeof(char *));
    if (!av) return NULL;
    av[n++] = (char *)arg0;
    for (;;) {
        char *s = va_arg(ap, char *);
        if (!s) break;
        if (n + 1 >= cap) {
            char **nv = (char **)realloc(av, (size_t)(cap *= 2) * sizeof(char *));
            if (!nv) break;
            av = nv;
        }
        av[n++] = s;
    }
    av[n] = NULL;
    return av;
}

static int execl(const char *path, const char *arg0, ...)
{
    va_list ap; char **av; int rc;
    if (!arg0) return px_exec_common(path, NULL, NULL, 0);
    va_start(ap, arg0);
    av = px_vararg_argv(arg0, ap);
    va_end(ap);
    if (!av) return -1;
    rc = px_exec_common(path, av, NULL, 0);
    free(av);
    return rc;
}

static int execle(const char *path, const char *arg0, ...)
{
    va_list ap; char **av; char **ev = NULL; int rc;
    if (!arg0) return px_exec_common(path, NULL, NULL, 0);
    va_start(ap, arg0);
    av = px_vararg_argv(arg0, ap);
    ev = va_arg(ap, char **);
    va_end(ap);
    if (!av) return -1;
    rc = px_exec_common(path, av, ev, 0);
    free(av);
    return rc;
}

static int execlp(const char *file, const char *arg0, ...)
{
    va_list ap; char **av; int rc;
    if (!arg0) return px_exec_common(file, NULL, NULL, 1);
    va_start(ap, arg0);
    av = px_vararg_argv(arg0, ap);
    va_end(ap);
    if (!av) return -1;
    rc = px_exec_common(file, av, NULL, 1);
    free(av);
    return rc;
}

static int execv(const char *path, char *const argv[])
{ return px_exec_common(path, (char *const *)argv, NULL, 0); }

static int execve(const char *path, char *const argv[], char *const envp[])
{ return px_exec_common(path, (char *const *)argv, (char *const *)envp, 0); }

static int execvp(const char *file, char *const argv[])
{ return px_exec_common(file, (char *const *)argv, NULL, 1); }

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* PX_COMPAT_WINPROC_H */
