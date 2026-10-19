/* unistd.h - POSIX <unistd.h> mapped onto the Win32 API (header-only).
 *
 * On non-Windows platforms this header just includes the real <unistd.h>.
 * License: MIT
 */
#ifndef PX_COMPAT_UNISTD_H
#define PX_COMPAT_UNISTD_H

#ifdef _WIN32

#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <stdlib.h>
#include <string.h>
#include "compat/posix_defs.h"
#include "compat/winfd.h"
#include "compat/winpath.h"  /* unix-path <-> win32-path translation */
#include "compat/winproc.h"   /* fork()/exec*() emulation */

#ifdef __cplusplus
extern "C" {
#endif

/* ---- constants -------------------------------------------------- */
#define R_OK 4
#define W_OK 2
#define X_OK 1   /* no exec-permission concept on Windows: like F_OK */
#define F_OK 0

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#ifndef _SC_PAGESIZE
#define _SC_PAGESIZE         30
#define _SC_CLK_TCK          2
#define _SC_OPEN_MAX         4
#define _SC_HOST_NAME_MAX    180
#define _SC_LINE_MAX         1024
#define _SC_NPROCESSORS_ONLN 84
#endif

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
#endif

/* AT_* constants (also referenced by fcntl.h / sys/stat.h mappings) */
#ifndef AT_FDCWD
#define AT_FDCWD            (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR        0x200
#define AT_SYMLINK_FOLLOW   0x400
#define AT_EMPTY_PATH       0x1000
#endif

/* ---- file descriptor I/O ----------------------------------------- */
static ssize_t read(int fd, void *buf, size_t n)
{
    px_fork_lazy_handshake(); /* arm + finish fork handshake once */
    ssize_t r = px_fd_read(fd, buf, n); /* dispatches files vs sockets */
    if (r == -1) px_set_errno_from_win();
    return r;
}

static ssize_t write(int fd, const void *buf, size_t n)
{
    px_fork_lazy_handshake();
    ssize_t r = px_fd_write(fd, buf, n);
    if (r == -1) px_set_errno_from_win();
    return r;
}

static ssize_t pread(int fd, void *buf, size_t n, off_t offset)
{
    HANDLE h = px_fd_handle(fd);
    OVERLAPPED ov;
    DWORD rd = 0;
    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    memset(&ov, 0, sizeof(ov));
    ov.Offset     = (DWORD)((UINT64)offset & 0xFFFFFFFFull);
    ov.OffsetHigh = (DWORD)(((UINT64)offset >> 32) & 0xFFFFFFFFull);
    if (!ReadFile(h, buf, (DWORD)n, &rd, &ov)) { px_set_errno_from_win(); return -1; }
    return (ssize_t)rd;
}

static ssize_t pwrite(int fd, const void *buf, size_t n, off_t offset)
{
    HANDLE h = px_fd_handle(fd);
    OVERLAPPED ov;
    DWORD wr = 0;
    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    memset(&ov, 0, sizeof(ov));
    ov.Offset     = (DWORD)((UINT64)offset & 0xFFFFFFFFull);
    ov.OffsetHigh = (DWORD)(((UINT64)offset >> 32) & 0xFFFFFFFFull);
    if (!WriteFile(h, buf, (DWORD)n, &wr, &ov)) { px_set_errno_from_win(); return -1; }
    return (ssize_t)wr;
}

static off_t lseek(int fd, off_t offset, int whence)
{
    long r = _lseek(fd, (long)offset, whence);
    if (r == -1L) px_set_errno_from_win();
    return (off_t)r;
}

static off64_t lseek64(int fd, off64_t offset, int whence)
{
    __int64 r = _lseeki64(fd, (__int64)offset, whence);
    if (r == -1LL) px_set_errno_from_win();
    return (off64_t)r;
}

static int fsync(int fd)     { return _commit(fd); }
static int fdatasync(int fd) { return _commit(fd); }
static int close(int fd)     { return px_fd_close(fd); }
static int dup(int fd)       { return _dup(fd); }
static int dup2(int a, int b){ return _dup2(a, b); }

static int truncate(const char *path, off_t length)
{
    HANDLE h;
    LARGE_INTEGER li;
    DWORD err;
    h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { px_set_errno_from_win(); return -1; }
    li.QuadPart = (LONGLONG)length;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN) || !SetEndOfFile(h)) {
        err = GetLastError(); CloseHandle(h); SetLastError(err);
        px_set_errno_from_win(); return -1;
    }
    CloseHandle(h);
    return 0;
}

static int ftruncate(int fd, off_t length)
{
    HANDLE h = px_fd_handle(fd);
    LARGE_INTEGER li;
    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    li.QuadPart = (LONGLONG)length;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN) || !SetEndOfFile(h)) {
        px_set_errno_from_win(); return -1;
    }
    return 0;
}

/* ---- open / create ------------------------------------------------
 * open() is a macro so the optional variadic `mode` argument works.
 * O_* flag values are identical to the CRT's in <fcntl.h>.
 * Absolute unix paths ("/...", "/c/...", "/cygdrive/c/...") are resolved
 * through compat/winpath.h; POSIX device files (/dev/null, /dev/zero,
 * /dev/random, /dev/fd/N, ...) and virtual system files (/proc/...,
 * /etc/passwd, ...) are served by px_dev_open().
 */
static int px_open_impl(const char *path, int oflag, int pmode)
{
    int fd;
    /* POSIX mode_t permission bits have no direct Win32 equivalent;
       they map to FILE_ATTRIBUTE_READONLY semantics handled by chmod(). */
    (void)pmode;
    if (!px_path_native_mode() && path && path[0] == '/' &&
        px_dev_is_special(path))
        return px_dev_open(path, oflag);
    fd = PX_PATH_RUN(path, ({
        int _r = _open(p, oflag | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
        if (_r == -1) px_set_errno_from_win();
        _r;
    }));
    return fd;
}
/* open() takes an optional third (mode) argument -> variadic macro.
 * MSVC's traditional preprocessor splices __VA_ARGS__ correctly here. */
#define open(path, oflag, ...)         px_open_impl((path), (oflag), (int)(0 __VA_ARGS__))

static int creat(const char *path, mode_t mode)
{
    return px_open_impl(path, _O_CREAT | _O_TRUNC | _O_WRONLY, (int)mode);
}

/* ---- file system ---------------------------------------------------
 * Every absolute path below goes through compat/winpath.h: "/..." is
 * resolved against the virtual POSIX root (PX_UNIX_ROOT or an auto-detected
 * pxroot directory), "/c/..." and "/cygdrive/c/..." map to real drives,
 * native "C:\..." paths and relative paths pass through untouched.
 */
static int unlink(const char *path)
{
    return PX_PATH_RUN(path, ({
        int _r = _unlink(p);
        if (_r == 0) px_lnk_remove(p);      /* drop sidecar of emulated link */
        else {
            _chmod(p, _S_IWRITE);           /* retry after clearing read-only */
            _r = _unlink(p);
            if (_r == 0) px_lnk_remove(p);
            else px_set_errno_from_win();
        }
        _r;
    }));
}

static int rmdir(const char *path)
{
    return PX_PATH_RUN(path, ({
        int _r = _rmdir(p);
        if (_r != 0) px_set_errno_from_win();
        _r;
    }));
}

static int mkdir(const char *path, mode_t mode)
{
    (void)mode;
    return PX_PATH_RUN(path, ({
        int _r = _mkdir(p);
        if (_r != 0) {
            if (GetLastError() == ERROR_ALREADY_EXISTS) { errno = EEXIST; _r = -1; }
            else px_set_errno_from_win();
        }
        _r;
    }));
}

static int access(const char *path, int amode)
{
    if (!px_path_native_mode() && path && path[0] == '/' &&
        px_dev_is_special(path))
        return 0;                           /* devices/virtual files exist */
    return PX_PATH_RUN(path, ({
        int _m = (amode == X_OK) ? F_OK : amode;
        int _r = _access(p, _m);
        if (_r != 0) px_set_errno_from_win();
        _r;
    }));
}

static int faccessat(int dirfd, const char *path, int amode, int flag)
{
    char full[4200], base[4096];
    (void)flag;
    if (dirfd != AT_FDCWD && path && path[0] != '/' && path[1] != ':') {
        if (px_fd_getcwd(dirfd, base, sizeof(base)) == NULL) return -1;
        snprintf(full, sizeof(full), "%s\\%s", base, path);
        path = full;
    }
    return access(path, amode);
}

static int rename(const char *oldpath, const char *newpath)
{
    char wnew[4200];
    int trn;
    return PX_PATH_RUN(oldpath, ({
        const char *_np = newpath;
        trn = px_path_translate(newpath, wnew, sizeof(wnew));
        if (trn > 0) _np = wnew;
        /* follow an emulated symlink at the destination like POSIX does */
        {
            char *_t = px_lnk_read(_np);
            if (_t) {
                strncpy(wnew, _t, sizeof(wnew) - 1);
                wnew[sizeof(wnew) - 1] = '\0';
                _np = wnew;
                free(_t);
            }
        }
        if (MoveFileExA(p, _np, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
            px_lnk_move(p, _np);            /* keep sidecars in sync */
            0;
        } else { px_set_errno_from_win(); -1; }
    }));
}

static int chown(const char *path, uid_t owner, gid_t group)
{
    /* Real ownership changes need SetSecurityInfo(); treat as a no-op for
       visible files, matching the common single-user desktop case. */
    (void)owner; (void)group;
    return access(path, F_OK);
}
static int lchown(const char *path, uid_t owner, gid_t group)
{ return chown(path, owner, group); }
static int fchown(int fd, uid_t owner, gid_t group)
{ (void)owner; (void)group;
  if (fd < 0) { errno = EBADF; return -1; }
  return 0; }

static int chmod(const char *path, mode_t mode)
{
    return PX_PATH_RUN(path, ({
        int _r = _chmod(p, (mode & 0200) ? _S_IWRITE : _S_IREAD);
        if (_r != 0) px_set_errno_from_win();
        _r;
    }));
}
static int fchmod(int fd, mode_t mode)
{ (void)fd; (void)mode; errno = ENOTSUP; return -1; }

static int link(const char *oldpath, const char *newpath)
{
    char wnew[4200];
    int trn;
    return PX_PATH_RUN(oldpath, ({
        const char *_np = newpath;
        trn = px_path_translate(newpath, wnew, sizeof(wnew));
        if (trn > 0) _np = wnew;
        if (CreateHardLinkA(_np, p, NULL)) 0;
        else { px_set_errno_from_win(); -1; }
    }));
}

static int symlink(const char *oldpath, const char *newpath)
{
    char wnew[4200];
    int trn;
    const char *wlink = newpath;
    trn = px_path_translate(newpath, wnew, sizeof(wnew));
    if (trn < 0) { errno = ENAMETOOLONG; return -1; }
    if (trn > 0) wlink = wnew;
    {
        DWORD flags = (GetFileAttributesA(oldpath) & FILE_ATTRIBUTE_DIRECTORY)
                    ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;
        if (CreateSymbolicLinkA(wlink, oldpath,
                                flags | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
            return 0;
        /* unprivileged Windows without developer mode: fall back to the
           ".pxlnk" sidecar emulation understood by readlink()/stat().
           The target stays in unix form so readers see POSIX strings. */
        return px_symlink_emulate(oldpath, wlink);
    }
}
static int symlinkat(const char *oldpath, int dirfd, const char *newpath)
{
    char q[4200], base[4096];
    (void)dirfd;
    if (dirfd != AT_FDCWD && newpath && newpath[0] != '/' && newpath[1] != ':') {
        if (px_fd_getcwd(dirfd, base, sizeof(base)) == NULL) return -1;
        snprintf(q, sizeof(q), "%s\\%s", base, newpath);
        newpath = q;
    }
    return symlink(oldpath, newpath);
}
static int linkat(int oldfd, const char *oldpath, int newfd,
                  const char *newpath, int flags)
{
    (void)oldfd; (void)newfd; (void)flags;
    return link(oldpath, newpath);
}
static int unlinkat(int dirfd, const char *path, int flags)
{
    (void)dirfd;
    if (flags & AT_REMOVEDIR) return rmdir(path);
    return unlink(path);
}
static int renameat(int oldfd, const char *oldp, int newfd, const char *newp)
{
    (void)oldfd; (void)newfd;
    return rename(oldp, newp);
}

static ssize_t readlink(const char *path, char *buf, size_t bufsiz)
{
    char win[4200];
    int tr;
    tr = px_path_translate(path, win, sizeof(win));
    if (tr < 0) { errno = ENAMETOOLONG; return -1; }
    if (tr > 0) path = win;
    {
        char target[4096];
        DWORD n;
        char *emul = px_lnk_read(path);
        if (emul) {                        /* emulated (.pxlnk) link first */
            size_t l = strlen(emul);
            if (l > bufsiz) l = bufsiz;
            memcpy(buf, emul, l);
            free(emul);
            return (ssize_t)l;
        }
        n = px_reparse_target(path, target, sizeof(target));
        if (n == 0) { px_set_errno_from_win(); return -1; }
        if ((size_t)n > bufsiz) n = (DWORD)bufsiz;
        memcpy(buf, target, n);
        return (ssize_t)n;
    }
}
static ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    (void)dirfd;
    return readlink(path, buf, bufsiz);
}

/* ---- process ------------------------------------------------------- */
static pid_t getpid(void)  { return (pid_t)_getpid(); }
static pid_t getppid(void)
{
    /* Win32 has no parent-PID API; our fork() emulation records it in the
       child's environment before exec'ing.  Fall back to ENOSYS for
       processes that were not created through px_fork(). */
    const char *v = getenv("PX_FORK_PPID");
    if (v && *v) return (pid_t)atoi(v);
    errno = ENOSYS;
    return -1;
}
static uid_t getuid(void)  { return 0; }
static uid_t geteuid(void) { return 0; }
static gid_t getgid(void)  { return 0; }
static gid_t getegid(void) { return 0; }
static int setuid(uid_t u) { (void)u; return 0; }
static int setgid(gid_t g) { (void)g; return 0; }

static unsigned int sleep(unsigned int s)
{
    Sleep(s * 1000u);
    return 0;
}
static int usleep(useconds_t us)
{
    Sleep(us / 1000u);
    return 0;
}
static int nanosleep(const struct timespec *req, struct timespec *rem)
{
    DWORD ms = (DWORD)(req->tv_sec * 1000 + req->tv_nsec / 1000000);
    if (ms == 0 && (req->tv_sec || req->tv_nsec)) ms = 1;
    Sleep(ms);
    if (rem) { rem->tv_sec = 0; rem->tv_nsec = 0; }
    return 0;
}

static int isatty(int fd) { return _isatty(fd); }

static char *getcwd(char *buf, size_t size)
{
    char raw[4200];
    if (!_getcwd(raw, (int)sizeof(raw))) { px_set_errno_from_win(); return NULL; }
    /* report the process cwd in unix form ("/c/dir" or "/rest-under-root") */
    if (!px_path_native_mode()) {
        char ux[4200];
        px_path_untranslate(raw, -1, ux, sizeof(ux));
        if (strlen(ux) + 1 <= size) { memcpy(buf, ux, strlen(ux) + 1); return buf; }
        errno = ERANGE;
        return NULL;
    }
    if (strlen(raw) + 1 <= size) { memcpy(buf, raw, strlen(raw) + 1); return buf; }
    errno = ERANGE;
    return NULL;
}
static int chdir(const char *path)
{
    return PX_PATH_RUN(path, ({
        int _r = _chdir(p);
        if (_r != 0) px_set_errno_from_win();
        _r;
    }));
}
static int fchdir(int fd)
{
    char p[4096];
    if (px_fd_getcwd(fd, p, sizeof(p)) == NULL) return -1;
    return chdir(p);
}
static int chroot(const char *path) { (void)path; errno = ENOSYS; return -1; }

static char *getlogin(void)
{
    static char name[256];
    DWORD sz = sizeof(name);
    if (GetUserNameA(name, &sz)) return name;
    return NULL;
}
#define getlogname() getlogin()

static long sysconf(int name)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    switch (name) {
    case _SC_PAGESIZE:         return (long)si.dwPageSize;
    case _SC_CLK_TCK:          return 1000;
    case _SC_OPEN_MAX:         return 8192;
    case _SC_HOST_NAME_MAX:    return 256;
    case _SC_NPROCESSORS_ONLN: return (long)si.dwNumberOfProcessors;
    default: errno = EINVAL; return -1;
    }
}

static char *ttyname(int fd)
{
    static char b[16];
    if (!_isatty(fd)) { errno = ENOTTY; return NULL; }
    return strcpy(b, "CON");
}
static int ttyname_r(int fd, char *buf, size_t len)
{
    if (!_isatty(fd)) return ENOTTY;
    snprintf(buf, len, "CON");
    return 0;
}

static void sync(void) { /* per-volume flush happens via FlushFileBuffers */ }

/* alarm(): one-shot SIGALRM timer (winfd.h + signal.h vectored handler) */
static unsigned int alarm(unsigned int seconds) { return px_alarm(seconds); }

/* pipe()/pipe2(): loopback socketpair emulation (winfd.h) */
static int pipe(int fds[2])           { return px_pipe(fds, 0); }
static int pipe2(int fds[2], int flags) { return px_pipe(fds, flags); }

/* ---- fork() / exec*() ----------------------------------------------
 * Windows has no native fork(); compat/winproc.h emulates it by
 * spawning a fresh copy of the current executable with a handshake so
 * `pid = fork(); if (pid == 0) ...` behaves like POSIX.  Shared memory
 * crosses the boundary: mappings created through mmap(MAP_SHARED) or
 * <sys/shm.h>'s px_shm_open() are re-materialised in the child at the
 * IDENTICAL virtual address backed by the same physical pages (fork-tree address-space
 * overlay -- see winproc.h; this exceeds what Cygwin's private-clone
 * fork can do).  Pre-branch side effects still run twice.  exec*()
 * replaces this process image by running the new program and exiting
 * with its status; shared mappings are dropped across exec, per POSIX.
 */
static pid_t fork(void) { return px_fork(); }

/* MAP_SHARED anonymous mapping that survives fork() with identical
 * pointers in parent and children (POSIX mmap(MAP_SHARED|MAP_ANONYMOUS)
 * subset).  addr is ignored (fixed placement is part of the contract);
 * prot must be readable/writable. */
#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
#ifndef PROT_READ
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#endif
#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

static void *mmap(void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
    (void)addr; (void)prot;
    if (!(flags & MAP_SHARED)) { errno = EINVAL; return MAP_FAILED; }
    if ((flags & MAP_ANONYMOUS) || fd < 0) {
        void *p = px_shm_attach(length, NULL);
        return p ? p : MAP_FAILED;
    }
    errno = ENOTSUP;                /* file-backed maps: not emulated */
    return MAP_FAILED;
}

static int munmap(void *addr, size_t length)
{
    (void)length;
    return px_shm_detach(addr);
}

static int execl(const char *path, const char *arg0, ...);
static int execle(const char *path, const char *arg0, ...);
static int execlp(const char *file, const char *arg0, ...);
static int execv(const char *path, char *const argv[])
{ return px_exec_common(path, argv, NULL, 0); }
static int execve(const char *path, char *const argv[], char *const envp[])
{ return px_exec_common(path, argv, envp, 0); }
static int execvp(const char *file, char *const argv[])
{ return px_exec_common(file, argv, NULL, 1); }

#ifdef __cplusplus
}
#endif

#else /* !_WIN32: use the real system header */
#include <unistd.h>
#endif

#endif /* PX_COMPAT_UNISTD_H */
