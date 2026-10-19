/* fcntl.h - POSIX <fcntl.h> mapped onto the Win32 API (header-only).
 *
 * On non-Windows platforms this header includes the real <fcntl.h>.
 * License: MIT
 */
#ifndef PX_COMPAT_FCNTL_H
#define PX_COMPAT_FCNTL_H

#ifdef _WIN32

#include <fcntl.h>      /* CRT O_* / _SH_* flag values */
#include <io.h>
#include <stdarg.h>
#include <string.h>
#include "compat/posix_defs.h"
#include "compat/winfd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- open flags ----------------------------------------------------
 * The CRT <fcntl.h> already defines O_RDONLY/O_WRONLY/O_RDWR/O_CREAT/
 * O_EXCL/O_TRUNC/O_APPEND/O_BINARY/O_TEXT/O_RANDOM/O_SEQUENTIAL/
 * O_TEMPORARY/O_NOINHERIT/O_SHORTNAME.  We add the POSIX-only ones. */
#ifndef O_DIRECTORY
#define O_DIRECTORY   0x100000   /* emulated: checked after open */
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC     0x200000   /* Windows handles are non-inheritable by default (_O_NOINHERIT) */
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK    _O_NONBLOCK
#endif
#ifndef O_SYNC
#define O_SYNC        0x400000   /* emulated via _commit() on write */
#endif
#ifndef O_DSYNC
#define O_DSYNC       0x800000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW    0x01000000 /* emulated with FILE_FLAG_OPEN_REPARSE_POINT */
#endif
#ifndef O_SEARCH
#define O_SEARCH      0x02000000
#endif
#ifndef O_EXEC
#define O_EXEC        0x04000000
#endif

/* AT_* may already come from unistd.h; guard */
#ifndef AT_FDCWD
#define AT_FDCWD            (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_REMOVEDIR        0x200
#define AT_SYMLINK_FOLLOW   0x400
#define AT_EMPTY_PATH       0x1000
#endif

/* F_* commands: use distinct values so they never clash with the CRT's
   F_DUPFD/F_GETFD/F_SETFD/F_GETFL/F_SETFL (which we honour anyway). */
#ifndef F_DUPFD
#define F_DUPFD   0
#endif
#ifndef F_GETFD
#define F_GETFD  1
#endif
#ifndef F_SETFD
#define F_SETFD  2
#endif
#ifndef F_GETFL
#define F_GETFL  3
#endif
#ifndef F_SETFL
#define F_SETFL  4
#endif
#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC 1030
#endif
#define F_GETLK   5
#define F_SETLK   6
#define F_SETLKW  7
#define FD_CLOEXEC 1

struct flock {
    short l_type;   /* F_RDLCK, F_WRLCK, F_UNLCK */
    short l_whence; /* SEEK_SET/CUR/END */
    off_t l_start;
    off_t l_len;
    pid_t l_pid;
};
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

/* ---- open* family --------------------------------------------------
 * These functions do take an explicit mode argument, so plain statics
 * work here (unlike the variadic open() macro in <unistd.h>).
 */
static int px_openat_impl(int dirfd, const char *path, int oflag, int pmode)
{
    char full[4096], base[4096];
    (void)pmode;
    if (dirfd != AT_FDCWD && path && path[0] != '/' && path[1] != ':') {
        if (px_fd_getcwd(dirfd, base, sizeof(base)) == NULL) return -1;
        snprintf(full, sizeof(full), "%s\\%s", base, path);
        path = full;
    }
    {
        int fd = _open(path, oflag | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
        if (fd == -1) { px_set_errno_from_win(); return -1; }
        if ((oflag & O_DIRECTORY)) {
            struct _stati64 st;
            if (_stati64(path, &st) != 0 || !(st.st_mode & _S_IFDIR)) {
                _close(fd); errno = ENOTDIR; return -1;
            }
        }
        if (oflag & O_NONBLOCK) {
            HANDLE h = (HANDLE)_get_osfhandle(fd);
            if (px_fd_is_socket(fd)) {
                u_long nb = 1;
                ioctlsocket((SOCKET)h, FIONBIO, &nb);
            }
        }
        return fd;
    }
}
static int openat(int dirfd, const char *path, int oflag, int pmode)
{ return px_openat_impl(dirfd, path, oflag, pmode); }

static int open(const char *path, int oflag, int pmode)
{ return px_openat_impl(AT_FDCWD, path, oflag, pmode); }

/* F_GETFL needs the current status flags: emulate with a small table */
static int px_fd_flags[256];
static int px_fcntl_getfl(int fd)
{
    int accmode;
    if (fd >= 0 && fd < (int)(sizeof(px_fd_flags)/sizeof(px_fd_flags[0])) &&
        px_fd_flags[fd])
        return px_fd_flags[fd];
    accmode = _isatty(fd) >= 0 ? O_RDWR : 0;
    return accmode;
}

/* remember status flags set through fcntl(F_SETFL) so F_GETFL can report them */
static void px_fcntl_setfl(int fd, long flags)
{
    if (fd >= 0 && fd < (int)(sizeof(px_fd_flags)/sizeof(px_fd_flags[0]))) {
        px_fd_flags[fd] = (int)((flags & (O_NONBLOCK | O_APPEND)) |
                                (px_fd_flags[fd] & ~(long)(O_NONBLOCK | O_APPEND)));
    }
}

/* helper: extend a file through its handle (used by posix_fallocate) */
static int ftruncate_via_handle(int fd, off_t newsize)
{
    HANDLE h = px_fd_handle(fd);
    LARGE_INTEGER li;
    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    li.QuadPart = (LONGLONG)newsize;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN) || !SetEndOfFile(h)) {
        px_set_errno_from_win(); return -1;
    }
    return 0;
}

/* ---- descriptor manipulation ---------------------------------------- */
static int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    long arg;
    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);

    switch (cmd) {
    case F_DUPFD:
        return _dup(fd);          /* exact-number dup not supported by CRT */
    case F_DUPFD_CLOEXEC:
        return _dup(fd);
    case F_GETFD:
        return 0;                 /* all our fds are CLOEXEC-equivalent */
    case F_SETFD:
        return 0;
    case F_GETFL:
        return px_fcntl_getfl(fd);
    case F_SETFL:
        /* only O_NONBLOCK is changeable at runtime */
        if (px_fd_is_socket(fd)) {
            u_long nb = (arg & O_NONBLOCK) ? 1 : 0;
            int rr = ioctlsocket((SOCKET)_get_osfhandle(fd), FIONBIO, &nb);
            px_fcntl_setfl(fd, arg);
            return rr == 0 ? 0 : -1;
        }
        px_fcntl_setfl(fd, arg);
        return 0; /* regular files are always "blocking" on Windows */
    case F_GETLK:
    case F_SETLK:
    case F_SETLKW: {
        struct flock *lk = (struct flock *)arg;
        HANDLE h = px_fd_handle(fd);
        BOOL wait = (cmd == F_SETLKW);
        OVERLAPPED ov;
        LARGE_INTEGER s_off, s_len;
        memset(&ov, 0, sizeof(ov));
        if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
        s_off.QuadPart = lk->l_start;
        s_len.QuadPart = lk->l_len ? lk->l_len : 0x7FFFFFFFFFFFFFFFll;
        if (lk->l_type == F_UNLCK) {
            if (!UnlockFile(h, (DWORD)(s_off.QuadPart & 0xFFFFFFFF),
                            (DWORD)((UINT64)s_off.QuadPart >> 32),
                            (DWORD)(s_len.QuadPart & 0xFFFFFFFF),
                            (DWORD)((UINT64)s_len.QuadPart >> 32))) {
                px_set_errno_from_win(); return -1;
            }
            return 0;
        }
        if (!LockFileEx(h,
                (lk->l_type == F_WRLCK ? LOCKFILE_EXCLUSIVE_LOCK : 0) |
                (wait ? 0 : LOCKFILE_FAIL_IMMEDIATELY),
                0,
                (DWORD)(s_len.QuadPart & 0xFFFFFFFF),
                (DWORD)((UINT64)s_len.QuadPart >> 32),
                &ov)) {
            px_set_errno_from_win();
            if (cmd == F_SETLK) { errno = EAGAIN; return -1; }
            return -1;
        }
        return 0;
    }
    default:
        errno = EINVAL; return -1;
    }
}

static int posix_fallocate(int fd, off_t offset, off_t len)
{
    if (ftruncate_via_handle(fd, offset + len) != 0) return errno ? errno : EINVAL;
    return 0;
}



#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <fcntl.h>
#endif

#endif /* PX_COMPAT_FCNTL_H */
