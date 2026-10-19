/* compat/winfd.h - INTERNAL helpers shared by the POSIX->Win32 headers.
 *
 * Provides:
 *   - lazy Winsock startup
 *   - fd <-> HANDLE dispatch so read()/write()/close() work on both CRT
 *     file descriptors and Winsock sockets
 *   - pipe()/pipe2() emulated with a loopback socket pair
 *   - reparse-point (symlink) target reader used by readlink()
 *   - alarm() implemented with CreateTimerQueueTimer + RaiseException
 *   - fork()/exec*() process emulation (compat/winproc.h)
 *
 * Not part of the public API; included by <unistd.h>, <fcntl.h>, <poll.h>.
 * License: MIT
 */
#ifndef PX_COMPAT_WINFD_H
#define PX_COMPAT_WINFD_H

#ifdef _WIN32

#include "compat/posix_defs.h"
#include <winsock2.h>
#include <mswsock.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* fd cloexec bookkeeping (shared with compat/winproc.h)               */
/*                                                                     */
/* Windows env-var names are case-insensitive/upper-cased, so the       */
/* fork()/exec*() fd table in winproc.h avoids letters in its values.   */
/* The O_CLOEXEC bit value is defined here as well; <fcntl.h>           */
/* re-defines it identically.                                           */
/* ------------------------------------------------------------------ */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0x200000
#endif

typedef struct { int fd; int cloexec; } px_fdinfo_t;
static px_fdinfo_t px_fdinfo[256];
static int px_fdinfo_n = 0;

/* record close-on-exec state per fd so fork()/exec*() (winproc.h) can
 * decide which handles to hand to the child.  Also readable there via
 * the same statics (single translation unit when headers are included
 * from one .c file). */
static void px_fdinfo_set(int fd, int cloexec)
{
    int i;
    for (i = 0; i < px_fdinfo_n; i++)
        if (px_fdinfo[i].fd == fd) { px_fdinfo[i].cloexec = cloexec; return; }
    if (fd >= 0 && fd < 256 && px_fdinfo_n < 256) {
        px_fdinfo[px_fdinfo_n].fd = fd;
        px_fdinfo[px_fdinfo_n].cloexec = cloexec;
        px_fdinfo_n++;
    }
}
static int px_fdinfo_cloexec(int fd)
{
    int i;
    for (i = 0; i < px_fdinfo_n; i++)
        if (px_fdinfo[i].fd == fd) return px_fdinfo[i].cloexec;
    return 0; /* unknown: assume inheritable, like a fresh open() */
}

/* ------------------------------------------------------------------ */
/* winsock lazy init                                                   */
/* ------------------------------------------------------------------ */
static volatile long px_wsa_inited = 0;
static void px_wsa_init(void)
{
    if (px_wsa_inited) return;
    if (InterlockedCompareExchange(&px_wsa_inited, 1, 0) == 0) {
        WSADATA d;
        WSAStartup(MAKEWORD(2, 2), &d);
    }
}

/* ------------------------------------------------------------------ */
/* fd classification: is this CRT fd a socket?                         */
/* ------------------------------------------------------------------ */
static int px_fd_is_socket(int fd)
{
    int type = 0, len = sizeof(type);
    HANDLE h;
    if (fd < 0) return 0;
    h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    SetLastError(0);
    if (getsockopt((SOCKET)h, SOL_SOCKET, SO_TYPE, (char *)&type, &len) == 0)
        return 1;   /* only true for real sockets */
    return 0;
}

static HANDLE px_fd_handle(int fd)
{
    HANDLE h;
    if (fd < 0) return INVALID_HANDLE_VALUE;
    h = (HANDLE)_get_osfhandle(fd);
    return h;
}

static ssize_t px_fd_read(int fd, void *buf, size_t n)
{
    if (px_fd_is_socket(fd))
        return (ssize_t)recv((SOCKET)_get_osfhandle(fd), (char *)buf, (int)n, 0);
    return (ssize_t)_read(fd, buf, (unsigned)n);
}

static ssize_t px_fd_write(int fd, const void *buf, size_t n)
{
    if (px_fd_is_socket(fd))
        return (ssize_t)send((SOCKET)_get_osfhandle(fd), (const char *)buf, (int)n, 0);
    return (ssize_t)_write(fd, buf, (unsigned)n);
}

static int px_fd_close(int fd)
{
    if (px_fd_is_socket(fd)) {
        SOCKET s = (SOCKET)_get_osfhandle(fd);
        closesocket(s);      /* the CRT fd itself is closed by _close below */
    }
    return _close(fd);
}

/* ------------------------------------------------------------------ */
/* pipe(): loopback socket pair                                        */
/*                                                                     */
/* Windows has no fd-compatible pipes that work with poll/select in    */
/* every scenario, so we emulate with a TCP socketpair over the        */
/* loopback interface (AF_UNIX is available on Win10+ but not everywhere). */
/* ------------------------------------------------------------------ */
static int px_pipe(int fds[2], int flags)
{
    SOCKET ls, a, b;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);
    int opt = 1;
    u_long nb;

    px_wsa_init();

    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { px_set_errno_from_win(); return -1; }
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(ls, 1) == SOCKET_ERROR) {
        px_set_errno_from_win(); closesocket(ls); return -1;
    }
    if (getsockname(ls, (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR) {
        px_set_errno_from_win(); closesocket(ls); return -1;
    }
    a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (a == INVALID_SOCKET) { px_set_errno_from_win(); closesocket(ls); return -1; }
    if (connect(a, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        px_set_errno_from_win(); closesocket(a); closesocket(ls); return -1;
    }
    b = accept(ls, NULL, NULL);
    closesocket(ls);
    if (b == INVALID_SOCKET) { px_set_errno_from_win(); closesocket(a); return -1; }

    /* disable Nagle for latency parity with POSIX pipes */
    setsockopt(b, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
    setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));

    /* fds[0] = read end, fds[1] = write end */
    fds[0] = _open_osfhandle((intptr_t)b, _O_RDONLY |
                             ((flags & _O_NONBLOCK) ? _O_NONBLOCK : 0));
    fds[1] = _open_osfhandle((intptr_t)a, _O_WRONLY |
                             ((flags & _O_NONBLOCK) ? _O_NONBLOCK : 0));
    if (flags & _O_NONBLOCK) {
        nb = 1;
        ioctlsocket(b, FIONBIO, &nb);
        ioctlsocket(a, FIONBIO, &nb);
    }
    if (fds[0] == -1 || fds[1] == -1) {
        px_set_errno_from_win();
        if (fds[0] != -1) _close(fds[0]);
        if (fds[1] != -1) _close(fds[1]);
        return -1;
    }
    /* record cloexec state so fork()/exec*() export the right ends */
    px_fdinfo_set(fds[0], (flags & O_CLOEXEC) ? 1 : 0);
    px_fdinfo_set(fds[1], (flags & O_CLOEXEC) ? 1 : 0);
    return 0;
}

/* ------------------------------------------------------------------ */
/* symlink/reparse target reader                                       */
/* ------------------------------------------------------------------ */
#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK 0xA000000CL
#endif
#ifndef FSCTL_GET_REPARSE_POINT
#define FSCTL_GET_REPARSE_POINT 0x000900A8
#endif

typedef struct {
    ULONG ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG Flags;
            WCHAR PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    } DUMMYUNIONNAME;
} px_reparse_data_buffer;

static DWORD px_reparse_target(const char *path, char *out, size_t outlen)
{
    HANDLE h;
    BYTE buf[8192];
    DWORD rn = 0;
    px_reparse_data_buffer *rdb = (px_reparse_data_buffer *)buf;
    WCHAR *w;
    WORD off, len;
    int n;

    h = CreateFileA(path, 0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    NULL);
    if (h == INVALID_HANDLE_VALUE) { px_set_errno_from_win(); return 0; }
    if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, NULL, 0,
                         buf, sizeof(buf), &rn, NULL)) {
        px_set_errno_from_win(); CloseHandle(h); return 0;
    }
    CloseHandle(h);

    if (rdb->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        off = rdb->DUMMYUNIONNAME.SymbolicLinkReparseBuffer.SubstituteNameOffset;
        len = rdb->DUMMYUNIONNAME.SymbolicLinkReparseBuffer.SubstituteNameLength;
        w = (WCHAR *)((char *)rdb->DUMMYUNIONNAME.SymbolicLinkReparseBuffer.PathBuffer + off);
    } else {
        px_set_errno_from_win();
        errno = EINVAL;
        return 0;
    }
    n = WideCharToMultiByte(CP_UTF8, 0, w, len / 2, out, (int)outlen, NULL, NULL);
    if (n <= 0) return 0;
    out[n] = '\0';
    /* strip the \??\ or \DosDevices\ device prefix */
    if (n > 4 && out[0] == '\\' && out[1] == '?' && out[2] == '?' && out[3] == '\\') {
        memmove(out, out + 4, (size_t)(n - 4) + 1);
        n -= 4;
    }
    return (DWORD)n;
}

/* ------------------------------------------------------------------ */
/* getcwd for a directory fd (used by fchdir/faccessat)                */
/* Windows has no per-fd cwd; fall back to the process cwd.            */
/* ------------------------------------------------------------------ */
static char *px_fd_getcwd(int dirfd, char *buf, size_t len)
{
    (void)dirfd;
    return _getcwd(buf, (int)len);
}

/* ------------------------------------------------------------------ */
/* alarm(): one-shot SIGALRM delivery                                  */
/*                                                                     */
/* A Win32 timer-queue callback runs on an arbitrary worker thread, so */
/* it cannot call the signal handler in the *signalling* thread.       */
/* Instead we raise a user-mode exception (0xE005A1A) that            */
/* compat/signal.h's vectored handler catches in every registered     */
/* thread and turns into a SIGALRM upcall.                            */
/* ------------------------------------------------------------------ */
#define PX_EXC_ALARM 0xE005A1Au

static HANDLE px_alarm_timer = NULL;
static ULONGLONG px_alarm_deadline = 0;

static VOID CALLBACK px_alarm_cb(PVOID arg, BOOLEAN unused_param)
{
    (void)arg; (void)unused_param;
    RaiseException(PX_EXC_ALARM, EXCEPTION_NONCONTINUABLE, 0, NULL);
}

static unsigned int px_alarm(unsigned int seconds)
{
    /* report the remaining time of a previously armed alarm, if any */
    unsigned int prev = 0;
    if (px_alarm_timer) {
        HANDLE ev = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (ev) {
            /* ChangeTimerQueueTimer with due=MAXDWORD disarms; we cannot
               query the remainder portably, so approximate with elapsed
               bookkeeping kept in px_alarm_deadline. */
            ULONGLONG now = GetTickCount64();
            long long left = (long long)(px_alarm_deadline - now);
            if (left > 0) prev = (unsigned int)((left + 999) / 1000);
            DeleteTimerQueueTimer(NULL, px_alarm_timer, ev);
            WaitForSingleObject(ev, 2000);
            CloseHandle(ev);
        } else {
            DeleteTimerQueueTimer(NULL, px_alarm_timer, INVALID_HANDLE_VALUE);
        }
        px_alarm_timer = NULL;
    }
    if (seconds > 0) {
        px_alarm_deadline = GetTickCount64() + (ULONGLONG)seconds * 1000ull;
        if (!CreateTimerQueueTimer(&px_alarm_timer, NULL, px_alarm_cb, NULL,
                                   seconds * 1000, 0,
                                   WT_EXECUTEONLYONCE | WT_EXECUTEDEFAULT)) {
            px_set_errno_from_win();
            return 0;
        }
    }
    return prev;
}

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* PX_COMPAT_WINFD_H */
