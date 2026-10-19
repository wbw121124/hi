/* posix_defs.h - shared types & errno mapping for the win32 build.
 *
 * Part of "header-only c lib: map POSIX APIs onto Win32 APIs".
 * Included by every compat header when compiling on Windows.
 * Do not include directly; include <unistd.h>, <pthread.h>, ... instead.
 *
 * License: MIT
 */
#ifndef PX_COMPAT_POSIX_DEFS_H
#define PX_COMPAT_POSIX_DEFS_H

#ifdef _WIN32 /* whole file is win32-only */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <errno.h>
#include <process.h>  /* _getpid, _beginthreadex */
#include <stdio.h>    /* snprintf, _getfullpathname */
#include <time.h>     /* time_t */
#include <stddef.h>   /* size_t, wchar_t */
#include <stdint.h>   /* intptr_t, uint*_t */
#include <sys/types.h> /* CRT: off_t, dev_t ... */

#pragma comment(lib, "ws2_32.lib")

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* basic posix scalar types                                            */
/* ------------------------------------------------------------------ */
typedef unsigned char       u_int8_t;
typedef unsigned short      u_int16_t;
typedef unsigned int        u_int32_t;
typedef unsigned long long  u_int64_t;
typedef u_int64_t           u_int;

/* ssize_t: MSVC defines it (as long) in <corecrt.h>; MinGW in <sys/types.h> */
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef long ssize_t;
#endif

typedef unsigned int        mode_t;
typedef unsigned int        uid_t;
typedef unsigned int        gid_t;
typedef long long           off64_t;
typedef long                clockid_t;
typedef int                 key_t;
typedef unsigned long long  ino_t;
typedef long                suseconds_t;
typedef unsigned int        useconds_t;
typedef long                dev_t;
typedef unsigned int        nlink_t;
typedef long                blksize_t;
typedef long long           blkcnt_t;
typedef unsigned short      in_port_t;
typedef unsigned int        in_addr_t;
typedef int                 px_timer_id_t;

#ifndef NULL
#define NULL 0
#endif

/* pthread handle: maps to a Win32 HANDLE (thread handle from DuplicateHandle) */
typedef uintptr_t pthread_key_t;

#ifndef _PX_TIMESPEC_DEFINED
#define _PX_TIMESPEC_DEFINED
struct timespec { time_t tv_sec; long tv_nsec; };
#endif

#ifndef _PX_TIMEVAL_DEFINED
#define _PX_TIMEVAL_DEFINED
struct timeval  { time_t tv_sec; suseconds_t tv_usec; };
#endif

#ifndef _PX_UTIMBUF_DEFINED
#define _PX_UTIMBUF_DEFINED
struct utimbuf { time_t actime; time_t modtime; };
#endif

/* ------------------------------------------------------------------ */
/* errno values missing from the MSVC CRT                              */
/* ------------------------------------------------------------------ */
#ifndef EAGAIN
#define EAGAIN          11
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK     EAGAIN
#endif
#ifndef EACCES
#define EACCES          13
#endif
#ifndef EBUSY
#define EBUSY           16
#endif
#ifndef ECHILD
#define ECHILD          10
#endif
#ifndef ELOOP
#define ELOOP           40
#endif
#ifndef ENAMETOOLONG
#define ENAMETOOLONG    36
#endif
#ifndef ENOTDIR
#define ENOTDIR         20
#endif
#ifndef ENOSPC
#define ENOSPC          28
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT       110
#endif
#ifndef EDEADLK
#define EDEADLK         35
#endif
#ifndef ENOTEMPTY
#define ENOTEMPTY       39
#endif
#ifndef EXDEV
#define EXDEV           18
#endif
#ifndef ECONNABORTED
#define ECONNABORTED    103
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED    111
#endif
#ifndef ECONNRESET
#define ECONNRESET      104
#endif
#ifndef EADDRINUSE
#define EADDRINUSE      98
#endif
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL   99
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT    97
#endif
#ifndef EISCONN
#define EISCONN         106
#endif
#ifndef ENOTCONN
#define ENOTCONN        107
#endif
#ifndef ENOTSOCK
#define ENOTSOCK        88
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH    113
#endif
#ifndef ENETUNREACH
#define ENETUNREACH     101
#endif
#ifndef EMSGSIZE
#define EMSGSIZE        90
#endif
#ifndef EPROTO
#define EPROTO          71
#endif
#ifndef EINPROGRESS
#define EINPROGRESS     115
#endif
#ifndef EALREADY
#define EALREADY        114
#endif
#ifndef EDESTADDRREQ
#define EDESTADDRREQ    89
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP      95
#endif
#ifndef ENOTSUP
#define ENOTSUP         EOPNOTSUPP
#endif
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT    96
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 93
#endif
#ifndef EPROTOTYPE
#define EPROTOTYPE      91
#endif
#ifndef ENOPROTOOPT
#define ENOPROTOOPT     92
#endif
#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT 94
#endif
#ifndef ENETDOWN
#define ENETDOWN        100
#endif
#ifndef ENETRESET
#define ENETRESET       102
#endif
#ifndef ENOBUFS
#define ENOBUFS         105
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN       108
#endif
#ifndef EHOSTDOWN
#define EHOSTDOWN       112
#endif
#ifndef ECANCELED
#define ECANCELED       125
#endif
#ifndef EOVERFLOW
#define EOVERFLOW       75
#endif
#ifndef ENOMSG
#define ENOMSG          42
#endif
#ifndef ENOSYS
#define ENOSYS          38
#endif
#ifndef EROFS
#define EROFS           30
#endif
#ifndef ESPIPE
#define ESPIPE          29
#endif
#ifndef ETXTBSY
#define ETXTBSY         26
#endif
#ifndef EILSEQ
#define EILSEQ          84
#endif

/* ------------------------------------------------------------------ */
/* error-code translation helpers                                      */
/* ------------------------------------------------------------------ */
/* translate a Win32 error code into a POSIX errno value */
static int px_win32_to_errno(DWORD we)
{
    switch (we) {
    case ERROR_SUCCESS:              return 0;
    case ERROR_INVALID_FUNCTION:
    case ERROR_BAD_COMMAND:
    case ERROR_DEVICE_REQUIRED:      return EIO;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:       return ENOENT;
    case ERROR_TOO_MANY_OPEN_FILES:  return EMFILE;
    case ERROR_ACCESS_DENIED:
    case ERROR_PRIVILEGE_NOT_HELD:   return EACCES;
    case ERROR_INVALID_HANDLE:       return EBADF;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:          return ENOMEM;
    case ERROR_INVALID_PARAMETER:    return EINVAL;
    case ERROR_SHARING_VIOLATION:
    case ERROR_PIPE_BUSY:
    case ERROR_BUSY:                 return EBUSY;
    case ERROR_DIR_NOT_EMPTY:        return ENOTEMPTY;
    case ERROR_ALREADY_EXISTS:
    case ERROR_FILE_EXISTS:          return EEXIST;
    case ERROR_BAD_PATHNAME:
    case ERROR_INVALID_NAME:
    case ERROR_NO_MORE_FILES:        return ENOENT;
    case ERROR_FILENAME_EXCED_RANGE: return ENAMETOOLONG;
    case ERROR_DISK_FULL:            return ENOSPC;
    case ERROR_TIMEOUT:              return ETIMEDOUT;
    case ERROR_CALL_NOT_IMPLEMENTED: return ENOSYS;
    case ERROR_READ_FAULT:
    case ERROR_WRITE_FAULT:          return EIO;
    case ERROR_SEEK:                 return ESPIPE;
    case ERROR_NOT_READY:            return EIO;
    default:                         return (int)we; /* keep raw code */
    }
}

/* translate a winsock error into a BSD-socket errno value */
static int px_wsae_to_errno(int we)
{
    switch (we) {
    case WSAEINTR:           return EINTR;
    case WSAEBADF:           return EBADF;
    case WSAEACCES:          return EACCES;
    case WSAEFAULT:          return EFAULT;
    case WSAEINVAL:          return EINVAL;
    case WSAEMFILE:          return EMFILE;
    case WSAEWOULDBLOCK:     return EWOULDBLOCK;
    case WSAEINPROGRESS:     return EINPROGRESS;
    case WSAEALREADY:        return EALREADY;
    case WSAENOTSOCK:        return ENOTSOCK;
    case WSAEDESTADDRREQ:    return EDESTADDRREQ;
    case WSAEMSGSIZE:        return EMSGSIZE;
    case WSAEPROTOTYPE:      return EPROTOTYPE;
    case WSAENOPROTOOPT:     return ENOPROTOOPT;
    case WSAEPROTONOSUPPORT: return EPROTONOSUPPORT;
    case WSAESOCKTNOSUPPORT: return ESOCKTNOSUPPORT;
    case WSAEOPNOTSUPP:      return EOPNOTSUPP;
    case WSAEPFNOSUPPORT:    return EPFNOSUPPORT;
    case WSAEAFNOSUPPORT:    return EAFNOSUPPORT;
    case WSAEADDRINUSE:      return EADDRINUSE;
    case WSAEADDRNOTAVAIL:   return EADDRNOTAVAIL;
    case WSAENETDOWN:        return ENETDOWN;
    case WSAENETUNREACH:     return ENETUNREACH;
    case WSAENETRESET:       return ENETRESET;
    case WSAECONNABORTED:    return ECONNABORTED;
    case WSAECONNRESET:      return ECONNRESET;
    case WSAENOBUFS:         return ENOBUFS;
    case WSAEISCONN:         return EISCONN;
    case WSAENOTCONN:        return ENOTCONN;
    case WSAESHUTDOWN:       return ESHUTDOWN;
    case WSAETIMEDOUT:       return ETIMEDOUT;
    case WSAECONNREFUSED:    return ECONNREFUSED;
    case WSAEHOSTDOWN:       return EHOSTDOWN;
    case WSAEHOSTUNREACH:    return EHOSTUNREACH;
    default:                 return we;
    }
}

/* set errno from the last Win32/Winsock error (auto-detects socket errors) */
static void px_set_errno_from_win(void)
{
    DWORD le = GetLastError();
    if (le >= WSABASEERR && le <= WSABASEERR + 10000)
        errno = px_wsae_to_errno((int)le);
    else
        errno = px_win32_to_errno(le);
}

/* resolve a possibly-relative path to an absolute one (buffer supplied) */
static char *px_abspath(const char *path, char *buf, size_t buflen)
{
    char full[4096];
    if (!path) return NULL;
    if (path[0] && (path[1] == ':' || path[0] == '\\' || path[0] == '/'))
        snprintf(buf, buflen, "%s", path);
    else if (_getfullpathname(path, full, (int)sizeof(full)) > 0)
        snprintf(buf, buflen, "%s", full);
    else
        snprintf(buf, buflen, "%s", path);
    return buf;
}

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* PX_COMPAT_POSIX_DEFS_H */
