/* sys/stat.h - POSIX <sys/stat.h> mapped onto the Win32 API (header-only).
 * License: MIT
 */
#ifndef PX_COMPAT_SYS_STAT_H
#define PX_COMPAT_SYS_STAT_H

#ifdef _WIN32

/* Pull in the CRT's own <sys/stat.h> (struct _stat/_stati64, _S_IF* bits)
 * by skipping this compat header via include_next (supported by both MSVC
 * and MinGW when this directory is on the include path). */
#include_next <sys/stat.h>
#include <string.h>
#include "compat/posix_defs.h"
#include "compat/winfd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- S_* mode bits --------------------------------------------------
 * The CRT only defines owner bits (_S_IREAD/_S_IWRITE) and the _S_IF*
 * file-type masks; provide the full POSIX bit layout for st_mode. */
#ifndef S_IFIFO
#define S_IFIFO  0010000
#endif
#ifndef S_IFLNK
#define S_IFLNK  0120000
#endif
#ifndef S_IFSOCK
#define S_IFSOCK 0140000
#endif
#ifndef S_IFBLK
#define S_IFBLK  0060000
#endif
#ifndef S_ISUID
#define S_ISUID 0004000
#endif
#ifndef S_ISGID
#define S_ISGID 0002000
#endif
#ifndef S_ISVTX
#define S_ISVTX 0001000
#endif
#ifndef S_IRWXU
#define S_IRWXU 0000700
#endif
#ifndef S_IRUSR
#define S_IRUSR 0000400
#endif
#ifndef S_IWUSR
#define S_IWUSR 0000200
#endif
#ifndef S_IXUSR
#define S_IXUSR 0000100
#endif
#ifndef S_IRWXG
#define S_IRWXG 0000070
#endif
#ifndef S_IRGRP
#define S_IRGRP 0000040
#endif
#ifndef S_IWGRP
#define S_IWGRP 0000020
#endif
#ifndef S_IXGRP
#define S_IXGRP 0000010
#endif
#ifndef S_IRWXO
#define S_IRWXO 0000007
#endif
#ifndef S_IROTH
#define S_IROTH 0000004
#endif
#ifndef S_IWOTH
#define S_IWOTH 0000002
#endif
#ifndef S_IXOTH
#define S_IXOTH 0000001
#endif

/* file type test macros (work on any st_mode value) */
#ifndef S_ISDIR
#define S_ISDIR(m)  (((m) & _S_IFMT) == _S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m)  (((m) & _S_IFMT) == _S_IFREG)
#endif
#ifndef S_ISCHR
#define S_ISCHR(m)  (((m) & _S_IFMT) == _S_IFCHR)
#endif
#define S_ISFIFO(m) (((m) & _S_IFMT) == S_IFIFO)
#define S_ISLNK(m)  (((m) & _S_IFMT) == S_IFLNK)
#define S_ISSOCK(m) (((m) & _S_IFMT) == S_IFSOCK)
#define S_ISBLK(m)  (((m) & _S_IFMT) == S_IFBLK)

/* ---- struct stat ----------------------------------------------------
 * Our own layout so we can synthesise nlink/uid/gid and 64-bit size.
 * `#undef stat` first: MSVC's <sys/stat.h> maps stat -> _stat via macro. */
#undef stat
struct stat {
    dev_t     st_dev;
    ino_t     st_ino;
    mode_t    st_mode;
    nlink_t   st_nlink;
    uid_t     st_uid;
    gid_t     st_gid;
    dev_t     st_rdev;
    off_t     st_size;
    blksize_t st_blksize;
    blkcnt_t  st_blocks;
    time_t    st_atime;
    time_t    st_mtime;
    time_t    st_ctime;
};

static mode_t px_mode_from_attrs(DWORD attr, int is_link)
{
    mode_t base;
    if (is_link)                                       base = S_IFLNK;
    else if (attr & FILE_ATTRIBUTE_DIRECTORY)          base = _S_IFDIR;
    else if (attr & (FILE_ATTRIBUTE_DEVICE))           base = _S_IFCHR;
    else                                               base = _S_IFREG;
    /* Windows only distinguishes read-only; expand to all-user bits */
    if (attr & FILE_ATTRIBUTE_READONLY)
        return (mode_t)(base | S_IRUSR | S_IRGRP | S_IROTH);
    return (mode_t)(base | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
}

static void px_ft_to_time(const FILETIME *ft, time_t *out_sec)
{
    ULARGE_INTEGER u;
    u.LowPart = ft->dwLowDateTime; u.HighPart = ft->dwHighDateTime;
    if (u.QuadPart == 0) { *out_sec = 0; return; }
    u.QuadPart -= 116444736000000000ull;   /* 100ns ticks 1601 -> unix epoch */
    *out_sec = (time_t)(u.QuadPart / 10000000ull);
}

static int px_stat_fill(const char *path, struct stat *st, int follow)
{
    HANDLE h;
    BY_HANDLE_FILE_INFORMATION bi;
    DWORD attr;
    int is_link = 0;
    char target[4096];

    memset(st, 0, sizeof(*st));
    attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) { px_set_errno_from_win(); return -1; }

    if ((attr & FILE_ATTRIBUTE_REPARSE_POINT) && !follow) {
        if (px_reparse_target(path, target, sizeof(target)) > 0)
            is_link = 1;
    }

    h = CreateFileA(path, 0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS |
                    (follow ? 0 : FILE_FLAG_OPEN_REPARSE_POINT),
                    NULL);
    if (h != INVALID_HANDLE_VALUE) {
        if (GetFileInformationByHandle(h, &bi)) {
            st->st_dev     = (dev_t)bi.dwVolumeSerialNumber;
            st->st_ino     = ((ino_t)bi.nFileIndexHigh << 32) | bi.nFileIndexLow;
            st->st_nlink   = (nlink_t)bi.nNumberOfLinks;
            st->st_size    = ((off_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
            st->st_atime   = 0;
            st->st_blksize = 4096;
            st->st_blocks  = (blkcnt_t)((st->st_size + 511) / 512);
            px_ft_to_time(&bi.ftLastAccessTime, &st->st_atime);
            px_ft_to_time(&bi.ftLastWriteTime,  &st->st_mtime);
            px_ft_to_time(&bi.ftCreationTime,   &st->st_ctime);
            CloseHandle(h);
            st->st_mode = px_mode_from_attrs(bi.dwFileAttributes ?
                                             bi.dwFileAttributes : attr,
                                             is_link);
            return 0;
        }
        CloseHandle(h);
    }
    /* handle path failed (e.g. locked): fall back to attributes only */
    st->st_mode    = px_mode_from_attrs(attr, is_link);
    st->st_nlink   = 1;
    st->st_blksize = 4096;
    return 0;
}

static int stat(const char *path, struct stat *st)
{ return px_stat_fill(path, st, 1); }

static int lstat(const char *path, struct stat *st)
{ return px_stat_fill(path, st, 0); }

static int fstat(int fd, struct stat *st)
{
    char path[4096];
    HANDLE h = px_fd_handle(fd);
    BY_HANDLE_FILE_INFORMATION bi;
    if (h == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    if (!GetFileInformationByHandle(h, &bi)) {
        /* pipes/sockets have no file info: report a FIFO-like stat */
        memset(st, 0, sizeof(*st));
        st->st_mode    = S_IFIFO | S_IRWXU;
        st->st_blksize = 4096;
        st->st_nlink   = 1;
        return 0;
    }
    if (GetFinalPathNameByHandleA(h, path, sizeof(path),
                                  FILE_NAME_OPENED) > 0)
        return px_stat_fill(path, st, 1);
    memset(st, 0, sizeof(*st));
    st->st_mode    = px_mode_from_attrs(bi.dwFileAttributes, 0);
    st->st_size    = ((off_t)bi.nFileSizeHigh << 32) | bi.nFileSizeLow;
    st->st_nlink   = (nlink_t)bi.nNumberOfLinks;
    st->st_blksize = 4096;
    px_ft_to_time(&bi.ftLastWriteTime, &st->st_mtime);
    px_ft_to_time(&bi.ftCreationTime,  &st->st_ctime);
    px_ft_to_time(&bi.ftLastAccessTime,&st->st_atime);
    return 0;
}

static int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
    char full[4096], base[4096];
    if (flags & AT_SYMLINK_NOFOLLOW) return lstat(path, st);
    if (dirfd != AT_FDCWD && path && path[0] != '/' && path[1] != ':') {
        if (px_fd_getcwd(dirfd, base, sizeof(base)) == NULL) return -1;
        snprintf(full, sizeof(full), "%s\\%s", base, path);
        path = full;
    }
    return stat(path, st);
}

#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <sys/stat.h>
#endif

#endif /* PX_COMPAT_SYS_STAT_H */
