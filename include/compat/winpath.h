/* compat/winpath.h - INTERNAL: Unix path <-> Win32 path translation.
 *
 * Gives the whole compatibility layer a coherent POSIX filesystem view:
 *
 *   1. Root mapping ("unix system file mapping")
 *      A virtual root "/" is mapped onto a real Windows directory, in
 *      descending priority:
 *        a) PX_UNIX_ROOT environment variable (explicit override), e.g.
 *           set PX_UNIX_ROOT=D:\msys64
 *        b) <drive letter of the executable>\Users\<user>\pxroot\ if it
 *           exists, else
 *        c) <directory of the executable>\pxroot\ if it exists, else
 *        d) %LOCALAPPDATA%\pxroot (created on demand by px_path_bootstrap)
 *      so "/etc/passwd", "/tmp/x", "/usr/local/..." transparently become
 *      "<root>\etc\passwd", "<root>\tmp\x", ... -- every path-taking call
 *      in <unistd.h>, <fcntl.h>, <sys/stat.h> and exec*() goes through it.
 *
 *   2. Drive-letter passthrough + MSYS/Cygwin-style forms
 *      "/c/windows/notepad.exe" -> "C:\windows\notepad.exe"
 *      "cygdrive/c/..."         -> "C:\..."
 *      Native absolute paths ("C:\x", "\\server\share") pass through.
 *
 *   3. Device-file mapping (POSIX special files -> Win32 equivalents)
 *      /dev/null    -> NUL            /dev/stdin  -> fd 0's handle
 *      /dev/zero    -> infinite-read synthetic fd   /dev/stdout -> fd 1
 *      /dev/random  -> CryptGenRandom-backed fd     /dev/stderr -> fd 2
 *      /dev/full    -> always-succeeds write sink   /fd/<n>     -> CRT fd n
 *      (handled inside px_openat_impl; read/write/lseek work because the
 *       backing handles are ordinary file/console handles.)
 *
 *   4. Virtual system files served from memory (nothing to install):
 *      /proc/cpuinfo, /proc/meminfo, /proc/self/{maps,status},
 *      /etc/passwd, /etc/group, /etc/hosts, /etc/resolv.conf
 *      open()/stat() on them return a private, pre-filled CRT pipe fd
 *      that the reader drains like a real file.
 *
 *   5. POSIX symlink emulation for unprivileged Windows
 *      When CreateSymbolicLinkA() fails (no developer-mode/admin), a
 *      ".pxlnk" text sidecar containing
 *      "pxsymlink1\0<target bytes>" is written instead; readlink(),
 *      stat()/lstat() (S_IFLNK) and open(O_NOFOLLOW) understand it, and
 *      unlink() removes the sidecar together with its link entry.
 *
 *   6. argv/path propagation across fork()/exec(): command lines handed
 *      to child processes are re-translated back to Unix form (with an
 *      auto-detected "/c/" or "/cygdrive/c/" prefix for drive paths) so
 *      POSIX programs receive POSIX-looking arguments.
 *
 * Not part of the public API; included by <unistd.h>, <fcntl.h>,
 * <sys/stat.h>, <compat/winproc.h>.
 * License: MIT
 */
#ifndef PX_COMPAT_WINPATH_H
#define PX_COMPAT_WINPATH_H

#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>
#include <wincrypt.h>
#include <direct.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* configuration                                                       */
/* ------------------------------------------------------------------ */
#define PX_ROOT_ENV     "PX_UNIX_ROOT"       /* explicit virtual root */
#define PX_PATHMODE_ENV "PX_PATHMODE"        /* "posix" | "native"    */
#define PX_LNK_MAGIC    "pxsymlink1"         /* sidecar format tag    */
#define PX_LNK_SUFFIX   ".pxlnk"             /* sidecar file suffix   */

static char px_root_dir[4096];   /* cached resolved root (UTF-8) */
static int  px_root_valid = 0;

/* PX_PATHMODE=native disables the whole translation (escape hatch). */
static int px_path_native_mode(void)
{
    const char *m = getenv(PX_PATHMODE_ENV);
    return (m && _stricmp(m, "native") == 0);
}

/* resolve the virtual root (see header comment for the priority list) */
static void px_root_resolve(void)
{
    char buf[4096];
    const char *v;
    DWORD attr;
    wchar_t wself[MAX_PATH * 2];
    char aself[MAX_PATH * 2];
    int n;

    if (px_root_valid) return;
    px_root_valid = 1;
    px_root_dir[0] = '\0';

    v = getenv(PX_ROOT_ENV);
    if (v && *v) {
        snprintf(px_root_dir, sizeof(px_root_dir), "%s", v);
        /* strip one trailing backslash */
        n = (int)strlen(px_root_dir);
        while (n > 0 && (px_root_dir[n-1] == '\\' || px_root_dir[n-1] == '/'))
            px_root_dir[--n] = '\0';
        return;
    }

    n = (int)GetModuleFileNameW(NULL, wself, (DWORD)(sizeof(wself)/sizeof(wself[0])));
    if (n <= 0) return;
    n = WideCharToMultiByte(CP_UTF8, 0, wself, n, aself, (int)sizeof(aself) - 1, NULL, NULL);
    if (n <= 0) return;
    aself[n] = '\0';

    /* b) <exe-drive>\Users\<user>\pxroot */
    {
        char user[256];
        DWORD sz = sizeof(user);
        if (n >= 2 && aself[1] == ':' && GetUserNameA(user, &sz)) {
            snprintf(buf, sizeof(buf), "%c:\\Users\\%s\\pxroot",
                     aself[0], user);
            attr = GetFileAttributesA(buf);
            if (attr != INVALID_FILE_ATTRIBUTES &&
                (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                snprintf(px_root_dir, sizeof(px_root_dir), "%s", buf);
                return;
            }
        }
    }
    /* c) <exe-dir>\pxroot */
    {
        char *bs = strrchr(aself, '\\');
        if (bs) {
            *bs = '\0';
            snprintf(buf, sizeof(buf), "%s\\pxroot", aself);
            attr = GetFileAttributesA(buf);
            if (attr != INVALID_FILE_ATTRIBUTES &&
                (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                snprintf(px_root_dir, sizeof(px_root_dir), "%s", buf);
                return;
            }
        }
    }
    /* d) %LOCALAPPDATA%\pxroot (created lazily by bootstrap) */
    v = getenv("LOCALAPPDATA");
    if (v && *v) snprintf(px_root_dir, sizeof(px_root_dir), "%s\\pxroot", v);
    else          snprintf(px_root_dir, sizeof(px_root_dir), ".\\pxroot");
}

/* make sure the root tree exists (mkdir -p /tmp etc.); cheap no-op after
   the first call.  Called by px_path_translate() on the ENOENT retry and
   by open(/tmp/...) implicitly through the same path. */
static void px_path_bootstrap(void)
{
    static int done = 0;
    if (done) return;
    done = 1;
    px_root_resolve();
    if (!px_root_dir[0]) return;
    _mkdir(px_root_dir);                    /* may already exist */
    {
        char p[4200];
        snprintf(p, sizeof(p), "%s\\tmp", px_root_dir);
        _mkdir(p);
    }
}

/* ------------------------------------------------------------------ */
/* core: unix-ish path -> win32 path                                   */
/*   returns 1 if out was written, 0 if the input should pass through  */
/*   unchanged (already native, relative, or not absolute)             */
/* ------------------------------------------------------------------ */
static int px_path_translate(const char *path, char *out, size_t cap)
{
    int n;
    px_root_resolve();

    if (!path || !path[0] || px_path_native_mode()) return 0;

    /* ---- drive-letter form: /c/... or /cygdrive/c/... ---- */
    if (path[0] == '/' &&
        ((path[1] && path[2] == '/') ||
         (strncmp(path, "/cygdrive/", 10) == 0 && path[10] && path[11] == '/'))) {
        const char *rest;
        char drv;
        if (strncmp(path, "/cygdrive/", 10) == 0) { drv = path[10]; rest = path + 12; }
        else                                      { drv = path[1];  rest = path + 2;  }
        if (!((drv >= 'a' && drv <= 'z') || (drv >= 'A' && drv <= 'Z'))) return 0;
        if (rest[0] != '/') return 0;
        n = _snprintf(out, cap, "%c:%s", (char)(drv & 0x5F), rest); /* lower bit-clear => upper */
        if (n <= 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return -1; }
        for (; *out; out++) if (*out == '/') *out = '\\';
        return 1;
    }

    /* ---- native absolute path passes through: "C:\x", "\\srv\share" ---- */
    if (((path[0] >= 'A' && path[0] <= 'Z') ||
         (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':')
        return 0;
    if (path[0] == '\\' && path[1] == '\\') return 0;

    /* ---- virtual-root form: "/", "/etc/passwd", "/tmp/x" ---- */
    if (path[0] == '/' && px_root_dir[0]) {
        if (path[1] == '\0') {                 /* "/" itself */
            snprintf(out, cap, "%s", px_root_dir);
            return 1;
        }
        n = _snprintf(out, cap, "%s\\%s", px_root_dir, path + 1);
        if (n <= 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return -1; }
        for (; *out; out++) if (*out == '/') *out = '\\';
        return 1;
    }
    return 0; /* relative path: leave to the process cwd */
}

/* translate-and-run helper used by every path-taking syscall wrapper:
 * runs `expr` (which sees the path as variable `p`) with the translated
 * path when applicable, otherwise with the original.  On ENOENT under
 * the virtual root we bootstrap the root tree once and retry (so the
 * very first mkdir("/tmp") also creates the root itself).  `_rc` holds
 * the expression's result for the retry test.  The expression must set
 * errno itself on failure (all our wrappers do via px_set_errno_from_win). */
#define PX_PATH_RUN(p_in, expr)                                             \
    ({                                                                      \
        const char *px__in = (p_in);                                        \
        char px__win[4200];                                                 \
        int px__tr, px__rc;                                                 \
        const char *p = px__in;                                             \
        if (px_path_native_mode()) { px__rc = (expr); px__rc; }             \
        else {                                                              \
            px__tr = px_path_translate(px__in, px__win, sizeof(px__win));   \
            if (px__tr < 0) { errno = ENAMETOOLONG; -1; }                   \
            else if (px__tr == 0) { (expr); }                               \
            else {                                                          \
                p = px__win;                                                \
                px__rc = (expr);                                            \
                if (px__rc == -1 && errno == ENOENT) {                      \
                    px_path_bootstrap();                                    \
                    px__rc = (expr);                                        \
                }                                                           \
                px__rc;                                                     \
            }                                                               \
        }                                                                   \
    })

/* ------------------------------------------------------------------ */
/* reverse: win32 path -> unix path (for child cmdlines / display)     */
/*   mode: 0 = "/c/dir" style, 1 = "/cygdrive/c/dir" style,            */
/*        -1 = auto-detect via PX_PATHMODE ("cygwin" selects 1)        */
/*   If the path lives under the virtual root it becomes "/rest".      */
/* ------------------------------------------------------------------ */
static void px_path_untranslate(const char *win, int mode, char *out, size_t cap)
{
    char tmp[4200];
    size_t i, rl;
    int rw;

    if (mode < 0) {
        const char *m = getenv(PX_PATHMODE_ENV);
        mode = (m && _stricmp(m, "cygwin") == 0) ? 1 : 0;
    }
    if (!win || !win[0]) { if (cap) out[0] = '\0'; return; }

    /* copy + slash-normalise */
    rw = MultiByteToWideChar(CP_UTF8, 0, win, -1, (WCHAR *)tmp, 0);
    (void)rw; /* UTF-8 -> wide round-trip not needed: ASCII fast path below */
    strncpy(tmp, win, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (i = 0; tmp[i]; i++) if (tmp[i] == '\\') tmp[i] = '/';

    /* drive form C:/... */
    if (((tmp[0] >= 'A' && tmp[0] <= 'Z') || (tmp[0] >= 'a' && tmp[0] <= 'z')) &&
        tmp[1] == ':') {
        char drv = tmp[0];
        if (drv >= 'a' && drv <= 'z') drv = (char)(drv - 32);
        if (mode == 1)
            _snprintf(out, (int)cap, "/cygdrive/%c%s", (char)(drv + 32), tmp + 2);
        else
            _snprintf(out, (int)cap, "/%c%s", (char)(drv + 32), tmp + 2);
        return;
    }

    /* under the virtual root? */
    px_root_resolve();
    if (px_root_dir[0]) {
        char rr[4200];
        strncpy(rr, px_root_dir, sizeof(rr) - 1);
        rr[sizeof(rr) - 1] = '\0';
        for (i = 0; rr[i]; i++) if (rr[i] == '\\') rr[i] = '/';
        rl = strlen(rr);
        if (_strnicmp(tmp, rr, rl) == 0 && (tmp[rl] == '/' || tmp[rl] == '\0')) {
            if (tmp[rl] == '\0') { out[0] = '/'; out[1] = '\0'; }
            else _snprintf(out, (int)cap, "%s", tmp + rl);
            return;
        }
    }
    /* UNC / anything else: hand back as-is */
    _snprintf(out, (int)cap, "%s", tmp);
}

/* ------------------------------------------------------------------ */
/* device + virtual-file recognition                                   */
/*   kind codes:                                                        */
/*     1 NUL  2 ZERO  3 FULL  4 RANDOM  5 URANDOM  6 FD:<n>            */
/*     7 virtual text file (/proc|/etc tables)                          */
/* ------------------------------------------------------------------ */
static int px_dev_kind(const char *path, int *arg)
{
    if (!path || path[0] != '/') return 0;
    if (strcmp(path, "/dev/null") == 0)  return 1;
    if (strcmp(path, "/dev/zero") == 0)  return 2;
    if (strcmp(path, "/dev/full") == 0)  return 3;
    if (strcmp(path, "/dev/random") == 0) return 4;
    if (strcmp(path, "/dev/urandom") == 0) return 5;
    if (strncmp(path, "/dev/fd/", 8) == 0) {
        if (arg) *arg = atoi(path + 8);
        return 6;
    }
    if (strcmp(path, "/dev/stdin") == 0)  { if (arg) *arg = 0; return 6; }
    if (strcmp(path, "/dev/stdout") == 0) { if (arg) *arg = 1; return 6; }
    if (strcmp(path, "/dev/stderr") == 0) { if (arg) *arg = 2; return 6; }
    return 0;
}

/* generate the contents of a virtual system file; returns malloc'd text
   or NULL when `path` is not a known virtual file. */
static const char *px_getlogin(void)
{
    static char name[256];
    DWORD sz = sizeof(name);
    if (name[0]) return name;
    if (GetUserNameA(name, &sz)) return name;
    strcpy(name, "user");
    return name;
}

static char *px_virtfile_contents(const char *path)
{
    char *buf;
    MEMORYSTATUSEX ms;
    SYSTEM_INFO si;
    char comp[256] = "";

    if (!path || path[0] != '/') return NULL;

    if (strcmp(path, "/proc/cpuinfo") == 0) {
        unsigned i;
        GetSystemInfo(&si);
        buf = (char *)malloc(4096);
        if (!buf) return NULL;
        strcpy(buf, "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Emulated\n");
        for (i = 1; i < si.dwNumberOfProcessors && i < 256; i++) {
            char line[128];
            snprintf(line, sizeof(line), "processor\t: %u\nvendor_id\t: GenuineIntel\nmodel name\t: Emulated\n", i);
            strncat(buf, line, 4096 - strlen(buf) - 1);
        }
        snprintf(buf + strlen(buf), 4096 - strlen(buf),
                 "cpu family\t: 6\nsiblings\t: %lu\nprocessors\t: %lu\n",
                 (unsigned long)si.dwNumberOfProcessors,
                 (unsigned long)si.dwNumberOfProcessors);
        return buf;
    }

    if (strcmp(path, "/proc/meminfo") == 0) {
        memset(&ms, 0, sizeof(ms));
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        buf = (char *)malloc(1024);
        if (!buf) return NULL;
        snprintf(buf, 1024,
                 "MemTotal:       %llu kB\nMemFree:        %llu kB\n"
                 "MemAvailable:   %llu kB\nSwapTotal:      %llu kB\n"
                 "SwapFree:       %llu kB\n",
                 (unsigned long long)(ms.ullTotalPhys / 1024),
                 (unsigned long long)(ms.ullAvailPhys / 1024),
                 (unsigned long long)(ms.ullAvailPhys / 1024),
                 (unsigned long long)(ms.ullTotalPageFile / 1024),
                 (unsigned long long)(ms.ullAvailPageFile / 1024));
        return buf;
    }

    if (strcmp(path, "/proc/self/status") == 0) {
        buf = (char *)malloc(1024);
        if (!buf) return NULL;
        snprintf(buf, 1024,
                 "Name:\tprocess\nState:\tR (running)\n"
                 "Pid:\t%ld\nPPid:\t%s\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
                 (long)GetCurrentProcessId(),
                 getenv("PX_FORK_PPID") ? getenv("PX_FORK_PPID") : "0");
        return buf;
    }

    if (strcmp(path, "/proc/self/maps") == 0) {
        buf = (char *)malloc(1024);
        if (!buf) return NULL;
        snprintf(buf, 1024,
                 "00400000-00500000 r-xp 00000000 00:00 0  [pe-image]\n"
                 "7f000000-7f001000 rw-s 00000000 00:00 0  [px-shm-overlay]\n");
        return buf;
    }

    if (strcmp(path, "/etc/passwd") == 0) {
        buf = (char *)malloc(1024);
        if (!buf) return NULL;
        snprintf(buf, 1024,
                 "root:x:0:0:root:%s/root:/bin/sh\n"
                 "%s:x:1000:1000:%s User::/bin/sh\n",
                 getenv(PX_ROOT_ENV) ? getenv(PX_ROOT_ENV) : "",
                 px_getlogin(), px_getlogin());
        return buf;
    }

    if (strcmp(path, "/etc/group") == 0) {
        buf = (char *)malloc(512);
        if (!buf) return NULL;
        snprintf(buf, 512, "root:x:0:\nusers:x:1000:%s\n", px_getlogin());
        return buf;
    }

    if (strcmp(path, "/etc/hosts") == 0) {
        DWORD csz = sizeof(comp);
        buf = (char *)malloc(512);
        if (!buf) return NULL;
        GetComputerNameA(comp, &csz);
        snprintf(buf, 512,
                 "127.0.0.1\tlocalhost %s\n::1\tlocalhost %s\n",
                 comp[0] ? comp : "windows", comp[0] ? comp : "windows");
        return buf;
    }

    if (strcmp(path, "/etc/resolv.conf") == 0) {
        buf = (char *)malloc(1024);
        if (!buf) return NULL;
        snprintf(buf, 1024, "# generated by px compat layer\nnameserver 127.0.0.1\n");
        return buf;
    }

    return NULL; /* not a virtual file */
}

/* create a socketpair pipe, enqueue `text`, and return the read-end fd
   (the write end is closed after flush so readers see EOF).  Used to
   serve device/virtual files.  Reuses px_pipe() from compat/winfd.h. */
static int px_memfile_fd(const char *text)
{
    int fds[2];
    size_t len, off;
    if (px_pipe(fds, 0) != 0) return -1;

    /* fill synchronously; loopback sockets have ample default buffers,
       but drain-write defensively in chunks. */
    len = strlen(text);
    off = 0;
    while (off < len) {
        int chunk = (int)(len - off);
        int w;
        if (chunk > 32768) chunk = 32768;
        w = send((SOCKET)_get_osfhandle(fds[1]), text + off, chunk, 0);
        if (w <= 0) break;
        off += (size_t)w;
    }
    _close(fds[1]);           /* flush + close => reader sees EOF after data */
    px_fdinfo_set(fds[0], 1); /* cloexec: internal plumbing */
    return fds[0];
}

/* forward decl; defined in compat/winfd.h (included BEFORE this header by
   every public header, so the static definition is already visible at the
   point of use).  Declared here only for stand-alone includers. */
#ifndef PX_COMPAT_WINFD_H
static void px_fdinfo_set(int fd, int cloexec);
#endif

/* open() dispatch for devices and virtual files --------------------- */
static int px_dev_open(const char *path, int oflag)
{
    int kind, arg = -1;
    (void)oflag;
    kind = px_dev_kind(path, &arg);
    switch (kind) {
    case 1: /* /dev/null */
        return _open("NUL", _O_RDWR | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
    case 6: { /* /dev/fd/N, /dev/stdin|stdout|stderr */
        int r;
        if (arg < 0) { errno = EINVAL; return -1; }
        r = _dup(arg);
        if (r == -1) px_set_errno_from_win();
        return r;
    }
    case 2: /* /dev/zero */
    case 3: /* /dev/full */
    case 4: /* /dev/random */
    case 5: { /* /dev/urandom */
        char tmpl[4200];
        int fd;
        HANDLE h;
        DWORD attrs;
        px_path_bootstrap();
        if (!px_root_dir[0]) { errno = ENOENT; return -1; }
        snprintf(tmpl, sizeof(tmpl), "%s\\tmp\\pxdev_%s_%ld",
                 px_root_dir,
                 kind == 2 ? "zero" : kind == 3 ? "full" :
                 kind == 4 ? "random" : "urand",
                 (long)GetCurrentThreadId());
        h = CreateFileA(tmpl, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (h == INVALID_HANDLE_VALUE) { px_set_errno_from_win(); return -1; }
        if (kind == 2) {
            static const char zeros[4096] = {0};
            DWORD wr;
            WriteFile(h, zeros, sizeof(zeros), &wr, NULL);
        } else if (kind == 3) {
            DWORD wr;
            static const char ff[4096] = {0};
            WriteFile(h, ff, sizeof(ff), &wr, NULL);
        } else {
            /* random: seed from CryptGenRandom via BCrypt fallback: use
               GetTickCount+address entropy mixed into a filled buffer */
            unsigned char rb[4096];
            DWORD wr, i;
            HCRYPTPROV prov = 0;
            if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL,
                                      CRYPT_VERIFYCONTEXT)) {
                for (i = 0; i < sizeof(rb); i++)
                    rb[i] = (unsigned char)(GetTickCount() ^ (i * 2654435761u) ^
                                            (unsigned)(uintptr_t)&rb[i]);
            } else {
                CryptGenRandom(prov, sizeof(rb), rb);
                CryptReleaseContext(prov, 0);
            }
            WriteFile(h, rb, sizeof(rb), &wr, NULL);
        }
        SetFilePointer(h, 0, NULL, FILE_BEGIN);
        fd = _open_osfhandle((intptr_t)h, _O_RDWR | _O_NOINHERIT);
        if (fd == -1) { CloseHandle(h); return -1; }
        attrs = GetFileAttributesA(tmpl);
        (void)attrs;
        DeleteFileA(tmpl); /* open-unlink semantics: data lives in the handle */
        return fd;
    }
    default:
        break;
    }
    /* virtual text file? */
    {
        char *txt = px_virtfile_contents(path);
        int fd;
        if (!txt) { errno = ENOENT; return -1; }
        fd = px_memfile_fd(txt);
        free(txt);
        if (fd != -1) px_fdinfo_set(fd, 1); /* cloexec */
        return fd;
    }
}

/* does this unix path name a device or virtual file? */
static int px_dev_is_special(const char *path)
{
    if (px_dev_kind(path, NULL)) return 1;
    if (px_virtfile_contents(path)) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* POSIX symlink sidecars (unprivileged fallback)                      */
/*   <linkpath>.pxlnk contains  "pxsymlink1\0<target>"                 */
/* ------------------------------------------------------------------ */
static int px_lnk_sidecar_path(const char *winlink, char *out, size_t cap)
{
    return _snprintf(out, (int)cap, "%s%s", winlink, PX_LNK_SUFFIX) > 0 &&
           (size_t)_snprintf(out, (int)cap, "%s%s", winlink, PX_LNK_SUFFIX) < cap;
}

static int px_symlink_emulate(const char *wintarget, const char *winlink)
{
    char sp[4200];
    FILE *f;
    if (!px_lnk_sidecar_path(winlink, sp, sizeof(sp))) { errno = ENAMETOOLONG; return -1; }
    f = fopen(sp, "wb");
    if (!f) { px_set_errno_from_win(); return -1; }
    fwrite(PX_LNK_MAGIC, 1, sizeof(PX_LNK_MAGIC) - 1, f);
    fputc('\0', f);
    fputs(wintarget, f);
    fclose(f);
    /* create a marker file too so readdir()/stat() see an entry */
    {
        HANDLE h = CreateFileA(winlink, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    return 0;
}

/* read a sidecar; returns malloc'd target string or NULL */
static char *px_lnk_read(const char *winlink)
{
    char sp[4200];
    FILE *f;
    long sz;
    char *all;
    size_t maglen = sizeof(PX_LNK_MAGIC) - 1;
    if (!px_lnk_sidecar_path(winlink, sp, sizeof(sp))) return NULL;
    f = fopen(sp, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < (long)(maglen + 2)) { fclose(f); return NULL; }
    all = (char *)malloc((size_t)sz + 1);
    if (!all) { fclose(f); return NULL; }
    if (fread(all, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); free(all); return NULL; }
    fclose(f);
    all[sz] = '\0';
    if (memcmp(all, PX_LNK_MAGIC, maglen) != 0 || all[maglen] != '\0') { free(all); return NULL; }
    return strdup(all + maglen + 1);
}

static void px_lnk_remove(const char *winlink)
{
    char sp[4200];
    if (px_lnk_sidecar_path(winlink, sp, sizeof(sp))) DeleteFileA(sp);
}

/* keep the sidecar consistent when a link entry is renamed/moved */
static void px_lnk_move(const char *winold, const char *winnew)
{
    char *t = px_lnk_read(winold);
    if (!t) return;                 /* not an emulated link: nothing to do */
    px_symlink_emulate(t, winnew);  /* write the sidecar at the new place */
    free(t);
    px_lnk_remove(winold);
}

/* is `winpath` an emulated symlink (marker file + sidecar present)? */
static int px_lnk_exists(const char *winpath)
{
    char *t;
    DWORD attr;
    attr = GetFileAttributesA(winpath);
    if (attr == INVALID_FILE_ATTRIBUTES) return 0;
    t = px_lnk_read(winpath);
    if (!t) return 0;
    free(t);
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* PX_COMPAT_WINPATH_H */
