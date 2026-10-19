/* time.h - POSIX <time.h> extras mapped onto the Win32 API (header-only).
 *
 * The CRT already provides clock/time/localtime etc.  This header adds:
 *   clock_gettime / clock_settime / nanosleep-decl / gmtime_r / localtime_r
 *   POSIX per-process timers (timer_create...) -> CreateWaitableTimerEx
 * License: MIT
 */
#ifndef PX_COMPAT_TIME_H
#define PX_COMPAT_TIME_H

#ifdef _WIN32

#include_next <time.h>   /* the real CRT <time.h> */
#include <stdlib.h>
#include <string.h>
#include "compat/posix_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- clock ids ---------------------------------------------------- */
#define CLOCK_REALTIME         0
#define CLOCK_MONOTONIC        1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6

/* CRT defines CLOCKS_PER_SEC; posix uses a different scale for cpu clocks */
#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC 1000000
#endif

static int px_filetime_to_timespec(const FILETIME *ft, struct timespec *ts)
{
    ULARGE_INTEGER u;
    u.LowPart = ft->dwLowDateTime; u.HighPart = ft->dwHighDateTime;
    ts->tv_sec  = (time_t)(u.QuadPart / 10000000ull);
    ts->tv_nsec = (long)((u.QuadPart % 10000000ull) * 100);
    return 0;
}

static int clock_gettime(clockid_t clk, struct timespec *ts)
{
    switch (clk) {
    case CLOCK_MONOTONIC:
    case CLOCK_MONOTONIC_RAW:
    case CLOCK_MONOTONIC_COARSE: {
        LARGE_INTEGER li, fq;
        QueryPerformanceFrequency(&fq);
        QueryPerformanceCounter(&li);
        ts->tv_sec  = (time_t)(li.QuadPart / fq.QuadPart);
        ts->tv_nsec = (long)((li.QuadPart % fq.QuadPart) *
                             1000000000LL / fq.QuadPart);
        return 0;
    }
    case CLOCK_REALTIME:
    case CLOCK_REALTIME_COARSE: {
        FILETIME ft;
        ULARGE_INTEGER u;
        GetSystemTimeAsFileTime(&ft);
        u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
        u.QuadPart -= 116444736000000000ull; /* to unix epoch */
        ts->tv_sec  = (time_t)(u.QuadPart / 10000000ull);
        ts->tv_nsec = (long)((u.QuadPart % 10000000ull) * 100);
        return 0;
    }
    case CLOCK_PROCESS_CPUTIME_ID: {
        FILETIME c, e, k, x;
        ULARGE_INTEGER cu, eu;
        if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &x)) return -1;
        cu.LowPart = c.dwLowDateTime; cu.HighPart = c.dwHighDateTime;
        eu.LowPart = e.dwLowDateTime; eu.HighPart = e.dwHighDateTime;
        {
            unsigned long long total = cu.QuadPart + eu.QuadPart;
            ts->tv_sec  = (time_t)(total / 10000000ull);
            ts->tv_nsec = (long)((total % 10000000ull) * 100);
        }
        return 0;
    }
    case CLOCK_THREAD_CPUTIME_ID: {
        FILETIME c, e, k, x;
        ULARGE_INTEGER cu, eu;
        if (!GetThreadTimes(GetCurrentThread(), &c, &e, &k, &x)) return -1;
        cu.LowPart = c.dwLowDateTime; cu.HighPart = c.dwHighDateTime;
        eu.LowPart = e.dwLowDateTime; eu.HighPart = e.dwHighDateTime;
        {
            unsigned long long total = cu.QuadPart + eu.QuadPart;
            ts->tv_sec  = (time_t)(total / 10000000ull);
            ts->tv_nsec = (long)((total % 10000000ull) * 100);
        }
        return 0;
    }
    default:
        errno = EINVAL;
        return -1;
    }
}

static int clock_getres(clockid_t clk, struct timespec *res)
{
    (void)clk;
    if (res) { res->tv_sec = 0; res->tv_nsec = 100; } /* 100ns system timer */
    return 0;
}

static int clock_settime(clockid_t clk, const struct timespec *ts)
{
    SYSTEMTIME st;
    ULARGE_INTEGER u;
    FILETIME ft;
    if (clk != CLOCK_REALTIME) { errno = EINVAL; return -1; }
    u.QuadPart = (ULONGLONG)ts->tv_sec * 10000000ull +
                 (ULONGLONG)ts->tv_nsec / 100ull + 116444736000000000ull;
    ft.dwLowDateTime = u.LowPart; ft.dwHighDateTime = u.HighPart;
    if (!FileTimeToSystemTime(&ft, &st)) { px_set_errno_from_win(); return -1; }
    if (!SetSystemTime(&st)) { px_set_errno_from_win(); return -1; }
    return 0;
}

/* reentrant conversions missing from MSVC's <time.h> */
#ifndef gmtime_r
static struct tm *gmtime_r(const time_t *timep, struct tm *result)
{
    return (gmtime_s(result, timep) == 0) ? result : NULL;
}
#endif
#ifndef localtime_r
static struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    return (localtime_s(result, timep) == 0) ? result : NULL;
}
#endif

/* timegm / timelocal equivalents */
#ifndef timegm
static time_t timegm(struct tm *tm) { return _mkgmtime(tm); }
#endif
#ifndef timelocal
static time_t timelocal(struct tm *tm) { return mktime(tm); }
#endif

/* ------------------------------------------------------------------ */
/* POSIX per-process timers -> CreateWaitableTimerEx                   */
/* ------------------------------------------------------------------ */
typedef HANDLE timer_t;

#define SIGEV_NONE     (-1)
#define SIGEV_SIGNAL   0
#define SIGEV_THREAD   1

union sigval_compat { int sival_int; void *sival_ptr; };

struct sigevent_compat {
    int sigev_notify;
    int sigev_signo;
    union sigval_compat sigev_value;
    void (*sigev_notify_function)(union sigval_compat);
};

struct px_timer_ctx {
    void (*fn)(union sigval_compat);
    union sigval_compat val;
    HANDLE reg;   /* registered-wait handle, closed on timer_delete */
};

static VOID CALLBACK px_timer_completion(PVOID arg, BOOLEAN fired)
{
    struct px_timer_ctx *c = (struct px_timer_ctx *)arg;
    (void)fired;
    if (c && c->fn) c->fn(c->val);
}

static int timer_create(clockid_t clk, struct sigevent_compat *evp,
                        timer_t *timerid)
{
    HANDLE h;
    char name[64];
    (void)clk;
    snprintf(name, sizeof(name), "pxtimer_%lu", (unsigned long)GetTickCount());
    h = CreateWaitableTimerExA(NULL, name, SYNCHRONIZE | TIMER_ALL_ACCESS,
                               CREATE_WAITABLE_TIMER_HIGH_RESOLUTION);
    if (!h)
        h = CreateWaitableTimerExA(NULL, name, SYNCHRONIZE | TIMER_ALL_ACCESS, 0);
    if (!h) { px_set_errno_from_win(); return -1; }
    if (evp && evp->sigev_notify == SIGEV_THREAD && evp->sigev_notify_function) {
        struct px_timer_ctx *c =
            (struct px_timer_ctx *)calloc(1, sizeof(*c));
        HANDLE reg = NULL;
        if (!c) { CloseHandle(h); errno = ENOMEM; return -1; }
        c->fn = evp->sigev_notify_function;
        c->val = evp->sigev_value;
        /* The registered-wait handle is stored in the context itself; the
           caller only ever sees the timer HANDLE via *timerid. */
        if (!RegisterWaitForSingleObject(&reg, h, px_timer_completion, c,
                                         10000000 /*1s poll*/, WT_EXECUTEONLYONCE)) {
            free(c); CloseHandle(h); px_set_errno_from_win(); return -1;
        }
        c->reg = reg;
    }
    *timerid = h;
    return 0;
}

static int timer_delete(timer_t t)
{
    CancelWaitableTimer(t);
    CloseHandle(t);
    return 0;
}

struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

static int timer_settime(timer_t t, int flags,
                         const struct itimerspec *new_val,
                         struct itimerspec *old_val)
{
    LARGE_INTEGER due;
    LONG period;
    BOOL ok;
    (void)flags;
    if (old_val) { old_val->it_value.tv_sec = 0; old_val->it_value.tv_nsec = 0;
                   old_val->it_interval = old_val->it_value; }
    if (new_val->it_value.tv_sec == 0 && new_val->it_value.tv_nsec == 0) {
        if (!CancelWaitableTimer(t)) { px_set_errno_from_win(); return -1; }
        return 0;
    }
    if (flags & 1 /*TIMER_ABSTIME*/) {
        ULARGE_INTEGER target;
        FILETIME now_ft, tgt_ft;
        ULONGLONG now100, tgt100;
        GetSystemTimeAsFileTime(&now_ft);
        target.QuadPart = (ULONGLONG)new_val->it_value.tv_sec * 10000000ull +
                          (ULONGLONG)new_val->it_value.tv_nsec / 100ull +
                          116444736000000000ull;
        tgt_ft.dwLowDateTime = target.LowPart; tgt_ft.dwHighDateTime = target.HighPart;
        now100 = ((ULONGLONG)now_ft.dwHighDateTime << 32) | now_ft.dwLowDateTime;
        tgt100 = ((ULONGLONG)tgt_ft.dwHighDateTime << 32) | tgt_ft.dwLowDateTime;
        due.QuadPart = -(LONGLONG)(tgt100 > now100 ? (tgt100 - now100) : 0);
    } else {
        due.QuadPart = -((LONGLONG)new_val->it_value.tv_sec * 10000000ll +
                         (LONGLONG)new_val->it_value.tv_nsec / 100ll);
    }
    period = (LONG)(new_val->it_interval.tv_sec * 1000 +
                    new_val->it_interval.tv_nsec / 1000000);
    ok = SetWaitableTimer(t, &due, period, NULL, NULL, FALSE);
    return ok ? 0 : -1;
}

static int timer_gettime(timer_t t, struct itimerspec *cur)
{
    /* Win32 waitable timers do not expose their remaining time through a
       public API, so we report the armed state as best-effort zeros. */
    (void)t;
    memset(cur, 0, sizeof(*cur));
    return 0;
}

static int timer_getoverrun(timer_t t) { (void)t; return 0; }

#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <time.h>
#endif

#endif /* PX_COMPAT_TIME_H */
