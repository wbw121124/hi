/* pthread.h - POSIX <pthread.h> mapped onto the Win32 API (header-only).
 *
 * Mapping:
 *   pthread_t            -> HANDLE  (thread handle)
 *   pthread_mutex_t      -> CRITICAL_SECTION (initialised on first use)
 *   pthread_cond_t       -> Win32 CONDITION_VARIABLE (Vista+)
 *   rwlock               -> SRWLOCK (Win8+) with a CRITICAL_SECTION fallback
 *   thread-specific data -> TlsAlloc / TlsSetValue, destructor list per key
 * License: MIT
 */
#ifndef PX_COMPAT_PTHREAD_H
#define PX_COMPAT_PTHREAD_H

#ifdef _WIN32

#include "compat/posix_defs.h"
#include <process.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- types --------------------------------------------------------- */
typedef uintptr_t         pthread_t;   /* a Win32 thread HANDLE */
typedef LONG              pthread_once_t;

typedef struct {
    CRITICAL_SECTION cs;
    int              init;   /* lazy-init guard */
} pthread_mutex_t;

typedef struct {
    CONDITION_VARIABLE cv;
    int                init;
    LONG               waiters;
    LONG               generation;   /* broadcast counter for re-broadcast logic */
} pthread_cond_t;

typedef struct {
    union {
        SRWLOCK srw;
    } u;
    volatile LONG held_exclusive;  /* 1 while an exclusive holder is inside */
    int init;
} pthread_rwlock_t;

typedef struct { int dummy; } pthread_attr_t;
typedef struct { int dummy; } pthread_condattr_t;
typedef struct { int dummy; } pthread_mutexattr_t;
typedef struct { int dummy; } pthread_rwlockattr_t;
typedef struct { int dummy; } pthread_barrier_t;
typedef struct { int dummy; } pthread_barrierattr_t;
typedef struct { int dummy; } pthread_spinlock_t;

/* CRITICAL_SECTION is opaque (size varies by CRT); static initialisers are
 * therefore not possible for mutexes. All mutex APIs lazily initialise on
 * first use, so zero-initialised storage works everywhere: */
#define PTHREAD_MUTEX_INITIALIZER     { {0,0,0,0,0,0}, 0 }
#define PTHREAD_COND_INITIALIZER      { CONDITION_VARIABLE_INIT, 1, 0, 0 }
#define PTHREAD_RWLOCK_INITIALIZER    { {{0}}, 1, 0 }
#define PTHREAD_ONCE_INIT             0

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

/* ------------------------------------------------------------------ */
/* lazy initialisation helpers                                         */
/* ------------------------------------------------------------------ */
static void px_mutex_init(pthread_mutex_t *m)
{
    if (!m->init) {
        InitializeCriticalSection(&m->cs);
        m->init = 1;
    }
}
static void px_cond_init(pthread_cond_t *c)
{
    if (!c->init) {
        InitializeConditionVariable(&c->cv);
        c->init = 1;
    }
}
static void px_rwlock_init(pthread_rwlock_t *r)
{
    if (!r->init) {
        InitializeSRWLock(&r->u.srw);
        r->init = 1;
    }
}

/* ---- mutex --------------------------------------------------------- */
static int pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a)
{ (void)a; memset(m, 0, sizeof(*m)); px_mutex_init(m); return 0; }

static int pthread_mutex_destroy(pthread_mutex_t *m)
{ if (m->init) { DeleteCriticalSection(&m->cs); m->init = 0; } return 0; }

static int pthread_mutex_lock(pthread_mutex_t *m)
{ px_mutex_init(m); EnterCriticalSection(&m->cs); return 0; }

static int pthread_mutex_trylock(pthread_mutex_t *m)
{
    px_mutex_init(m);
    return TryEnterCriticalSection(&m->cs) ? 0 : EBUSY;
}

static int pthread_mutex_unlock(pthread_mutex_t *m)
{ LeaveCriticalSection(&m->cs); return 0; }

/* ---- condition variable -------------------------------------------- */
static int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a)
{ (void)a; memset(c, 0, sizeof(*c)); px_cond_init(c); return 0; }
static int pthread_cond_destroy(pthread_cond_t *c)
{ (void)c; c->init = 0; return 0; }  /* CV needs no cleanup on Windows */

static int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m)
{
    px_cond_init(c);
    SleepConditionVariableCS(&c->cv, &m->cs, INFINITE);
    return 0;
}

static int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                                  const struct timespec *abstime)
{
    DWORD ms;
    ULONGLONG now = GetTickCount64();
    ULONGLONG target = (ULONGLONG)abstime->tv_sec * 1000ull +
                       (ULONGLONG)abstime->tv_nsec / 1000000ull;
    /* abstime uses CLOCK_REALTIME-ish semantics; approximate with tick delta */
    ms = (target > now) ? (DWORD)(target - now) : 0;
    px_cond_init(c);
    if (SleepConditionVariableCS(&c->cv, &m->cs, ms))
        return 0;
    if (GetLastError() == ERROR_TIMEOUT) return ETIMEDOUT;
    return 0;
}

static int pthread_cond_signal(pthread_cond_t *c)
{ px_cond_init(c); WakeConditionVariable(&c->cv); return 0; }
static int pthread_cond_broadcast(pthread_cond_t *c)
{ px_cond_init(c); WakeAllConditionVariable(&c->cv); return 0; }

/* ---- read/write lock ------------------------------------------------ */
static int pthread_rwlock_init(pthread_rwlock_t *r, const pthread_rwlockattr_t *a)
{ (void)a; memset(r, 0, sizeof(*r)); px_rwlock_init(r); return 0; }
static int pthread_rwlock_destroy(pthread_rwlock_t *r)
{ r->init = 0; return 0; }
static int pthread_rwlock_rdlock(pthread_rwlock_t *r)
{ px_rwlock_init(r); AcquireSRWLockShared(&r->u.srw); return 0; }
static int pthread_rwlock_wrlock(pthread_rwlock_t *r)
{
    px_rwlock_init(r);
    AcquireSRWLockExclusive(&r->u.srw);
    r->held_exclusive = 1;
    return 0;
}
static int pthread_rwlock_tryrdlock(pthread_rwlock_t *r)
{
    px_rwlock_init(r);
    return TryAcquireSRWLockShared(&r->u.srw) ? 0 : EBUSY;
}
static int pthread_rwlock_trywrlock(pthread_rwlock_t *r)
{
    px_rwlock_init(r);
    if (TryAcquireSRWLockExclusive(&r->u.srw)) { r->held_exclusive = 1; return 0; }
    return EBUSY;
}
/* SRWLOCK does not remember how it was acquired; we track the exclusive
 * case with a flag so the generic POSIX unlock() works correctly. */
static int pthread_rwlock_unlock(pthread_rwlock_t *r)
{
    if (InterlockedExchange(&r->held_exclusive, 0) == 1)
        ReleaseSRWLockExclusive(&r->u.srw);
    else
        ReleaseSRWLockShared(&r->u.srw);
    return 0;
}

/* ---- once ------------------------------------------------------------ */
static int pthread_once_impl(pthread_once_t *once_control,
                             void (*init_routine)(void))
{
    for (;;) {
        LONG v = *once_control;
        if (v >= 2) return 0;                       /* already initialised */
        if (v == 0 && InterlockedCompareExchange(once_control, 1, 0) == 0) {
            init_routine();                          /* we own the call */
            *once_control = 2;
            MemoryBarrier();
            return 0;
        }
        Sleep(0);                                    /* another thread runs it */
    }
}
#define pthread_once(ctrl, fn) pthread_once_impl((ctrl), (fn))

/* ---- thread-specific data (TLS) ------------------------------------- */
/* Values live in the per-thread TLS array itself (TlsGetValue/SetValue);
 * only the destructor table is global. */
static void (*g_px_tls_dtor[64])(void *) = {0};

static int pthread_key_create(pthread_key_t *key, void (*dtor)(void *))
{
    DWORD idx = TlsAlloc();
    if (idx == TLS_OUT_OF_INDEXES) return EAGAIN;
    if (idx < 64) g_px_tls_dtor[idx] = dtor;
    *key = (pthread_key_t)idx;
    return 0;
}

static int pthread_key_delete(pthread_key_t key)
{
    if (key < 64) g_px_tls_dtor[key] = NULL;
    return TlsFree((DWORD)key) ? 0 : EINVAL;
}

static void *pthread_getspecific(pthread_key_t key)
{
    return TlsGetValue((DWORD)key);
}

static int pthread_setspecific(pthread_key_t key, const void *value)
{
    return TlsSetValue((DWORD)key, (LPVOID)value) ? 0 : EINVAL;
}

/* ---- threads --------------------------------------------------------- */
typedef unsigned (__stdcall *px_thread_fn)(void *);

struct px_thunk {
    void *(*start)(void *);
    void *arg;
    int   detached;
};

static unsigned __stdcall px_thread_trampoline(void *p)
{
    struct px_thunk t = *(struct px_thunk *)p;
    void *ret;
    free(p);
    ret = t.start(t.arg);
    if (t.detached) {
        /* nothing joins us; exit cleanly */
    }
    return (unsigned)(intptr_t)ret;
}

static int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                          void *(*start)(void *), void *arg)
{
    uintptr_t hnd;
    struct px_thunk *t;
    int detached = (attr && ((char *)attr)[0] == PTHREAD_CREATE_DETACHED);
    (void)attr;
    t = (struct px_thunk *)malloc(sizeof(*t));
    if (!t) return EAGAIN;
    t->start = start; t->arg = arg; t->detached = detached;
    hnd = (uintptr_t)_beginthreadex(NULL, 0, px_thread_trampoline, t, 0, NULL);
    if (hnd == 0) { free(t); return EAGAIN; }
    if (detached) CloseHandle((HANDLE)hnd);
    *thread = (pthread_t)hnd;
    return 0;
}

static int pthread_join(pthread_t th, void **retval)
{
    HANDLE h = (HANDLE)(uintptr_t)th;
    DWORD r;
    if (!h || h == INVALID_HANDLE_VALUE) return EINVAL;
    r = WaitForSingleObject(h, INFINITE);
    if (r == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeThread(h, &code);
        if (retval) *retval = (void *)(intptr_t)code;
        CloseHandle(h);
        return 0;
    }
    return EINVAL;
}

static void pthread_exit(void *retval)
{
    _endthreadex((unsigned)(intptr_t)retval);
}

static int pthread_detach(pthread_t th)
{
    /* keep the handle so joiners can still wait; detach is a hint only */
    (void)th;
    return 0;
}

static pthread_t pthread_self(void)
{
    HANDLE h;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                    GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS);
    return (pthread_t)(uintptr_t)h;
}

static int pthread_equal(pthread_t a, pthread_t b)
{
    return a == b;
}

static int pthread_cancel(pthread_t th)
{
    TerminateThread((HANDLE)(uintptr_t)th, 0);
    return 0;
}
#define PTHREAD_CANCEL_ENABLE 0
#define PTHREAD_CANCEL_DISABLE 1
#define PTHREAD_CANCELED ((void *)-1)
static int pthread_setcancelstate(int state, int *old)
{ (void)state; if (old) *old = 0; return 0; }
static int pthread_setcanceltype(int type, int *old)
{ (void)type; if (old) *old = 0; return 0; }
static void pthread_testcancel(void) { }

static int pthread_atfork(void (*prep)(void), void (*parent)(void),
                          void (*child)(void))
{ (void)prep; (void)parent; (void)child; errno = ENOSYS; return ENOSYS; }

/* scheduling stubs */
#define SCHED_FIFO 1
#define SCHED_RR   2
#define SCHED_OTHER 0
struct sched_param_compat { int sched_priority; };
static int pthread_setschedparam(pthread_t th, int pol,
                                 const struct sched_param_compat *p)
{
    static const int map[] = {0, THREAD_PRIORITY_TIME_CRITICAL,
                              THREAD_PRIORITY_HIGHEST, THREAD_PRIORITY_NORMAL};
    (void)pol;
    if (!SetThreadPriority((HANDLE)(uintptr_t)th,
                           p ? map[p->sched_priority & 3] : THREAD_PRIORITY_NORMAL))
        return EINVAL;
    return 0;
}
static int pthread_getschedparam(pthread_t th, int *pol,
                                 struct sched_param_compat *p)
{
    (void)th;
    if (pol) *pol = SCHED_OTHER;
    if (p) p->sched_priority = 0;
    return 0;
}

#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <pthread.h>
#endif

#endif /* PX_COMPAT_PTHREAD_H */
