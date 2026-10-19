/* semaphore.h - POSIX <semaphore.h> mapped onto the Win32 API (header-only).
 *
 * unnamed semaphores -> HANDLE (CreateSemaphore) wrapped in a struct
 * named semaphores   -> Global\\ kernel semaphore objects
 * License: MIT
 */
#ifndef PX_COMPAT_SEMAPHORE_H
#define PX_COMPAT_SEMAPHORE_H

#ifdef _WIN32

#include <stdarg.h>
#include <stdlib.h>
#include "compat/posix_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct px_sem {
    HANDLE h;          /* CreateSemaphoreA handle */
    char   name[256];  /* for named semaphores / sem_unlink */
} sem_t;

static int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    (void)pshared;
    if (value > 0x7FFFFFFF) value = 0x7FFFFFFF;
    sem->h = CreateSemaphoreA(NULL, (LONG)value, (LONG)value ? (LONG)value : 1, NULL);
    sem->name[0] = '\0';
    return sem->h ? 0 : -1;
}

static sem_t *sem_open(const char *name, int oflag, ...)
{
    unsigned int value = 0;
    va_list ap;
    HANDLE h;
    sem_t *s;
    char winname[300];

    if (oflag & O_CREAT) {
        va_start(ap, oflag);
        value = (unsigned int)va_arg(ap, int);
        va_end(ap);
    }
    snprintf(winname, sizeof(winname), "Global\\pxsem_%s", name);
    s = (sem_t *)calloc(1, sizeof(*s));
    if (!s) { errno = ENOMEM; return NULL; }
    if (oflag & O_CREAT) {
        h = CreateSemaphoreA(NULL, (LONG)value,
                             (LONG)(value ? value : 0x7FFFFFFF), winname);
        if (!h) { free(s); px_set_errno_from_win(); return NULL; }
        if ((oflag & O_EXCL) && GetLastError() == ERROR_ALREADY_EXISTS) {
            CloseHandle(h); free(s); errno = EEXIST; return NULL;
        }
    } else {
        h = OpenSemaphoreA(SEMAPHORE_ALL_ACCESS, FALSE, winname);
        if (!h) { free(s); px_set_errno_from_win(); return NULL; }
    }
    s->h = h;
    snprintf(s->name, sizeof(s->name), "%s", name);
    return s;
}

static int sem_close(sem_t *sem)
{
    if (sem->h) CloseHandle(sem->h);
    return 0;
}

static int sem_unlink(const char *name)
{
    /* kernel objects vanish when the last handle closes; nothing to do */
    (void)name;
    return 0;
}

static int sem_destroy(sem_t *sem)
{
    if (sem->h) { CloseHandle(sem->h); sem->h = NULL; }
    return 0;
}

static int sem_post(sem_t *sem)
{
    return ReleaseSemaphore(sem->h, 1, NULL) ? 0 : -1;
}

static int sem_wait(sem_t *sem)
{
    DWORD r = WaitForSingleObject(sem->h, INFINITE);
    if (r == WAIT_OBJECT_0) return 0;
    errno = EINTR;   /* abandonment etc. reported as interrupt */
    return -1;
}

static int sem_trywait(sem_t *sem)
{
    DWORD r = WaitForSingleObject(sem->h, 0);
    if (r == WAIT_OBJECT_0) return 0;
    if (r == WAIT_TIMEOUT) { errno = EAGAIN; return -1; }
    return -1;
}

static int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout)
{
    ULONGLONG now = GetTickCount64();
    ULONGLONG target = (ULONGLONG)abs_timeout->tv_sec * 1000ull +
                       (ULONGLONG)abs_timeout->tv_nsec / 1000000ull;
    DWORD ms = (target > now) ? (DWORD)(target - now) : 0;
    DWORD r = WaitForSingleObject(sem->h, ms);
    if (r == WAIT_OBJECT_0) return 0;
    errno = ETIMEDOUT;
    return -1;
}

static int sem_getvalue(sem_t *sem, int *valp)
{
    /* No direct count API on Win32: drain with non-blocking waits, then
       restore exactly what we took. The value is a snapshot; concurrent
       posters between drain and restore are reported as the old count. */
    int n = 0;
    LONG prev = 0;
    while (WaitForSingleObject(sem->h, 0) == WAIT_OBJECT_0) n++;
    if (n > 0) ReleaseSemaphore(sem->h, (LONG)n, &prev);
    *valp = n;   /* pre-drain count == number we successfully acquired */
    return 0;
}

#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <semaphore.h>
#endif

#endif /* PX_COMPAT_SEMAPHORE_H */
