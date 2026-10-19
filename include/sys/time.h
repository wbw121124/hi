/* sys/time.h - POSIX <sys/time.h> mapped onto the Win32 API (header-only).
 * License: MIT
 */
#ifndef PX_COMPAT_SYS_TIME_H
#define PX_COMPAT_SYS_TIME_H

#ifdef _WIN32

#include <time.h>
#include <sys/timeb.h>
#include "compat/posix_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* struct timeval / struct timespec live in compat/posix_defs.h */

/* timezone/daylight globals (XSI): Windows CRT exposes _timezone/_daylight */
#ifndef px_timezone_defined
#define px_timezone_defined
extern long _timezone;
extern long _daylight;
#ifndef timezone
#define timezone (_timezone)
#endif
#ifndef daylight
#define daylight ((int)_daylight)
#endif
#endif

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

static int gettimeofday(struct timeval *tv, struct timezone *tz)
{
    (void)tz; /* tz is ignored on Windows, like modern BSD behaviour */
    if (tv) {
        struct _timeb tb;
        _ftime_s(&tb);
        tv->tv_sec  = (time_t)tb.time;
        tv->tv_usec = (long)tb.millitm * 1000;
    }
    return 0;
}

/* POSIX timers (timer_create & friends) are provided by <time.h> mapping. */

#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <sys/time.h>
#endif

#endif /* PX_COMPAT_SYS_TIME_H */
