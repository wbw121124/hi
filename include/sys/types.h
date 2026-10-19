/* sys/types.h - POSIX <sys/types.h> mapped onto the Win32 API (header-only).
 * License: MIT
 */
#ifndef PX_COMPAT_SYS_TYPES_H
#define PX_COMPAT_SYS_TYPES_H

#ifdef _WIN32
#include "compat/posix_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* All POSIX scalar types live in compat/posix_defs.h:
   size_t, ssize_t, off_t, mode_t, uid_t, gid_t, pid_t, dev_t, ino_t,
   nlink_t, blksize_t, blkcnt_t, clockid_t, timer_t, in_port_t, in_addr_t,
   int8_t..uint64_t, suseconds_t, useconds_t, key_t. */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <sys/types.h>
#endif

#endif /* PX_COMPAT_SYS_TYPES_H */
