/* sys/socket.h - POSIX <sys/socket.h> mapped onto Winsock2 (header-only).
 *
 * BSD socket calls are 1:1 with Winsock, so most of this header is type/
 * constant plumbing plus the few functions Windows lacks:
 *   socketpair()  -> loopback TCP pair (same trick as pipe())
 *   sendmsg/recvmsg -> WSASendMsg/WSARecvMsg via WSAIoctl lookup
 * License: MIT
 */
#ifndef PX_COMPAT_SYS_SOCKET_H
#define PX_COMPAT_SYS_SOCKET_H

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include "compat/posix_defs.h"
#include "compat/winfd.h"   /* px_wsa_init() */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _PX_SOCKLEN_T_DEFINED
#define _PX_SOCKLEN_T_DEFINED
typedef int socklen_t;
#endif

/* address families missing from older winsock headers */
#ifndef AF_UNIX
#define AF_UNIX 1
#endif
#ifndef PF_UNIX
#define PF_UNIX AF_UNIX
#endif

/* MSG_* flags: Winsock defines MSG_PEEK/MSG_OOB/MSG_WAITALL/MSG_DONTROUTE.
 * Add the BSD-only ones with values that translate sensibly. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000   /* ignored: Windows uses WSAEWOULDBLOCK model */
#endif
#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT 0x40     /* emulated by toggling FIONBIO around the call */
#endif
#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0
#endif

/* SOL_* aliases */
#ifndef SOL_SOCKET
#define SOL_SOCKET SO_SOCKET
#endif

struct msghdr {
    void         *msg_name;
    socklen_t     msg_namelen;
    struct iovec *msg_iov;
    int           msg_iovlen;
    void         *msg_control;
    size_t        msg_controllen;
    int           msg_flags;
};

struct cmsghdr {
    size_t cmsg_len;
    int    cmsg_level;
    int    cmsg_type;
};
#define CMSG_ALIGN(len)   (((len) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))
#define CMSG_SPACE(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define CMSG_LEN(len)     (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define CMSG_DATA(cmsg)   ((unsigned char *)(cmsg) + CMSG_ALIGN(sizeof(struct cmsghdr)))

/* shutdown(): SD_RECEIVE/SD_SEND already exist in winsock2.h */
#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH

/* accept4 flags */
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0x4000
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC  0x80000
#endif

/* ---- wrappers translating WSA errors into errno ------------------- */
static int px_sock_ret_to_errno(int r)
{
    if (r == SOCKET_ERROR) errno = px_wsae_to_errno(WSAGetLastError());
    return r;
}

static int bind_(SOCKET s, const struct sockaddr *a, socklen_t l)
{ return px_sock_ret_to_errno(bind(s, a, (int)l)); }
#define bind(a,b,c) bind_((a),(b),(socklen_t)(c))

static int connect_(SOCKET s, const struct sockaddr *a, socklen_t l)
{ return px_sock_ret_to_errno(connect(s, a, (int)l)); }
#define connect(a,b,c) connect_((a),(b),(socklen_t)(c))

static ssize_t send_(SOCKET s, const void *buf, size_t n, int flags)
{
    if (flags & MSG_DONTWAIT) {
        u_long nb = 1, zero = 0;
        ssize_t r;
        ioctlsocket(s, FIONBIO, &nb);
        r = (ssize_t)send(s, (const char *)buf, (int)n, flags & ~MSG_DONTWAIT);
        ioctlsocket(s, FIONBIO, &zero);
        return px_sock_ret_to_errno((int)r);
    }
    return px_sock_ret_to_errno(send(s, (const char *)buf, (int)n, flags));
}
#define send(a,b,c,d) send_((a),(b),(size_t)(c),(d))

static ssize_t recv_(SOCKET s, void *buf, size_t n, int flags)
{
    if (flags & MSG_DONTWAIT) {
        u_long nb = 1, zero = 0;
        ssize_t r;
        ioctlsocket(s, FIONBIO, &nb);
        r = (ssize_t)recv(s, (char *)buf, (int)n, flags & ~MSG_DONTWAIT);
        ioctlsocket(s, FIONBIO, &zero);
        return px_sock_ret_to_errno((int)r);
    }
    return px_sock_ret_to_errno(recv(s, (char *)buf, (int)n, flags));
}
#define recv(a,b,c,d) recv_((a),(b),(size_t)(c),(d))

static ssize_t sendto_(SOCKET s, const void *buf, size_t n, int flags,
                       const struct sockaddr *to, socklen_t tolen)
{
    return px_sock_ret_to_errno(sendto(s, (const char *)buf, (int)n, flags,
                                       to, (int)tolen));
}
#define sendto(a,b,c,d,e,f) sendto_((a),(b),(size_t)(c),(d),(e),(socklen_t)(f))

static ssize_t recvfrom_(SOCKET s, void *buf, size_t n, int flags,
                         struct sockaddr *from, socklen_t *fromlen)
{
    int fl = fromlen ? (int)*fromlen : 0;
    ssize_t r = px_sock_ret_to_errno(
                   recvfrom(s, (char *)buf, (int)n, flags, from,
                            fromlen ? &fl : NULL));
    if (fromlen) *fromlen = (socklen_t)fl;
    return r;
}
#define recvfrom(a,b,c,d,e,f) recvfrom_((a),(b),(size_t)(c),(d),(e),(f))

static int listen_(SOCKET s, int backlog)
{ return px_sock_ret_to_errno(listen(s, backlog)); }
#define listen(a,b) listen_((a),(b))

static SOCKET accept_(SOCKET s, struct sockaddr *addr, socklen_t *addrlen)
{
    int al = addrlen ? (int)*addrlen : 0;
    SOCKET r = accept(s, addr, addrlen ? &al : NULL);
    if (r == INVALID_SOCKET) errno = px_wsae_to_errno(WSAGetLastError());
    else if (addrlen) *addrlen = (socklen_t)al;
    return r;
}
#define accept(a,b,c) accept_((a),(b),(c))

static int socket_(int domain, int type, int protocol)
{
    SOCKET s = socket(domain, type & ~SOCK_NONBLOCK & ~SOCK_CLOEXEC, protocol);
    if (s == INVALID_SOCKET) { errno = px_wsae_to_errno(WSAGetLastError()); return -1; }
    if (type & SOCK_NONBLOCK) {
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
    }
    return (int)s;
}
#define socket(a,b,c) socket_((a),(b),(c))

static int closesocket_(SOCKET s)
{
    int r = closesocket(s);
    if (r == SOCKET_ERROR) errno = px_wsae_to_errno(WSAGetLastError());
    return r;
}
#define closesocket(a) closesocket_((a))

static int getsockopt_(SOCKET s, int level, int optname, void *optval,
                       socklen_t *optlen)
{
    int ol = optlen ? (int)*optlen : 0;
    int r = getsockopt(s, level, optname, (char *)optval, ol ? &ol : NULL);
    if (r == SOCKET_ERROR) errno = px_wsae_to_errno(WSAGetLastError());
    else if (optlen) *optlen = (socklen_t)ol;
    return r;
}
#define getsockopt(a,b,c,d,e) getsockopt_((a),(b),(c),(d),(e))

static int setsockopt_(SOCKET s, int level, int optname, const void *optval,
                       socklen_t optlen)
{
    int r = setsockopt(s, level, optname, (const char *)optval, (int)optlen);
    if (r == SOCKET_ERROR) errno = px_wsae_to_errno(WSAGetLastError());
    return r;
}
#define setsockopt(a,b,c,d,e) setsockopt_((a),(b),(c),(d),(socklen_t)(e))

static int getsockname_(SOCKET s, struct sockaddr *a, socklen_t *l)
{
    int al = l ? (int)*l : 0;
    int r = getsockname(s, a, l ? &al : NULL);
    if (r == SOCKET_ERROR) errno = px_wsae_to_errno(WSAGetLastError());
    else if (l) *l = (socklen_t)al;
    return r;
}
#define getsockname(a,b,c) getsockname_((a),(b),(c))

static int getpeername_(SOCKET s, struct sockaddr *a, socklen_t *l)
{
    int al = l ? (int)*l : 0;
    int r = getpeername(s, a, l ? &al : NULL);
    if (r == SOCKET_ERROR) errno = px_wsae_to_errno(WSAGetLastError());
    else if (l) *l = (socklen_t)al;
    return r;
}
#define getpeername(a,b,c) getpeername_((a),(b),(c))

static int shutdown_(SOCKET s, int how)
{
    int r = shutdown(s, how);
    if (r == SOCKET_ERROR) errno = px_wsae_to_errno(WSAGetLastError());
    return r;
}
#define shutdown(a,b) shutdown_((a),(b))

/* ---- accept4 -------------------------------------------------------- */
static SOCKET accept4(SOCKET s, struct sockaddr *addr, socklen_t *addrlen,
                      int flags)
{
    SOCKET c = accept_(s, addr, addrlen);
    if (c != INVALID_SOCKET && (flags & SOCK_NONBLOCK)) {
        u_long nb = 1;
        ioctlsocket(c, FIONBIO, &nb);
    }
    return c;
}

/* ---- socketpair: loopback TCP -------------------------------------- */
static int socketpair(int domain, int type, int protocol, int sv[2])
{
    SOCKET ls, a, b;
    struct sockaddr_in addr;
    int len = sizeof(addr);
    int one = 1;
    (void)domain; (void)protocol;
    px_wsa_init();
    ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) { errno = px_wsae_to_errno(WSAGetLastError()); return -1; }
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR ||
        listen(ls, 1) == SOCKET_ERROR ||
        getsockname(ls, (struct sockaddr *)&addr, &len) == SOCKET_ERROR) {
        errno = px_wsae_to_errno(WSAGetLastError()); closesocket(ls); return -1;
    }
    a = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (a == INVALID_SOCKET) { errno = px_wsae_to_errno(WSAGetLastError()); closesocket(ls); return -1; }
    if (connect(a, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        errno = px_wsae_to_errno(WSAGetLastError()); closesocket(a); closesocket(ls); return -1;
    }
    b = accept(ls, NULL, NULL);
    closesocket(ls);
    if (b == INVALID_SOCKET) { errno = px_wsae_to_errno(WSAGetLastError()); closesocket(a); return -1; }
    setsockopt(a, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
    setsockopt(b, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one));
    if (type & SOCK_NONBLOCK) {
        u_long nb = 1;
        ioctlsocket(a, FIONBIO, &nb);
        ioctlsocket(b, FIONBIO, &nb);
    }
    sv[0] = (int)a;
    sv[1] = (int)b;
    return 0;
}

/* ---- sendmsg / recvmsg via WSARecvMsg/WSASendMsg -------------------- */
#ifndef WSAID_WSASENDMSG
#define WSAID_WSASENDMSG \
    {0xa441e712, 0x754f, 0x43ca, {0xb0,0xde,0x72,0x40,0x18,0xec,0xa0,0xf7}}
#endif
#ifndef WSAID_WSARECVMSG
#define WSAID_WSARECVMSG \
    {0xf6ed9951,0x3abf,0x4625,0x9b,0x74,0x69,0xd0,0xf7,0xd8,0x29,0xe4}
#endif

static ssize_t sendmsg(SOCKET s, const struct msghdr *msg, int flags)
{
    WSABUF bufs[64];
    DWORD sent = 0, i;
    int n = msg->msg_iovlen;
    if (n > 64) { errno = EMSGSIZE; return -1; }
    for (i = 0; i < (DWORD)n; i++) {
        bufs[i].buf = (CHAR *)msg->msg_iov[i].iov_base;
        bufs[i].len = (ULONG)msg->msg_iov[i].iov_len;
    }
    {
        int r;
        if (msg->msg_name)
            r = WSASendTo(s, bufs, n, &sent, (DWORD)flags,
                          (const struct sockaddr *)msg->msg_name,
                          (int)msg->msg_namelen, NULL, NULL);
        else
            r = WSASend(s, bufs, n, &sent, (DWORD)flags, NULL, NULL);
        if (r == SOCKET_ERROR) { errno = px_wsae_to_errno(WSAGetLastError()); return -1; }
    }
    return (ssize_t)sent;
}

static ssize_t recvmsg(SOCKET s, struct msghdr *msg, int flags)
{
    WSABUF bufs[64];
    DWORD got = 0, i;
    int fl = flags;
    ULONG addr_len = 0;
    struct sockaddr_storage ss;
    int r;
    if (msg->msg_iovlen > 64) { errno = EMSGSIZE; return -1; }
    for (i = 0; i < (DWORD)msg->msg_iovlen; i++) {
        bufs[i].buf = (CHAR *)msg->msg_iov[i].iov_base;
        bufs[i].len = (ULONG)msg->msg_iov[i].iov_len;
    }
    if (msg->msg_name) {
        memcpy(&ss, msg->msg_name, sizeof(ss));
        addr_len = msg->msg_namelen;
    }
    r = WSARecv(s, bufs, (DWORD)msg->msg_iovlen, &got, &fl, NULL, NULL);
    if (r == SOCKET_ERROR) { errno = px_wsae_to_errno(WSAGetLastError()); return -1; }
    msg->msg_flags = (int)fl;
    if (msg->msg_name && addr_len) {
        memcpy(msg->msg_name, &ss, sizeof(ss));
        msg->msg_namelen = (socklen_t)addr_len;
    }
    return (ssize_t)got;
}

#ifdef __cplusplus
}
#endif

#else /* !_WIN32 */
#include <sys/socket.h>
#endif

#endif /* PX_COMPAT_SYS_SOCKET_H */
