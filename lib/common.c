#include "common.h"
#include <assert.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <string.h>

rw_buff *
create_rw_buff(uint32_t size)
{
    rw_buff *rw = NULL;

    rw = NG_MALLOC(sizeof(rw_buff));
    if (rw == NULL) {
        DM_LOG_ERROR("malloc 1 failed");
        goto end;
    }
    rw->buf = NG_MALLOC(size);
    if (rw->buf == NULL) {
        DM_LOG_ERROR("malloc 2 failed");
        NG_FREE(rw); rw = NULL;
        goto end;
    }
    rw->size = size;
    rw->off = 0;
    DM_LOG_TRACE("RW buf created size[%u] off[%u]", rw->size, rw->off);

    return rw;

end:
    return NULL;
}
void
free_rw_buff(rw_buff *rw)
{
    DM_LOG_TRACE("RW buf FREE size[%u] off[%u]", rw->size, rw->off);

    NG_FREE(rw->buf); rw->buf = NULL;
    NG_FREE(rw);
}

void
reset_rw_buff(rw_buff *rw)
{
    rw->off = 0;
    memset(rw->buf, 0, rw->size);
}

int
realloc_rw_buff(rw_buff *rw, uint32_t new_size)
{
    rw->size = new_size;
    rw->buf = realloc(rw->buf, rw->size);

    assert(rw->buf != NULL);

    return SUCCESS;
}

int
set_socketopt_recv_timeout(int sockfd, long sec, long usec)
{
    int ret = SUCCESS;
    struct timeval timeout;

    timeout.tv_sec = sec;
    timeout.tv_usec = usec;

    DM_LOG_TRACE("setting recv timeout to %ld.%06ld seconds", timeout.tv_sec, (long) timeout.tv_usec);

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        DM_LOG_ERROR("setsockopt failed due to '%s'", strerror(errno));
        ret = FAILURE;
    }
    return ret;
}

int
set_socketopt_send_timeout(int sockfd, long sec, long usec)
{
    int ret = SUCCESS;
    struct timeval timeout;

    timeout.tv_sec = sec;
    timeout.tv_usec = usec;

    DM_LOG_TRACE("setting send timeout to %ld.%06ld second(s)", timeout.tv_sec, (long) timeout.tv_usec);

    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        DM_LOG_ERROR("setsockopt failed due to '%s'", strerror(errno));
        ret = FAILURE;
    }
    return ret;
}

int
set_socketopt_nodelay(int sockfd, int on)
{
    int ret = SUCCESS;
    int i = on;

    DM_LOG_TRACE("setting socket no-delay=%d", on);

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *)&i, sizeof(i)) < 0) {
        DM_LOG_ERROR("setsockopt failed due to '%s'", strerror(errno));
        ret = FAILURE;
    }

    return ret;
}

#if defined(TCP_QUICKACK)
int
set_socketopt_quickack(int sockfd, int on)
{
    int ret = SUCCESS;
    int i = on;

    DM_LOG_TRACE("setting socket quickack=%d", on);

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i)) < 0) {
        DM_LOG_ERROR("setsockopt failed due to '%s'", strerror(errno));
        ret = FAILURE;
    }

    return ret;
}
#endif

void
diff_ts(const struct timespec *start, const struct timespec *end, struct timespec *diff)
{
    if ((end->tv_nsec-start->tv_nsec)<0) {
        diff->tv_sec = end->tv_sec-start->tv_sec-1;
        diff->tv_nsec = 1000000000+end->tv_nsec-start->tv_nsec;
    } else {
        diff->tv_sec = end->tv_sec-start->tv_sec;
        diff->tv_nsec = end->tv_nsec-start->tv_nsec;
    }
    return;
}

in_addr_t
hostname_to_ip(const char *hostname)
{
    struct hostent *he;

    if ((he = gethostbyname(hostname)) == NULL) {
        DM_LOG_ERROR("gethostbyname(%s) return error: %d %s", hostname, errno, hstrerror(h_errno));
        return INADDR_NONE;
    }

    int size = 0;
    int i;
    for (i=0; he->h_addr_list[i] != NULL; i++) {
        size++;
    }

    if (size == 0) {
        DM_LOG_ERROR("gethostbyname(%s) returned zero A records", hostname);
        return INADDR_NONE;
    }

    in_addr_t addr;
    // pickup random resolved address
    memcpy(&addr, he->h_addr_list[rand() % size], sizeof(addr));
    return addr;
}

#ifdef DEF_CLOCK_MONOTONIC
int clock_gettime(int foo, struct timespec *ts)
{

    gettimeofday(&tv, NULL);
    ts->tv_sec = tv.tv_sec;
    ts->tv_nsec = tv.tv_usec * 1000;

    return 0;
}
#endif

int wait_socket(int fd, short events, short *revents, int *max_timeout_ms)
{
    int ret;
    struct pollfd fds[1];
    struct timespec before, after, diff;

    if (clock_gettime(CLOCK_MONOTONIC, &before) != 0) {
        DM_LOG_ERROR("clock_gettime(CLOCK_MONOTONIC) %d:%s", errno, strerror(errno));
        return 0;
    }

    fds[0].fd = fd;
    fds[0].events = events;
    fds[0].revents = *revents;

    ret = poll(fds, 1, *max_timeout_ms);

    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0) {
        DM_LOG_ERROR("clock_gettime(CLOCK_MONOTONIC) %d:%s", errno, strerror(errno));
        return 0;
    }

    diff_ts(&before, &after, &diff);

    DM_LOG_TRACE("Decrease max timeout: max_timeout_ms: %d, diff.tv_sec: %d, diff.tv_nsec: %d",
        *max_timeout_ms, (int)diff.tv_sec, (int)diff.tv_nsec);

    *max_timeout_ms -= diff.tv_sec * 1000;
    *max_timeout_ms -= diff.tv_nsec / 1000000;

    if (*max_timeout_ms < 0) {
        *max_timeout_ms = 0;
    }

    *revents = fds[0].revents;

    return ret;
}

#ifdef ENABLE_HTTPS
int ssl_wait_socket(SSL *ssl, int ssl_ret, int fd, short events, short *revents, int *max_timeout_ms)
{
    int ssl_error_ret, real_events;

    *revents = 0;

    real_events = events & ~(POLLIN | POLLOUT);

    ssl_error_ret = SSL_get_error(ssl, ssl_ret);
    switch (ssl_error_ret) {
        case SSL_ERROR_WANT_READ:
            if (events & POLLIN) {
                DM_LOG_DEBUG("SSL with error code SSL_ERROR_WANT_READ, add POLLIN to events mask");
                real_events |= POLLIN;
                break;
            }
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_WANT_READ");
            return -1;

        case SSL_ERROR_WANT_WRITE:
            if (events & POLLOUT) {
                DM_LOG_DEBUG("SSL with error code SSL_ERROR_WANT_WRITE, add POLLOUT to events mask");
                real_events |= POLLOUT;
                break;
            }
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_WANT_WRITE");
            return -1;

        case SSL_ERROR_WANT_CONNECT:
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_WANT_CONNECT");
            return -1;

        case SSL_ERROR_WANT_ACCEPT:
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_WANT_ACCEPT");
            return -1;

        case SSL_ERROR_NONE:
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_NONE");
            return -1;

        case SSL_ERROR_ZERO_RETURN:
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_ZERO_RETURN");
            return -1;

        case SSL_ERROR_WANT_X509_LOOKUP:
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_WANT_X509_LOOKUP");
            return -1;

        case SSL_ERROR_SYSCALL:
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_SYSCALL");
            return -1;

        case SSL_ERROR_SSL:
            DM_LOG_DEBUG("SSL failed with error code SSL_ERROR_SSL");
            return -1;

        default:
            DM_LOG_DEBUG("SSL_get_error() return code %d was not expected, check SSL source for new error codes.", ssl_error_ret);
            return -1;

    }

    return wait_socket(fd, real_events, revents, max_timeout_ms);
}

int ssl_shutdown(SSL *ssl, int fd, int *max_timeout_ms)
{
    int   rc;
    short revents;

    for (;;) {
        rc = SSL_shutdown(ssl);
        if (rc != 0) {
            return rc;
        }

        revents = 0;

        rc = ssl_wait_socket(ssl, rc, fd, POLLHUP | POLLOUT | POLLIN, &revents, max_timeout_ms);
        if (rc == -1 || revents & POLLERR) {
            return -1;
        }
        if (revents & POLLHUP) {
            return 0;
        }
    }
}
#endif