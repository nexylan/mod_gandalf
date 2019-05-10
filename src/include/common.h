/**
 * @file    common.h
 * @brief   Function prototypes for common functions.
 *
 * @details This contains the prototypes for the common structures, macros
 *          and functions like read/write buffer structure and access APIs,
 *          Utils functions APIs & macros.
 *
 * @bug No known bugs.
 */

#ifndef __NG_HTTP_COMMON_H__
#define __NG_HTTP_COMMON_H__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <pthread.h>
#include <time.h>
#include <poll.h>

#ifdef ENABLE_HTTPS
//#warning "Compiling with ENABLE_HTTPS"
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
#warning "Compiling without ENABLE_HTTPS"
#endif

#include "logging.h"

//#define DEBUG 1

/**
 * @brief   The is common read/write buffer structre.
 * @details This structure will be used to handle data
 *          send and receive from peer.
 */
typedef struct _rw_buf {
    uint32_t size;  /*<! Buffer size */
    uint32_t off;   /*<! Buffer read/write offset */
    uint32_t rw_len;/*<! Buffer read/write process lenght */
    uint8_t *buf;   /*<! Buffer it self */
}rw_buff;

/**
 * @brief   This function creates the new read/write buffer
 *
 * @details Create a new rw_buff and allocate the required size
 *          buf and assign it and also initialize it
 * @param   size    Size of the buffer to be created
 * @return  It returns the allocated rw_buff pointer
 */
extern rw_buff * create_rw_buff(uint32_t size);

/**
 * @brief   This function reallocate the existing buffer size
 *
 * @details It reallocates the buffer and re-initialize the size
 *          of the buffer.
 * @param   newsize Newly required size of the buffer
 * @param   rw  Existing rw_buff pointer
 * @return  SUCCESS, if reallocation success
 *          FAILURE if realloc failed
 */
extern int realloc_rw_buff(rw_buff *rw, uint32_t newsize);
extern void reset_rw_buff(rw_buff *rw);
extern void free_rw_buff(rw_buff *rw);

#define DEFAULT_BUF_SIZE (16 * 1024)
#define FREE_RW_BUFF(__b) do { if (__b) {free_rw_buff(__b); __b = NULL;} } while (0)

/* Utils APIs */
extern int set_socketopt_recv_timeout(int sockfd, long sec, long usec);
extern int set_socketopt_send_timeout(int sockfd, long sec, long usec);
extern int set_socketopt_nodelay(int sockfd, int on);
#if defined(TCP_QUICKACK)
extern int set_socketopt_quickack(int sockfd, int on);
#endif
extern void diff_ts(const struct timespec *start, const struct timespec *end, struct timespec *diff);
extern in_addr_t hostname_to_ip(const char *hostname);

#define UNUSED_ARG __attribute__((unused))

#define SUCCESS 0
#define FAILURE -1
#define TIMED_OUT -2
#define RECONNECTION 2

#define NG_MALLOC(__size) calloc(1, __size)
#define NG_CALLOC calloc
#define NG_FREE(__p) do { free(__p); __p = NULL; } while (0)
#define NG_CLOSE(__fd) do { close(__fd); __fd = -1; } while (0)

#ifndef CLOCK_MONOTONIC // only for OS X
#define CLOCK_MONOTONIC 0
#define DEF_CLOCK_MONOTONIC 0
int clock_gettime(int foo, struct timespec *ts)
#endif

int wait_socket(int fd, short events, short *revents, int *max_timeout);
#ifdef ENABLE_HTTPS
int ssl_wait_socket(SSL *ssl, int ssl_ret, int fd, short events, short *revents, int *max_timeout_ms);
int ssl_shutdown(SSL *ssl, int fd, int *max_timeout_ms);
#endif

#endif
