/*
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _FF_MSG_H_
#define _FF_MSG_H_

#include <rte_memory.h>

#define FF_MSG_RING_IN  "ff_msg_ring_in_"
#define FF_MSG_RING_OUT "ff_msg_ring_out_"
#define FF_MSG_POOL     "ff_msg_pool"

/* MSG TYPE: sysctl, ioctl, etc.. */
enum FF_MSG_TYPE {
    FF_UNKNOWN = 0,
    FF_SYSCTL,
    FF_IOCTL,
    FF_IOCTL6,
    FF_ROUTE,
    FF_TOP,
    FF_NGCTL,
    FF_IPFW_CTL,
    FF_TRAFFIC,
    FF_SOCKET,
    FF_SOCKET_CONNECT,
    FF_KQUEUE,
    FF_KEVENT,
    FF_SOCK_READ,
    FF_SOCK_SEND,
    /*
     * to add other msg type before FF_MSG_NUM
     */
    FF_MSG_NUM,
};

struct ff_sysctl_args {
    int *name;
    unsigned namelen;
    void *old;
    size_t *oldlenp;
    void *new;
    size_t newlen;
};

struct ff_ioctl_args {
    unsigned long cmd;
    void *data;
};

struct ff_route_args {
    int fib;
    unsigned len;
    unsigned maxlen;
    void *data;
};

struct ff_top_args {
    unsigned long loops;
    unsigned long idle_tsc;
    unsigned long work_tsc;
    unsigned long sys_tsc;
    unsigned long usr_tsc;
};

struct ff_ngctl_args {
    int cmd;
    int ret;
    void *data;
};

enum FF_IPFW_CMD {
    FF_IPFW_GET,
    FF_IPFW_SET,
};

struct ff_ipfw_args {
    int cmd;
    int level;
    int optname;
    void *optval;
    socklen_t *optlen;
};

struct ff_traffic_args {
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
};

struct ff_socket_args {
    int domain;
    int type;
    int protocol;
    int socket_fd;
};

struct ff_sock_connect_args {
    int s;
    struct linux_sockaddr *name;
    socklen_t namelen;
    int rt;
};

struct ff_kqueue_args {
    int kq;
};

struct ff_kevent_args {
    int kq;
    struct kevent *changelist;
    int nchanges;
    struct kevent *eventlist;
    int nevents;
    struct timespec *timeout;
    int rt;
};

struct ff_sock_read_args {
    int d;
    void *buf;
    size_t nbytes;
    ssize_t rt;
};

struct ff_sock_send_args {
    int s;
    void *buf;
    size_t len;
    int flags;
    ssize_t rt;
};

#define MAX_MSG_BUF_SIZE 10240

/* structure of ipc msg */
struct ff_msg {
    enum FF_MSG_TYPE msg_type;
    /* Result of msg processing */
    int result;
    /* Length of segment buffer. */
    size_t buf_len;
    /* Address of segment buffer. */
    char *buf_addr;

    union {
        struct ff_sysctl_args sysctl;
        struct ff_ioctl_args ioctl;
        struct ff_route_args route;
        struct ff_top_args top;
        struct ff_ngctl_args ngctl;
        struct ff_ipfw_args ipfw;
        struct ff_traffic_args traffic;
        struct ff_socket_args socket;
        struct ff_sock_connect_args sock_connect;
        struct ff_kqueue_args kqueue;
        struct ff_kevent_args kevent;
        struct ff_sock_read_args sock_read;
        struct ff_sock_send_args sock_send;
    };
} __attribute__((packed)) __rte_cache_aligned;

#endif
