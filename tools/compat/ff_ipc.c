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

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <unistd.h>
#include "netinet/in.h"

#include "ff_ipc.h"

static int inited;

static struct rte_mempool *message_pool;

uint16_t ff_proc_id = 0;

void
ff_set_proc_id(int pid)
{
    if (pid < 0 || pid > 65535) {
        printf("Invalid F-Stack proccess id\n");
        exit(1);
    }
    ff_proc_id = pid;
}

int
ff_ipc_init(void)
{
    if (inited) {
        return 0;
    }

    char *dpdk_argv[] = {
        "ff-ipc", "-c1", "-n4",
        "--proc-type=secondary",
        /* RTE_LOG_WARNING */
        "--log-level=5",
    };

    int ret = rte_eal_init(sizeof(dpdk_argv)/sizeof(dpdk_argv[0]), dpdk_argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }

    message_pool = rte_mempool_lookup(FF_MSG_POOL);
    if (message_pool == NULL) {
        rte_exit(EXIT_FAILURE, "lookup message pool:%s failed!\n", FF_MSG_POOL);
    }

    inited = 1;

    return 0;
}

struct ff_msg *
ff_ipc_msg_alloc(void)
{
    if (inited == 0) {
        int ret = ff_ipc_init();
        if (ret < 0) {
            return NULL;
        }
    }

    void *msg;
    if (rte_mempool_get(message_pool, &msg) < 0) {
        printf("get buffer from message pool failed.\n");
        return NULL;
    }

    return (struct ff_msg *)msg;
}

int
ff_ipc_msg_free(struct ff_msg *msg)
{
    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    rte_mempool_put(message_pool, msg);

    return 0;
}

int
ff_ipc_send(const struct ff_msg *msg)
{
    int ret;

    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    char name[RTE_RING_NAMESIZE];
    snprintf(name, RTE_RING_NAMESIZE, "%s%u",
        FF_MSG_RING_IN, ff_proc_id);
    struct rte_ring *ring = rte_ring_lookup(name);
    if (ring == NULL) {
        printf("lookup message ring:%s failed!\n", name);
        return -1;
    }

    ret = rte_ring_enqueue(ring, (void *)msg);
    if (ret < 0) {
        printf("ff_ipc_send failed\n");
        return ret;
    }

    return 0;
}

int
ff_ipc_recv(struct ff_msg **msg, enum FF_MSG_TYPE msg_type)
{
    int ret, i;
    if (inited == 0) {
        printf("ff ipc not inited\n");
        return -1;
    }

    char name[RTE_RING_NAMESIZE];
    snprintf(name, RTE_RING_NAMESIZE, "%s%u_%u",
        FF_MSG_RING_OUT, ff_proc_id, msg_type);
    struct rte_ring *ring = rte_ring_lookup(name);
    if (ring == NULL) {
        printf("lookup message ring:%s failed!\n", name);
        return -1;
    }

    void *obj;
    #define MAX_ATTEMPTS_NUM 1000
    for (i = 0; i < MAX_ATTEMPTS_NUM; i++) {
        ret = rte_ring_dequeue(ring, &obj);
        if (ret == 0) {
            *msg = (struct ff_msg *)obj;
            break;
        }

        usleep(1000);
    }

    return ret;
}

int
ff_ipc_send_recv(struct ff_msg *msg){
    int ret = ff_ipc_send(msg);
    if (ret < 0) {
        errno = EPIPE;
        ff_ipc_msg_free(msg);
        return -1;
    }

    struct ff_msg *retmsg = NULL;
    do {
        if (retmsg != NULL) {
            ff_ipc_msg_free(retmsg);
        }

        ret = ff_ipc_recv(&retmsg, msg->msg_type);
        if (ret < 0) {
            errno = EPIPE;
            ff_ipc_msg_free(msg);
            return -1;
        }
    } while (msg != retmsg);

    return 0;
}

int ff_ipc_socket(int domain, int type, int protocol) {
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_SOCKET;
    msg->socket.domain = domain;
    msg->socket.type = type;
    msg->socket.protocol = protocol;

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    int socket_fd = msg->socket.socket_fd;

    ff_ipc_msg_free(msg);
    return socket_fd;
}

int ff_ipc_setsockopt(int s, int level, int optname, const void *optval,
                      socklen_t optlen){
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_SETSOCKOPT;
    msg->setsockopt.s = s;
    msg->setsockopt.level = level;
    msg->setsockopt.optname = optname;
    msg->setsockopt.optval = msg->buf_addr;
    msg->setsockopt.optlen = optlen;

    bcopy(optval, msg->setsockopt.optval, optlen);

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    ssize_t rt = msg->setsockopt.rt;

    ff_ipc_msg_free(msg);
    return rt;
}

int ff_ipc_connect(int s, const struct sockaddr *name, socklen_t namelen){
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_CONNECT;
    msg->connect.s = s;
    // convert freebsd sock to linux sock
    msg->connect.name = (struct linux_sockaddr *)(msg->buf_addr);
    msg->connect.name->sa_family = name->sa_family;
    bcopy(name->sa_data, msg->connect.name->sa_data,name->sa_len - sizeof(msg->connect.name->sa_family));

    msg->connect.namelen = namelen;

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    int rt = msg->connect.rt;

    ff_ipc_msg_free(msg);
    return rt;
}

int ff_ipc_bind(int s, const struct sockaddr *addr, socklen_t addrlen){
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_BIND;
    msg->bind.s = s;
    // convert freebsd sock to linux sock
    msg->bind.addr = (struct linux_sockaddr *)(msg->buf_addr);
    msg->bind.addr->sa_family = addr->sa_family;
    bcopy(addr->sa_data, msg->bind.addr->sa_data,addr->sa_len - sizeof(msg->bind.addr->sa_family));

    msg->bind.addrlen = addrlen;

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    int rt = msg->bind.rt;

    ff_ipc_msg_free(msg);
    return rt;
}

int ff_ipc_close(int fd){
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_CLOSE;
    msg->close.fd = fd;

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    ssize_t rt = msg->close.rt;

    ff_ipc_msg_free(msg);
    return rt;
}

int ff_ipc_kqueue(void){
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_KQUEUE;
    msg->kqueue.kq = 0;

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    int rt = msg->kqueue.kq;

    ff_ipc_msg_free(msg);
    return rt;
}

int ff_ipc_kevent(int kq, const struct kevent *changelist, int nchanges,
                  struct kevent *eventlist, int nevents, const struct timespec *timeout) {
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_KEVENT;

    msg->kevent.kq = kq;
    msg->kevent.nchanges = nchanges;
    if (changelist == NULL) {
        msg->kevent.changelist = NULL;
    } else {
        msg->kevent.changelist = (struct kevent *) (msg->buf_addr);
        bcopy(changelist, msg->kevent.changelist, nchanges * sizeof(struct kevent));
    }

    msg->kevent.nevents = nevents;
    if (eventlist == NULL) {
        msg->kevent.eventlist = NULL;
    } else {
        msg->kevent.eventlist = (struct kevent *) (msg->buf_addr + nchanges * sizeof(struct kevent));
        bcopy(eventlist, msg->kevent.eventlist, nevents * sizeof(struct kevent));
    }

    if (timeout == NULL) {
        msg->kevent.timeout = NULL;
    } else {
        msg->kevent.timeout = (struct timespec *) (msg->buf_addr + (nchanges + nevents) * sizeof(struct kevent));
        bcopy(timeout, msg->kevent.timeout, sizeof(struct timespec));
    }

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    int rt = msg->kevent.rt;
    if (rt > 0) {
        bcopy(msg->kevent.eventlist, eventlist, nevents * sizeof(struct kevent));
    }

    ff_ipc_msg_free(msg);
    return rt;
}

ssize_t ff_ipc_read(int d, void *buf, size_t nbytes){
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_READ;

    msg->read.d = d;
    msg->read.buf = msg->buf_addr;
    msg->read.nbytes = nbytes;

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    ssize_t rt = msg->read.rt;
    bcopy(msg->read.buf, buf, nbytes);

    ff_ipc_msg_free(msg);
    return rt;
}

ssize_t ff_ipc_recvmsg(int s, struct msghdr *msg, int flags) {
    struct ff_msg *rpc_msg = ff_ipc_msg_alloc();
    rpc_msg->msg_type = FF_RECVMSG;

    rpc_msg->recvmsg.s = s;
    rpc_msg->recvmsg.flags = flags;

    rpc_msg->recvmsg.msg = (struct msghdr *) rpc_msg->buf_addr;
    bcopy(msg, rpc_msg->recvmsg.msg, sizeof(struct msghdr));

    rpc_msg->recvmsg.msg->msg_name = rpc_msg->recvmsg.msg + sizeof(struct msghdr);
    bcopy(msg->msg_name, rpc_msg->recvmsg.msg->msg_name, sizeof(struct sockaddr_in));

    rpc_msg->recvmsg.msg->msg_iov = (struct iovec *) (rpc_msg->recvmsg.msg->msg_name + sizeof(struct linux_sockaddr));
    rpc_msg->recvmsg.msg->msg_iov->iov_base = rpc_msg->recvmsg.msg->msg_iov + sizeof(struct iovec);
    rpc_msg->recvmsg.msg->msg_iov->iov_len = msg->msg_iov->iov_len;

    rpc_msg->recvmsg.msg->msg_control = rpc_msg->recvmsg.msg->msg_iov->iov_base + rpc_msg->recvmsg.msg->msg_iov->iov_len;
    rpc_msg->recvmsg.msg->msg_flags = msg->msg_flags;

    int ret = ff_ipc_send_recv(rpc_msg);
    if (ret < 0) return ret;

    ssize_t rt = rpc_msg->recvmsg.rt;
    if (rt > 0){
        // msg_namelen, msg_name, msg_iov, msg_controllen, msg_flags may be changed by recvmsg syscall
        msg->msg_namelen = rpc_msg->recvmsg.msg->msg_namelen;
        // converte linux_sockaddr to freebsd socket
        struct linux_sockaddr*  linux_sock = (struct linux_sockaddr*) rpc_msg->recvmsg.msg->msg_name;
        struct sockaddr* freebsd_sock = (struct sockaddr*)msg->msg_name;
        freebsd_sock->sa_family = linux_sock->sa_family;
        freebsd_sock->sa_len = msg->msg_namelen;
        bcopy(linux_sock->sa_data, freebsd_sock->sa_data, msg->msg_namelen - sizeof(linux_sock->sa_family));

        msg->msg_iov->iov_len = rpc_msg->recvmsg.msg->msg_iov->iov_len + rt;
        bcopy(rpc_msg->recvmsg.msg->msg_iov->iov_base - rt, msg->msg_iov->iov_base, rt);

        msg->msg_controllen = rpc_msg->recvmsg.msg->msg_controllen;
        bcopy(rpc_msg->recvmsg.msg->msg_control, msg->msg_control, msg->msg_controllen);
        msg->msg_flags = rpc_msg->recvmsg.msg->msg_flags;
    }

    ff_ipc_msg_free(rpc_msg);
    return rt;
}

ssize_t ff_ipc_socksend(int s, const void *buf, size_t len, int flags){
    struct ff_msg *msg = ff_ipc_msg_alloc();

    msg->msg_type = FF_SEND;
    msg->send.s = s;
    msg->send.buf = msg->buf_addr;
    msg->send.len = len;
    msg->send.flags = flags;

    bcopy(buf, msg->send.buf, len);

    int ret = ff_ipc_send_recv(msg);
    if (ret < 0) return ret;

    ssize_t rt = msg->send.rt;

    ff_ipc_msg_free(msg);
    return rt;
}