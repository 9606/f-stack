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

#ifndef _FF_IPC_H_
#define _FF_IPC_H_

#include "ff_msg.h"
#include "ff_api.h"

/* Set F-Stack proccess id to communicate with */
void ff_set_proc_id(int pid);

int ff_ipc_init(void);
struct ff_msg *ff_ipc_msg_alloc(void);
int ff_ipc_msg_free(struct ff_msg *msg);

int ff_ipc_send(const struct ff_msg *msg);
int ff_ipc_recv(struct ff_msg **msg, enum FF_MSG_TYPE msg_type);

/* POSIX-LIKE-IPC api begin */
int ff_ipc_socket(int domain, int type, int protocol);
int ff_ipc_sock_connect(int s, const struct sockaddr *name, socklen_t namelen);

ssize_t ff_ipc_sock_read(int d, void *buf, size_t nbytes);
ssize_t ff_ipc_sock_send(int s, const void *buf, size_t len, int flags);

int ff_ipc_kqueue(void);
int ff_ipc_kevent(int kq, const struct kevent *changelist, int nchanges,
                  struct kevent *eventlist, int nevents, const struct timespec *timeout);

/* POSIX-LIKE-IPC api end */

#endif
