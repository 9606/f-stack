#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <assert.h>
#include <asm/errno.h>
#include <errno.h>
#include <zconf.h>
#include <sysexits.h>
#include <err.h>

#include "sys/ioctl.h"

#include "ff_api.h"
#include "ff_ipc.h"

#define BUFFER_SIZE 1024
#define HTTP_DEFAULT_PORT 80
#define HTTP_GET "GET /%s HTTP/1.1\r\nHOST: %s:%d\r\nAccept: */*\r\n\r\n"

int socket_fd = -1;
char lpbuf[BUFFER_SIZE * 4] = {'\0'};
int first = 1;

struct timeval last_time;
struct timeval now_time;
struct timeval time_interval;

#define MAX_EVENTS 512

/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;

int alive;

static void
usage(){
    errx(EX_USAGE, "usage: curl -p <f-stack proc_id> url");
}

struct timeval cal_time_offset(struct timeval begin, struct timeval end) {
    struct timeval ans;
    ans.tv_sec = end.tv_sec - begin.tv_sec;
    ans.tv_usec = end.tv_usec - begin.tv_usec;
    if (ans.tv_usec < 0) {
        ans.tv_sec--;
        ans.tv_usec += 1000000;
    }
    return ans;
}

static int http_tcpclient_create(const char *host, int port) {
    struct hostent *he;
    struct sockaddr_in server_addr;

    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_len = sizeof server_addr;
    server_addr.sin_port = htons(port);
    unsigned int inaddr = inet_addr(host);
    if (inaddr == INADDR_NONE) {
        he = gethostbyname(host);
        if (he == NULL) {
            return -1;
        }
        server_addr.sin_addr = *((struct in_addr *) he->h_addr);
    } else {
        memcpy((char *) &server_addr.sin_addr, &inaddr, sizeof(inaddr));
    }

    if ((socket_fd = ff_ipc_socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ff_socket failed\n");
        return -1;
    }

    ff_ipc_sock_connect(socket_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));

    return socket_fd;
}

static void http_tcpclient_close(int socket) {
    ff_ipc_sock_close(socket);
}

static int http_parse_url(const char *url, char *host, char *file, int *port) {
    char *ptr1, *ptr2;
    int len = 0;
    if (!url || !host || !file || !port) {
        return -1;
    }

    ptr1 = (char *) url;

    if (!strncmp(ptr1, "http://", strlen("http://"))) {
        ptr1 += strlen("http://");
    }

    ptr2 = strchr(ptr1, '/');
    if (ptr2) {
        len = strlen(ptr1) - strlen(ptr2);
        memcpy(host, ptr1, len);
        host[len] = '\0';
        if (*(ptr2 + 1)) {
            memcpy(file, ptr2 + 1, strlen(ptr2) - 1);
            file[strlen(ptr2) - 1] = '\0';
        }
    } else {
        memcpy(host, ptr1, strlen(ptr1));
        host[strlen(ptr1)] = '\0';
    }
    //get host and ip
    ptr1 = strchr(host, ':');
    if (ptr1) {
        *ptr1++ = '\0';
        *port = atoi(ptr1);
    } else {
        *port = HTTP_DEFAULT_PORT;
    }

    return 0;
}

static int http_tcpclient_recv(int socket, char *lpbuff) {
    int recvnum = 0;

    recvnum = ff_ipc_sock_read(socket, lpbuff, BUFFER_SIZE * 4);

    return recvnum;
}

static int http_tcpclient_send(int socket, char *buff, int size) {
    gettimeofday(&last_time, NULL);

    int sent = 0, tmpres = 0;
    while (sent < size) {
        tmpres = ff_ipc_sock_send(socket, buff + sent, size - sent, 0);
        if (tmpres == -1) {
            return -1;
        }
        sent += tmpres;
    }
    return sent;
}

static char *http_parse_result(const char *lpbuf) {
    char *ptmp = NULL;
    char *response = NULL;
    ptmp = (char *) strstr(lpbuf, "HTTP/1.1");
    if (!ptmp) {
        printf("http/1.1 not faind\n");
        return NULL;
    }
    if (atoi(ptmp + 9) != 200) {
        printf("result:\n%s\n", lpbuf);
        return NULL;
    }

    ptmp = (char *) strstr(lpbuf, "\r\n\r\n");
    if (!ptmp) {
        printf("ptmp is NULL\n");
        return NULL;
    }
    response = (char *) malloc(strlen(ptmp) + 1);
    if (!response) {
        printf("malloc failed \n");
        return NULL;
    }
    strcpy(response, ptmp + 4);
    return response;
}

int recv_loop() {
    if (first == 1) {
        http_tcpclient_send(socket_fd, lpbuf, strlen(lpbuf));
        first = 0;
    } else {
        gettimeofday(&now_time, NULL);
        time_interval = cal_time_offset(last_time, now_time);
        long time = time_interval.tv_sec * 1000 + time_interval.tv_usec / 1000;
        if (time > 1000) {
            http_tcpclient_send(socket_fd, lpbuf, strlen(lpbuf));
        }
    }
    /* Wait for events to happen */
    int nevents = ff_ipc_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    int i;

    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int) event.ident;

        if (clientfd == socket_fd) {
            if (http_tcpclient_recv(socket_fd, lpbuf) <= 0) {
                printf("http_tcpclient_recv failed\n");
                return -1;
            }
            http_tcpclient_close(socket_fd);
            printf("%s", http_parse_result(lpbuf));
            alive = 0;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    ff_ipc_init();

    int ch;
    while ((ch = getopt(argc, argv, "p:")) != -1){
        switch(ch) {
            case 'p':
                ff_set_proc_id(atoi(optarg));
                break;
            default:
                usage();
        }

    }
    if (argc - optind != 1)
        usage();
    char *url = argv[optind];

    assert((kq = ff_ipc_kqueue()) > 0);

    char host_addr[BUFFER_SIZE] = {'\0'};
    char file[BUFFER_SIZE] = {'\0'};
    int port = 0;

    if (http_parse_url(url, host_addr, file, &port)) {
        printf("http_parse_url failed!\n");
        return -1;
    }

    socket_fd = http_tcpclient_create(host_addr, port);
    sprintf(lpbuf, HTTP_GET, file, host_addr, port);

    EV_SET(&kevSet, socket_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    /* Update kqueue */
    ff_ipc_kevent(kq, &kevSet, 1, NULL, 0, NULL);

    alive = 1;
    while(alive){
        recv_loop();
        usleep(100000);
    }

    return 0;
}