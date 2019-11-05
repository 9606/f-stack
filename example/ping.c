#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <netdb.h>
#include <err.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "ff_config.h"
#include "ff_api.h"

#define MAX_EVENTS 512

/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;

#define PACKET_SEND_MAX_NUM 64

typedef struct ping_packet_status {
    struct timeval begin_time;
    struct timeval end_time;
    int flag;
    int seq;
} ping_packet_status;


ping_packet_status ping_packet[PACKET_SEND_MAX_NUM];

int alive;
int rawsock;
int send_count;
int recv_count;
pid_t pid;
struct sockaddr_in dest;
struct timeval start_time;
struct timeval end_time;
struct timeval last_time;
struct timeval now_time;
struct timeval time_interval;

void ping_stats_show() {
    long time = time_interval.tv_sec * 1000 + time_interval.tv_usec / 1000;

    printf("\n%d packets transmitted, %d recieved, %d%c packet loss, time %ldms\n",
           send_count, recv_count, (send_count - recv_count) * 100 / send_count, '%', time);
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

void icmp_sigint(int signo) {
    alive = 0;
    gettimeofday(&end_time, NULL);
    time_interval = cal_time_offset(start_time, end_time);

    ping_stats_show();
    exit(0);
}

unsigned short cal_chksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;


    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}


void icmp_pack(struct icmp *icmphdr, int seq, int length) {
    int i = 0;

    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_seq = htons(seq);
    icmphdr->icmp_id = pid & 0xffff;
    for (i = 0; i < length; i++) {
        icmphdr->icmp_data[i] = i;
    }

    icmphdr->icmp_cksum = cal_chksum((unsigned short *) icmphdr, length);
}

int icmp_unpack(char *buf, int len) {
    int iphdr_len;
    struct timeval begin_time, recv_time, offset_time;
    double rtt;

    struct ip *ip_hdr = (struct ip *) buf;
    iphdr_len = ip_hdr->ip_hl * 4;
    struct icmp *icmp = (struct icmp *) (buf + iphdr_len);
    len -= iphdr_len;
    if (len < 8) {
        fprintf(stderr, "Invalid icmp packet.Its length is less than 8\n");
        return -1;
    }
    icmp->icmp_seq = htons(icmp->icmp_seq);
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == (pid & 0xffff))) {
        if ((icmp->icmp_seq < 0) || (icmp->icmp_seq > PACKET_SEND_MAX_NUM)) {
            printf("icmp packet seq is out of range!\n");
            return -1;
        }

        ping_packet[icmp->icmp_seq].flag = 0;
        begin_time = ping_packet[icmp->icmp_seq].begin_time;
        gettimeofday(&recv_time, NULL);

        offset_time = cal_time_offset(begin_time, recv_time);
        rtt = (double) offset_time.tv_sec * 1000 + (double) offset_time.tv_usec / 1000;

        printf("%d byte from %s: icmp_seq=%u ttl=%d time=%.3f ms\n",
               len, inet_ntoa(ip_hdr->ip_src), icmp->icmp_seq, ip_hdr->ip_ttl, rtt);

    } else {
        fprintf(stderr, "Invalid ICMP packet! Its id is not matched!\n");
        return -1;
    }
    return 0;
}

char send_buf[128];
char recv_buf[256];

int send_packet() {
    gettimeofday(&last_time, NULL);
    memset(send_buf, 0, sizeof(send_buf));
    if (alive) {
        int size = 0;
        gettimeofday(&(ping_packet[send_count].begin_time), NULL);
        ping_packet[send_count].flag = 1;

        icmp_pack((struct icmp *) send_buf, send_count, 64);
        size = ff_send(rawsock, send_buf, 64, 0);
        send_count++;
        if (size < 0) {
            fprintf(stderr, "send icmp packet fail!\n");
        }
    }
}

int first_icmp = 1;

int recv_loop(void *arg) {

    if (!alive) {
        return 0;
    }

    if (first_icmp == 1) {
        gettimeofday(&start_time, NULL);
        send_packet();
        first_icmp = 0;
    } else {
        gettimeofday(&now_time, NULL);
        time_interval = cal_time_offset(last_time, now_time);
        long time = time_interval.tv_sec * 1000 + time_interval.tv_usec / 1000;
        if (time > 1000) {
            send_packet();
        }
    }

    /* Wait for events to happen */
    int nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    int i;

    for (i = 0; i < nevents; ++i) {
        struct kevent event = events[i];
        int clientfd = (int) event.ident;

        if (clientfd == rawsock) {
            int ret = 0;
            memset(recv_buf, 0, sizeof(recv_buf));
            int readlen = ff_read(clientfd, recv_buf, sizeof(recv_buf));
            ret = icmp_unpack(recv_buf, readlen);
            if (ret == -1) {
                fprintf(stderr, "recv data fail!\n");
                return -1;
            } else {
                recv_count++;
                sleep(1);
                send_packet();
            }
        }
    }
}

int get_hash(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
    int s = 0;
    s = ((s << 2) + (a >> 4)) ^ (a << 10);
    s = ((s << 2) + (b >> 4)) ^ (b << 10);
    s = ((s << 2) + (c >> 4)) ^ (c << 10);
    s = ((s << 2) + (d >> 4)) ^ (d << 10);

    s = s % 0x7FFFFFFF;
    s = s < 0 ? s + 0x7FFFFFFF : s;
    return s;
}

int pipeline_dispatch_cb(void *data, uint16_t *len,
                         uint16_t queue_id, uint16_t nb_queues) {
    struct ipv4_hdr *iph;
    int iph_len;
    uint32_t hash;

    iph = (struct ipv4_hdr *) (data + ETHER_HDR_LEN);
    iph_len = (iph->version_ihl & 0x0f) << 2;

    if (iph->next_proto_id != IPPROTO_IP) {
        return queue_id;
    }

    iph = (struct ipv4_hdr *) ((char *) iph + iph_len);
    iph_len = (iph->version_ihl & 0x0f) << 2;

    if (iph->next_proto_id == IPPROTO_TCP) {
        struct tcp_hdr *tcph = (struct tcp_hdr *) ((char *) iph + iph_len);
        hash = get_hash(iph->src_addr, iph->dst_addr, tcph->src_port, tcph->dst_port);
    } else if (iph->next_proto_id == IPPROTO_UDP) {
        struct udp_hdr *udph = (struct udp_hdr *) ((char *) iph + iph_len);
        hash = get_hash(iph->src_addr, iph->dst_addr, udph->src_port, udph->dst_port);
    } else {
        return queue_id;
    }

    return hash % nb_queues;
}

int main(int argc, char *argv[]) {
    ff_init(argc, argv);
    /* regist a packet dispath function */
    ff_regist_packet_dispatcher(pipeline_dispatch_cb);

    assert((kq = ff_kqueue()) > 0);

    int size = 128 * 1024;//128k
    char dest_addr_str[80];
    memset(dest_addr_str, 0, 80);
    unsigned int inaddr = 1;
    struct hostent *host = NULL;

    if (argc < 2) {
        printf("Invalid IP ADDRESS!\n");
        return -1;
    }

    memcpy(dest_addr_str, argv[argc - 1], strlen(argv[argc - 1]) + 1);

    rawsock = ff_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rawsock < 0) {
        printf("Fail to create socket!\n");
        return -1;
    }
    pid = getpid();

    ff_setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    bzero(&dest, sizeof(dest));

    dest.sin_family = AF_INET;

    inaddr = inet_addr(argv[argc - 1]);
    if (inaddr == INADDR_NONE) {
        host = gethostbyname(argv[argc - 1]);
        if (host == NULL) {
            printf("Fail to gethostbyname!\n");
            return -1;
        }

        memcpy((char *) &dest.sin_addr, host->h_addr, host->h_length);
    } else {
        memcpy((char *) &dest.sin_addr, &inaddr, sizeof(inaddr));
    }
    inaddr = dest.sin_addr.s_addr;

    printf("PING %s, (%d.%d.%d.%d) 56(84) bytes of data.\n", dest_addr_str,
           (inaddr & 0x000000ff), (inaddr & 0x0000ff00) >> 8,
           (inaddr & 0x00ff0000) >> 16, (inaddr & 0xff000000) >> 24);

    alive = 1;

    if (ff_connect(rawsock, (struct linux_sockaddr *) &dest, sizeof(dest)) != 0) {
        err(1, "connect");
    }

    EV_SET(&kevSet, rawsock, EVFILT_READ, EV_ADD, 0, 0, NULL);
    /* Update kqueue */
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);

    signal(SIGINT, icmp_sigint);

    ff_run(recv_loop, NULL);
    return 0;
}
